"""Open the isolated Claude web environment; leave normal browser profiles alone."""
from pathlib import Path
import ctypes
import datetime as dt
import importlib.util
import json
import os
import re
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'privacy-qa'))
from environment_launch import launch_environment, LaunchFailure, _pid_alive, _ready, _real_failure, _marker, probe_gateway_blocker, record_launch_failure, _native_ready, verify_native_browser_monitor
from browser_system_timezone import NATIVE_BROWSER_MODE, native_browser_arguments
import environment_lease as leases
import environment_watchdog as watchdog

HEALTH_TIMEOUT = 8.0
TOPOLOGY_COUNTS = ('attached','covered_pages','covered_iframes',
                   'retired_before_metadata','navigation_scope_resets')


def _publisher_validator():
    # Fixed installation-owned code path only. No report/runtime/config field
    # may select a Python module or an alternative validation implementation.
    source=leases.physical(ROOT/'privacy-qa'/'status_publisher.py',ROOT)
    spec=importlib.util.spec_from_file_location('claude_browser_reuse_status_validator',source)
    if spec is None or spec.loader is None:
        raise LaunchFailure('existing_page_health_not_verified')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.validate_status


def _utc_milliseconds(value):
    if type(value) is not str:
        raise LaunchFailure('existing_page_health_not_verified')
    try:
        stamp=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
        if stamp.tzinfo is None or stamp.utcoffset()!=dt.timedelta(0):
            raise ValueError()
        return round(stamp.timestamp()*1000)
    except (ValueError,TypeError,OverflowError,OSError):
        raise LaunchFailure('existing_page_health_not_verified') from None


def _retained_current_provenance(root, controller, target, status_path):
    # Historical provenance identifies only the same retained session. It is
    # never a current environment, page-health, lease or network permission.
    try:
        current = leases.read_json(Path(root) / 'browser-environment-current.json', root)
        evidence = current.get('document_evidence')
        binding = current.get('retained_identity')
        if (current.get('controller_pid') != controller['pid']
                or current.get('process_pid') != target['pid']
                or current.get('status_path') != str(status_path)
                or type(binding) is not dict
                or set(binding) != {'process_creation', 'controller_creation'}
                or binding['process_creation'] != target['creation']
                or binding['controller_creation'] != controller['creation']
                or type(evidence) is not dict):
            return None
        if current.get('outcome') == 'protected_page_unavailable':
            if ('retained_provenance' in current or evidence.get('window_preserved') is not True
                    or evidence.get('document_loaded') is not False
                    or evidence.get('activation_completed') is not False
                    or evidence.get('startup_error') != 'cdp_command_timeout'
                    or evidence.get('current_error_document_verified') is not True):
                return None
            provenance = {'schema': 1, 'source': 'startup-timeout-error-document-v1',
                          'startup_error': 'cdp_command_timeout', 'error_document_verified': True,
                          'error_document_checked_at': evidence.get('checked_at')}
        elif current.get('outcome') == 'reused-existing-session':
            provenance = current.get('retained_provenance')
            if (current.get('environment_evidence') != 'runtime'
                    or evidence.get('document_loaded') is not True
                    or evidence.get('environment_matches') is not True
                    or evidence.get('complete_target_inventory') is not True
                    or type(evidence.get('top_level_pages')) is not int
                    or not 1 <= evidence['top_level_pages'] <= 16):
                return None
        else:
            return None
        if (type(provenance) is not dict
                or set(provenance) != {'schema', 'source', 'startup_error',
                                       'error_document_verified', 'error_document_checked_at'}
                or type(provenance.get('schema')) is not int or provenance['schema'] != 1
                or provenance.get('source') != 'startup-timeout-error-document-v1'
                or provenance.get('startup_error') != 'cdp_command_timeout'
                or provenance.get('error_document_verified') is not True):
            return None
        original_ms = _utc_milliseconds(provenance['error_document_checked_at'])
        last_ms = _utc_milliseconds(evidence.get('checked_at'))
        birth_ms = max(int(item['creation'], 16) / 10000 - 11644473600000
                       for item in (target, controller))
        if not birth_ms <= original_ms <= last_ms <= time.time() * 1000:
            return None
        return dict(provenance)
    except Exception:
        return None


def _retained_current_record(root, controller, target, status_path):
    return _retained_current_provenance(root, controller, target, status_path) is not None


def _owned_health_status(existing,root,validator):
    target=leases.validate_identity(existing['target'])
    controller=leases.validate_identity(existing['controller'])
    expected=Path(root)/'privacy-qa'/'runs'/f"environment-browser-{controller['pid']}.json"
    if Path(existing['status_path'])!=expected:
        raise LaunchFailure('existing_page_health_not_verified')
    leases.physical(expected,root)
    if (not leases.same_identity(target,leases.identity(target['pid']))
            or not leases.same_identity(controller,leases.identity(controller['pid']))
            or leases.parents().get(target['pid'])!=controller['pid']):
        raise LaunchFailure('existing_page_health_not_verified')
    value=validator(leases.read_json(expected,root))
    if (value.get('process_pid')!=target['pid']
            or value.get('profile_scope')!='claude-persistent'
            or (value.get('activation_complete') is not True
                and not (value.get('activation_attempted') is True
                         and _retained_current_record(root, controller, target, expected)))):
        raise LaunchFailure('existing_page_health_not_verified')
    stamp=_utc_milliseconds(value.get('at'))
    born=max(int(item['creation'],16)/10000-11644473600000 for item in (target,controller))
    now_ms=time.time()*1000
    if not born<=stamp<=now_ms or not 0<=now_ms-stamp<=4000:
        raise LaunchFailure('existing_page_health_not_verified')
    return value,expected


def _document_topology(value):
    counts=value.get('counts',{})
    result=tuple(counts.get(key) for key in TOPOLOGY_COUNTS)
    if any(type(item) is not int or item<0 for item in result):
        raise LaunchFailure('existing_page_health_not_verified')
    return result


def current_document_health(existing,root=ROOT):
    """Request only the owning controller's fixed, account-free QA sample.

    No arbitrary CDP/DOM API, reload, close, login cleanup or gate mutation.
    QA has no nonce: require both the request-time floor and an advance beyond
    the prior QA timestamp, plus unchanged identity/topology and current status.
    """
    try:
        root=Path(root);validator=_publisher_validator()
        before,status_path=_owned_health_status(existing,root,validator)
        if before.get('environment_check_pending') is True or before.get('navigation_guard') is not None:
            raise LaunchFailure('existing_navigation_waiting_for_runtime')
        if not _ready(before):
            raise LaunchFailure('existing_page_health_not_verified')
        topology=_document_topology(before)
        prior=before.get('qa_diagnostic')
        previous_ms=_utc_milliseconds(prior['checked_at']) if isinstance(prior,dict) else -1
        requested_ms=int(time.time()*1000)
        # Exclusive zero-byte marker; never overwrite/remove someone else's
        # existing request or send a command payload. The controller consumes it.
        _marker(Path(str(status_path)+'.qa'))
        deadline=time.monotonic()+HEALTH_TIMEOUT
        while time.monotonic()<deadline:
            current,_=_owned_health_status(existing,root,validator)
            if _document_topology(current)!=topology:
                raise LaunchFailure('existing_page_health_not_verified')
            if current.get('environment_check_pending') is True or current.get('navigation_guard') is not None:
                raise LaunchFailure('existing_navigation_waiting_for_runtime')
            qa=current.get('qa_diagnostic')
            if isinstance(qa,dict):
                checked_ms=_utc_milliseconds(qa.get('checked_at'))
                now_ms=time.time()*1000
                if checked_ms>=requested_ms and checked_ms>previous_ms:
                    if not 0<=now_ms-checked_ms<=4000 or not _ready(current):
                        raise LaunchFailure('existing_page_health_not_verified')
                    pages=qa.get('pages',[])
                    # The existing strict publisher validates every field and
                    # result consistency, including RTC. Document health remains
                    # distinct from RTC acceptance; inspect every top-level page.
                    if (qa.get('complete_target_inventory') is not True or not pages
                            or not all(page.get('isErrorDocument') is False
                                       and page.get('securityOriginMatchesProtected') is True
                                       and page.get('protectedHttpsDocument') is True
                                       and page.get('unreachableDocument') is False
                                       and page.get('mainDocumentLoaded') is True
                                       and page.get('environmentMatches') is True for page in pages)):
                        raise LaunchFailure('existing_page_health_not_verified')
                    return {'checked_at':qa['checked_at'],'complete_target_inventory':True,
                            'top_level_pages':len(pages),'document_loaded':True,
                            'environment_matches':True}
            time.sleep(.1)
        raise LaunchFailure('existing_page_health_not_verified')
    except LaunchFailure:
        raise
    except (OSError,ValueError,KeyError,TypeError,leases.LeaseError):
        raise LaunchFailure('existing_page_health_not_verified') from None


def _recent_pending(value):
    if (not isinstance(value,dict) or value.get('environment_check_ok') is not False
            or value.get('environment_scope')!='isolated-browser-all-web-targets-v1'
            or value.get('profile_scope')!='claude-persistent' or _real_failure(value)):
        return False
    try:
        checked=dt.datetime.fromisoformat(value['environment_check_at'].replace('Z','+00:00'))
        age=time.time()-checked.timestamp()
        return checked.tzinfo is not None and checked.utcoffset()==dt.timedelta(0) and 0<=age<=4
    except (KeyError,ValueError,TypeError,OverflowError):
        return False


def _wait_pending(file,value,root=ROOT):
    deadline=time.monotonic()+2
    while _recent_pending(value) and time.monotonic()<deadline:
        time.sleep(.1)
        try:
            current=leases.read_json(file,root)
        except (OSError,ValueError,leases.LeaseError):
            return value  # Still pending; caller refuses reuse, never assumes success.
        if current.get('process_pid')!=value.get('process_pid'):
            return value
        value=current
    return value


def existing_environment(root=ROOT, *, runtime=None):
    root = Path(root)
    runtime = runtime or json.loads((root/'environment-runtime.json').read_text(encoding='utf-8'))
    for file in sorted((root/'privacy-qa/runs').glob('environment-browser-*.json'), key=lambda p:p.stat().st_mtime, reverse=True):
        try:
            value=leases.read_json(file,root)
            controller_pid=int(re.fullmatch(r'environment-browser-(\d+)\.json',file.name)[1])
            stamp=dt.datetime.fromisoformat(value['at'].replace('Z','+00:00'))
            if stamp.tzinfo is None or stamp.utcoffset()!=dt.timedelta(0):
                continue
            if _pid_alive(controller_pid) is not True or _pid_alive(value['process_pid']) is not True:
                continue
            controller,target=leases.identity(controller_pid),leases.identity(value['process_pid'])
            if (not controller or not target or os.path.normcase(controller['image'])!=os.path.normcase(runtime['node_executable'])
                    or os.path.normcase(target['image'])!=os.path.normcase(runtime['browser_executable'])
                    or leases.parents().get(target['pid'])!=controller_pid):
                continue
            # An old status file must not capture a reused node/browser PID.
            births=[int(item['creation'],16)/10_000_000-11_644_473_600 for item in (controller,target)]
            if stamp.timestamp()+1<max(births):
                continue
            if value.get('profile_scope')=='qa-isolated':
                continue
            if value.get('verification_mode') == NATIVE_BROWSER_MODE:
                if (value.get('activation_complete') is not True or not _native_ready(value)
                        or value.get('profile_scope') != 'claude-persistent'):
                    raise LaunchFailure('existing_native_policy_not_verified')
                monitor, observation = verify_native_browser_monitor(root,target,controller,str(file))
                return {'report':value,'status_path':str(file),'target':target,'controller':controller,
                        'verification_mode':NATIVE_BROWSER_MODE,'environment_monitor':monitor,
                        'environment_evidence':observation['reason']}
            if value.get('verification_mode') is not None:
                raise LaunchFailure('existing_environment_requires_restart')
            age=dt.datetime.now(dt.timezone.utc).timestamp()-stamp.timestamp()
            if (0<=age<10 and value.get('activation_complete') is True
                    and value.get('profile_scope')=='claude-persistent'
                    and value.get('environment_check_pending') is True
                    and isinstance(value.get('navigation_guard'),dict) and not _real_failure(value)):
                monitor=watchdog.active_monitor('browser',target,root=root)
                if monitor is None:
                    raise LaunchFailure('existing_navigation_waiting_for_runtime')
                try:
                    observation=watchdog.browser_observation(root,target,controller,str(file))
                except leases.LeaseError:
                    observation=None
                if observation and observation.get('mode')=='navigation_configuration_continuity':
                    return {'report':value,'status_path':str(file),'target':target,'controller':controller,
                            'navigation_active':True,'environment_monitor':monitor}
            if _recent_pending(value):
                value=_wait_pending(file,value,root)
                if not leases.alive(controller) or not leases.alive(target):
                    continue
                stamp=dt.datetime.fromisoformat(value['at'].replace('Z','+00:00'))
            age=dt.datetime.now(dt.timezone.utc).timestamp()-stamp.timestamp()
            if (0<=age<10 and (value.get('activation_complete') is True
                    or (value.get('activation_attempted') is True
                        and _retained_current_record(root,controller,target,file))) and _ready(value)
                    and value.get('profile_scope')=='claude-persistent'):
                return {'report':value,'status_path':str(file),'target':target,'controller':controller}
            raise LaunchFailure('existing_environment_requires_restart')
        except (OSError,ValueError,KeyError,TypeError,leases.LeaseError):
            pass
    return None


def reuse_environment(existing, root=ROOT):
    target,controller=existing['target'],existing['controller']
    mode = existing.get('verification_mode',existing['report'].get('verification_mode'))
    if mode is not None:
        if mode != NATIVE_BROWSER_MODE:
            raise LaunchFailure('existing_environment_requires_restart')
        value = leases.read_json(Path(existing['status_path']),root)
        if (value.get('verification_mode') != mode or value.get('process_pid') != target['pid']
                or value.get('activation_complete') is not True or not _native_ready(value)):
            raise LaunchFailure('existing_native_policy_not_verified')
        monitor, observation = verify_native_browser_monitor(root,target,controller,existing['status_path'],
                                                              monitor=existing.get('environment_monitor'))
        return {'outcome':'reused-existing-session','verification_mode':mode,
                'controller_pid':controller['pid'],'process_pid':target['pid'],
                'status_path':existing['status_path'],'environment_monitor':monitor,
                'timezone':'America/New_York','locale':'en-US',
                'environment_evidence':observation['reason'],
                'document_evidence':{'document_loaded':None,'navigation_dispatched':False,
                                     'scope':'policy-readiness-only'},
                'warnings':list(value.get('error_codes',[])),
                'limits':['The exact existing process, persistent profile and monitor registration were reused; no navigation was requested.',
                          'Native process policy readiness is not a remote document loading assertion.',
                          'Shared Edge executable: no per-profile WFP hard isolation is claimed.',
                          'Network admission still requires the independent four-second allowed-exit lease.']}
    provenance=_retained_current_provenance(root,controller,target,existing['status_path'])
    if existing['report'].get('activation_complete') is not True and provenance is None:
        raise LaunchFailure('existing_page_health_not_verified')
    try:
        active=getattr(watchdog,'active_monitor',lambda *args,**kwargs:None)
        monitor=active('browser',target,root=root)
        if monitor is None:
            if existing.get('navigation_active'):
                raise LaunchFailure('existing_navigation_waiting_for_runtime')
            monitor=watchdog.start_monitor('browser',target,controller=controller,
                                           status_path=existing['status_path'],root=root)
        evidence='runtime'
        document=None
        if existing.get('navigation_active'):
            observation=watchdog.browser_observation(root,target,controller,existing['status_path'])
            if observation.get('mode') not in ('runtime','navigation_configuration_continuity'):
                raise LaunchFailure('existing_navigation_waiting_for_runtime')
            # A detection made during navigation remains pending for this click,
            # even if runtime recovers in the meantime; never bypass fresh QA.
            evidence='navigation_configuration_continuity'
        else:
            document=current_document_health(existing,root)
    except leases.LeaseError as error:
        raise LaunchFailure(str(error)) from None
    outcome={'outcome':'reused-existing-session','controller_pid':controller['pid'],
            'process_pid':target['pid'],'status_path':existing['status_path'],
            'timezone':'America/New_York','locale':'en-US','environment_monitor':monitor,
            'environment_evidence':evidence,
            'document_evidence':document,
            'warnings':list(existing['report'].get('error_codes',[])),
            'limits':['Known navigation configuration continuity; no new page JS measurement during the pause.'
                      if evidence=='navigation_configuration_continuity' else
                      'Private environment metadata verified; not a per-packet egress proof.']}
    if provenance is not None:
        # A retained session must never publish a continuity-only outcome and
        # overwrite the durable origin needed by its next safe reuse.
        if evidence!='runtime' or document is None:
            raise LaunchFailure('existing_navigation_waiting_for_runtime')
        if type(document) is not dict or document.get('document_loaded') is not True:
            raise LaunchFailure('existing_page_health_not_verified')
        outcome['retained_identity']={'process_creation':target['creation'],
                                      'controller_creation':controller['creation']}
        outcome['retained_provenance']=provenance
    return outcome


def message(text):
    ctypes.windll.user32.MessageBoxW(None,text,'Claude 网页安全环境',0x40)


def ensure_ingress_follower(root=ROOT):
    source = leases.physical(Path(root) / 'ingress_follow.py', Path(root))
    spec = importlib.util.spec_from_file_location('claude_browser_ingress_preflight', source)
    if spec is None or spec.loader is None:
        raise LaunchFailure('ingress_follower_not_ready')
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        return module.ensure_running(Path(root))
    except Exception:
        raise LaunchFailure('ingress_follower_not_ready') from None


def environment_preflight(root=ROOT):
    blocker=probe_gateway_blocker(root)
    # A different live native environment already blocks this shared gateway.
    # Fail early with its actual cause; do not retire, close or grant anything.
    # Browser/unknown observations remain hints so normal reuse/navigation
    # verification keeps its existing behavior and remains authoritative.
    if blocker is not None and blocker.get('kind')=='native':
        error=LaunchFailure('native_environment_blocks_gateway')
        record_launch_failure(root,error,stage='preflight',blocker=blocker)
        raise error
    return blocker


def launch_failure_message(error):
    text=('Claude 桌面版仍在后台运行，但其环境监控没有通过；共用保护网关因此保持锁定。请保存工作，从 Claude 托盘菜单完整退出桌面版，或从桌面安全入口恢复检测后再打开网页。登录资料会保留。'
          if error.code=='native_environment_blocks_gateway' else
          '已有专用窗口尚未升级或实时环境未通过核验。请保存工作，正常关闭该专用窗口后再点入口；登录资料会保留。'
          if error.code=='existing_environment_requires_restart' else
          '专用窗口正在加载，但当前监控尚未通过验证。保护保持断网；请等加载结束后再点入口，或正常关闭专用窗口后重开。'
          if error.code=='existing_navigation_waiting_for_runtime' else '专用环境未能完成验证：'+error.code)
    if error.code=='exit_verification_unavailable':
        text='家宽出口探测暂未成功（exit_verification_unavailable）。这不表示时区或语言不合格。请确认 Clash 和链式家宽节点仍可用，等待入口切换完成后再试；保护仍保持，不会改走其他出口。'
    elif error.code=='exit_outside_allowlist':
        text='专用链当前出口不在允许名单中，已停止启动。请核对链式代理的家宽出口；保护不会放行其他 IP。'
    if error.code=='existing_page_health_not_verified':
        text='当前 Claude 页面健康检查未通过。专用窗口、登录资料和网络保护均保留；请切换检查加载状态，稍后再点入口。没有重载或关闭现有工作。'
    if error.code=='existing_native_policy_not_verified':
        text='现有专用窗口的实时进程策略尚未通过核验，网络保护保持锁定。窗口和登录资料均保留；没有刷新或关闭现有工作。'
    if error.hold_retained:
        text+='\n已保留 Claude 断网锁定，请检查保护状态；没有改用其他出口。'
    return text


def main():
    runtime_path=ROOT/'environment-runtime.json'
    if runtime_path.resolve(strict=True)!=runtime_path.absolute():
        raise RuntimeError('运行时路径被重定向，已停止。')
    runtime=json.loads(runtime_path.read_text(encoding='utf-8'))
    node=Path(runtime['node_executable'])
    browser=Path(runtime['browser_executable'])
    for executable in (node,browser):
        if not executable.is_file() or executable.resolve()!=executable.absolute():
            raise RuntimeError('专用环境运行时需要维护，已停止。')
    os.environ['PATH']=str(node.parent)+os.pathsep+os.environ.get('PATH','')
    ensure_ingress_follower(ROOT)
    environment_preflight(ROOT)
    existing=existing_environment(ROOT,runtime=runtime)
    if existing:
        outcome=reuse_environment(existing,ROOT)
        (ROOT/'browser-environment-current.json').write_text(json.dumps(outcome,ensure_ascii=False,indent=2),encoding='utf-8')
        if '--console' in sys.argv:
            print(json.dumps(outcome,ensure_ascii=False))
        else:
            message('已复用原专用窗口，实时进程策略和出口保护已核验。此结果不代表远端页面已经加载；请切换到原窗口使用。'
                    if outcome.get('verification_mode')==NATIVE_BROWSER_MODE else
                    '专用窗口正在受保护地加载；当前延续此前核验的配置，加载完成后会继续实际检查。请切换到该窗口使用。'
                    if outcome.get('environment_evidence')=='navigation_configuration_continuity' else
                    'Claude 专用页面已加载，环境参数和保护监控已核验。请切换到该窗口使用。')
        return
    env=dict(os.environ)
    for key in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy'):
        env[key]='http://127.0.0.1:17894'
    env['NO_PROXY']=env['no_proxy']=''
    argv=native_browser_arguments(ROOT)
    outcome=launch_environment('browser',browser,argv,env,ROOT,verification_mode=NATIVE_BROWSER_MODE)
    (ROOT/'browser-environment-current.json').write_text(json.dumps(outcome,ensure_ascii=False,indent=2),encoding='utf-8')
    if '--console' in sys.argv:
        print(json.dumps(outcome,ensure_ascii=False))
    elif outcome.get('outcome')=='protected_page_unavailable':
        message('网络环境与固定出口已核验，但 Claude 页面暂未加载。专用窗口和保护已保留，请在该窗口刷新；加载完成后可再次点击安全入口核验。')


if __name__=='__main__':
    try:
        main()
    except LaunchFailure as error:
        record_launch_failure(ROOT,error,stage='preflight')
        text=launch_failure_message(error)
        if '--console' in sys.argv:
            print(json.dumps({'failed':error.code,'hold_retained':error.hold_retained}));sys.exit(1)
        message(text)
    except Exception as error:
        record_launch_failure(ROOT,error,stage='preflight')
        if '--console' in sys.argv:
            print(json.dumps({'failed':'runtime_configuration_error'}));sys.exit(1)
        message('专用环境配置未通过检查，已停止。请检查本机保护配置。')
