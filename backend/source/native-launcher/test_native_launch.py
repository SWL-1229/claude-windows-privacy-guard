"""Pure offline tests. No Windows UI, process, DNS, proxy, or network actions."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location('native_launch_candidate', Path(__file__).with_name('native_desktop_launch.py'))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

OWNER = {'pid': 100, 'creation': '0123456789abcdef', 'image': str(Path('/private/pythonw.exe').absolute())}
TARGET = {'pid': 500, 'creation': '1123456789abcdef', 'image': str(Path('/private/Claude.exe').absolute())}


def good(origin='https://claude.ai'):
    return dict(nonce='a' * 32, origin=origin, timeZone='America/New_York', language='en-US',
                januaryOffset=300, julyOffset=240, epoch=1000000, topFrame=True)


class MemoryFile:
    def __init__(self, store, path, create):
        self.store, self.path, self.closed = store, str(path), False
        if create:
            if self.path in store:
                raise FileExistsError()
            store[self.path] = None
        elif self.path not in store:
            raise FileNotFoundError()

    def read(self):
        value = self.store[self.path]
        if not isinstance(value, dict):
            raise m.LaunchError('foreign_hold')
        return copy.deepcopy(value)

    def write(self, value):
        self.store[self.path] = copy.deepcopy(value)

    def delete(self):
        del self.store[self.path]
        self.closed = True

    def close(self):
        self.closed = True


class HoldTests(unittest.TestCase):
    def hold(self, store=None, life=False):
        store = {} if store is None else store
        return m.OwnedHold(Path('/private/root').absolute(), OWNER, lambda _: life,
                           open_file=lambda p, create: MemoryFile(store, p, create),
                           validate=lambda *a, **k: None), store

    def test_new_hold_release_exact_owner(self):
        hold, store = self.hold()
        hold.acquire()
        self.assertTrue(hold.owned)
        self.assertEqual(store[str(hold.path)]['owner_nonce'], hold.nonce)
        hold.release()
        self.assertEqual(store, {})

    def test_foreign_hold_is_unchanged(self):
        hold, store = self.hold()
        store[str(hold.path)] = {'manual': 'keep offline'}
        before = copy.deepcopy(store)
        with self.assertRaisesRegex(m.LaunchError, 'foreign_hold'):
            hold.recover_existing()
        self.assertEqual(store, before)

    def test_stale_own_hold_adopted_without_delete_gap(self):
        old, store = self.hold()
        old.acquire()
        old_nonce = old.nonce
        old.close_preserving()
        hold, _ = self.hold(store)
        self.assertTrue(hold.recover_existing())
        self.assertEqual(len(store), 1)
        self.assertNotEqual(old_nonce, hold.nonce)
        self.assertEqual(store[str(hold.path)]['owner_nonce'], hold.nonce)

    def test_live_owner_hold_is_preserved(self):
        old, store = self.hold()
        old.acquire()
        old.close_preserving()
        hold, _ = self.hold(store, life=True)
        before = copy.deepcopy(store)
        with self.assertRaisesRegex(m.LaunchError, 'hold_owner_still_alive'):
            hold.recover_existing()
        self.assertEqual(store, before)

    def test_unknown_owner_hold_is_preserved(self):
        old, store = self.hold()
        old.acquire()
        old.close_preserving()
        hold, _ = self.hold(store, life=None)
        with self.assertRaisesRegex(m.LaunchError, 'hold_owner_unknown'):
            hold.recover_existing()
        self.assertIn(str(hold.path), store)

    def test_changed_owner_cannot_be_deleted(self):
        hold, store = self.hold()
        hold.acquire()
        store[str(hold.path)]['owner_nonce'] = 'b' * 32
        with self.assertRaisesRegex(m.LaunchError, 'foreign_hold'):
            hold.release()
        self.assertIn(str(hold.path), store)

    def test_close_preserves_fail_closed_file(self):
        hold, store = self.hold()
        hold.acquire()
        hold.close_preserving()
        self.assertFalse(hold.owned)
        self.assertIn(str(hold.path), store)


class MetadataTests(unittest.TestCase):
    def test_accepts_only_account_free_fields(self):
        data = good()
        data.update(href='https://claude.ai/chat/private', consoleLog='secret', cookie='secret')
        checked = m.metadata(data, real_origin=True, now=1000)
        self.assertNotIn('href', checked)
        self.assertNotIn('cookie', checked)
        self.assertNotIn('consoleLog', checked)

    def test_uppercase_helper_fields_are_accepted(self):
        checked = m.metadata({k.upper(): v for k, v in good().items()}, real_origin=True, now=1000)
        self.assertEqual(checked['timeZone'], 'America/New_York')

    def test_wrong_zone_language_dst_origin_and_epoch(self):
        for key, value, code in [
            ('timeZone', 'Asia/Shanghai', 'wrong_timezone'),
            ('language', 'zh-CN', 'wrong_language'),
            ('januaryOffset', -480, 'wrong_dst_offsets'),
            ('julyOffset', True, 'wrong_dst_offsets'),
            ('origin', 'https://claude.ai.evil.example', 'wrong_origin'),
            ('epoch', 1, 'stale_metadata'),
            ('epoch', float('nan'), 'stale_metadata'),
            ('nonce', '', 'stale_metadata'),
            ('topFrame', False, 'wrong_frame'),
        ]:
            with self.subTest(key=key):
                value_obj = good()
                value_obj[key] = value
                with self.assertRaisesRegex(m.LaunchError, code):
                    m.metadata(value_obj, real_origin=True, now=1000)

    def test_offline_error_allowed_only_before_real_page(self):
        m.metadata(good('null'), real_origin=False, now=1000)
        with self.assertRaisesRegex(m.LaunchError, 'wrong_origin'):
            m.metadata(good('null'), real_origin=True, now=1000)


class FakeMutex:
    def __init__(self, acquired=True):
        self.acquired = acquired

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


class FakeHold:
    def __init__(self, events, *, foreign=False, recovered=False):
        self.events, self.owned, self.exists = events, False, recovered
        self.foreign, self.recovered = foreign, recovered

    def recover_existing(self):
        self.events.append('hold-recover')
        if self.foreign:
            raise m.LaunchError('foreign_hold')
        self.owned = self.exists
        return self.exists

    def acquire(self):
        self.events.append('hold-acquire')
        if self.foreign:
            raise m.LaunchError('foreign_hold')
        self.exists = self.owned = True

    def release(self):
        self.events.append('hold-release')
        assert self.owned
        self.exists = self.owned = False

    def close_preserving(self):
        self.events.append('hold-close-preserving')
        self.owned = False


class FakeBackend:
    def __init__(self, *, existing=False, foreign=False, recovered=False, fail=None):
        self.events, self.existing, self.fail = [], existing, fail
        self.h = FakeHold(self.events, foreign=foreign, recovered=recovered)
        self.acquired = True
        self.verify_results = [good() if existing else good('null')]
        self.real_results = [good(), good()]
        self.exit_ok, self.no_main_ok = True, True
        self.published = []

    def mutex(self):
        return FakeMutex(self.acquired)

    def now(self):
        return 1000

    def preflight(self):
        self.events.append('preflight')
        return dict(TARGET) if self.existing else None

    def hold(self):
        return self.h

    def ensure_services(self):
        self.events.append('services')
        return {'gate': 1, 'core': 2, 'dns_tcp': 3, 'dns_udp': 3}

    def activate_environment_monitor(self, target, hold):
        self.events.append('environment-monitor')
        if self.fail == 'environment-monitor':
            raise m.LaunchError('environment_monitor_not_ready')
        return {'kind': 'native', 'monitor_pid': 700, 'lease_seconds': 4.0}

    def fresh_exit(self):
        self.events.append('fresh-exit')
        if self.fail == 'fresh-exit':
            raise m.LaunchError('exit_not_allowed')
        return '192.0.2.10'

    def prepare_native_rtc(self, target, hold):
        assert target == TARGET and hold is self.h and hold.owned
        self.events.append('native-rtc-before-release')

    def require_existing_native_rtc(self, target):
        assert target == TARGET
        self.events.append('existing-native-rtc-verified')

    def internal_exit_probe(self):
        self.events.append('internal-probe')
        assert self.h.owned
        if self.fail == 'internal-probe':
            raise m.LaunchError('exit_not_allowed')
        return '192.0.2.10'

    def launch(self):
        self.events.append('launch')
        assert self.h.owned
        if self.fail == 'launch':
            raise m.LaunchError('unexpected_failure')

    def await_main(self, startup_hold=None):
        assert startup_hold is self.h and self.h.owned
        self.events.append('await-main')
        return dict(TARGET)

    def helper(self, command, identity):
        assert identity == TARGET
        self.events.append(command)
        if self.fail == command:
            raise m.LaunchError('helper_failed')
        if command in {'disable-js', 'configure'} and not self.existing:
            assert self.h.owned
        if command == 'verify':
            return self.verify_results.pop(0)
        if command == 'inspect':
            return {'windows': [{'kind': 'devtools-claude'}]}
        return {}

    def wait_real_metadata(self, identity):
        self.events.append('wait-real')
        assert not self.h.owned
        data = self.real_results.pop(0)
        return m.metadata(data, real_origin=True, now=self.now())

    def normal_exit_exact(self, identity):
        self.events.append('normal-exit')
        assert identity == TARGET
        return self.exit_ok

    def no_main(self):
        self.events.append('no-main')
        return self.no_main_ok

    def publish(self, state):
        self.events.append('publish')
        self.published.append(copy.deepcopy(state))


class TransactionTests(unittest.TestCase):
    def test_cold_start_order_and_success(self):
        b = FakeBackend()
        result = m.apply(b)
        self.assertTrue(result['ok'])
        for first, second in [('fresh-exit', 'hold-acquire'), ('hold-acquire', 'launch'),
                              ('disable-js', 'configure'), ('configure', 'verify'),
                              ('verify', 'internal-probe'), ('internal-probe', 'hold-release'),
                              ('hold-release', 'reload'), ('wait-real', 'enable-js'),
                              ('enable-js', 'park-monitor-bottom')]:
            self.assertLess(b.events.index(first), b.events.index(second), (first, second))
        self.assertEqual(b.events.count('reload'), 2)
        self.assertFalse(b.h.exists)
        self.assertTrue(result['persistent_environment_lease'])
        self.assertFalse(result['all_renderer_zero_window_proven'])

    def test_foreign_hold_not_removed_or_services_touched(self):
        b = FakeBackend(foreign=True)
        r = m.apply(b)
        self.assertFalse(r['ok'])
        self.assertEqual(r['code'], 'foreign_hold')
        self.assertNotIn('services', b.events)
        self.assertNotIn('hold-release', b.events)
        self.assertNotIn('launch', b.events)

    def test_fresh_exit_failure_does_not_launch_or_create_hold(self):
        b = FakeBackend(fail='fresh-exit')
        r = m.apply(b)
        self.assertEqual(r['code'], 'exit_not_allowed')
        self.assertNotIn('launch', b.events)
        self.assertNotIn('hold-acquire', b.events)

    def test_wrong_offline_metadata_never_releases_before_shutdown(self):
        b = FakeBackend()
        wrong = good('null')
        wrong['timeZone'] = 'Asia/Shanghai'
        b.verify_results = [wrong]
        r = m.apply(b)
        self.assertFalse(r['ok'])
        self.assertLess(b.events.index('enable-js'), b.events.index('normal-exit'))
        self.assertLess(b.events.index('normal-exit'), b.events.index('hold-release'))
        self.assertNotIn('reload', b.events)

    def test_failed_internal_probe_cannot_release_for_navigation(self):
        b = FakeBackend(fail='internal-probe')
        r = m.apply(b)
        self.assertFalse(r['ok'])
        self.assertNotIn('reload', b.events)
        self.assertLess(b.events.index('normal-exit'), b.events.index('hold-release'))

    def test_wrong_remote_metadata_reacquires_before_js_restore(self):
        b = FakeBackend()
        bad = good()
        bad['timeZone'] = 'Asia/Shanghai'
        b.real_results = [bad]
        r = m.apply(b)
        self.assertFalse(r['ok'])
        releases = [i for i, e in enumerate(b.events) if e == 'hold-release']
        acquires = [i for i, e in enumerate(b.events) if e == 'hold-acquire']
        self.assertGreater(acquires[-1], releases[0])
        self.assertLess(acquires[-1], b.events.index('enable-js'))
        self.assertLess(b.events.index('enable-js'), b.events.index('normal-exit'))

    def test_failed_normal_exit_keeps_hold(self):
        b = FakeBackend(fail='configure')
        b.exit_ok = False
        r = m.apply(b)
        self.assertFalse(r['ok'])
        self.assertTrue(r['offline_hold_retained'])
        self.assertTrue(b.h.exists)
        self.assertNotIn('hold-release', b.events)

    def test_existing_correct_reused_without_hold_reload_or_exit(self):
        b = FakeBackend(existing=True)
        r = m.apply(b)
        self.assertTrue(r['ok'])
        self.assertEqual(r['mode'], 'reused-existing-session')
        self.assertTrue(r['startup_before_controller_unverified'])
        for action in ('hold-acquire', 'launch', 'disable-js', 'enable-js', 'reload', 'normal-exit'):
            self.assertNotIn(action, b.events)

    def test_existing_wrong_reconfigured_without_reload_or_js_toggle(self):
        b = FakeBackend(existing=True)
        wrong = good()
        wrong['language'] = 'zh-CN'
        b.verify_results = [wrong, good()]
        r = m.apply(b)
        self.assertTrue(r['ok'])
        self.assertEqual(r['mode'], 'reconfigured-existing-session')
        self.assertLess(b.events.index('hold-acquire'), b.events.index('configure'))
        self.assertLess(b.events.index('configure'), b.events.index('hold-release'))
        for action in ('launch', 'disable-js', 'enable-js', 'reload', 'normal-exit'):
            self.assertNotIn(action, b.events)

    def test_existing_error_page_preserves_work_and_hold(self):
        b = FakeBackend(existing=True)
        b.verify_results = [good('null'), good('null')]
        r = m.apply(b)
        self.assertFalse(r['ok'])
        self.assertEqual(r['code'], 'existing_error_page')
        self.assertTrue(r['offline_hold_retained'])
        self.assertTrue(b.h.exists)
        self.assertNotIn('normal-exit', b.events)
        self.assertNotIn('reload', b.events)

    def test_existing_configuration_failure_does_not_close_app(self):
        b = FakeBackend(existing=True, fail='configure')
        b.verify_results = [good('null')]
        r = m.apply(b)
        self.assertFalse(r['ok'])
        self.assertTrue(r['offline_hold_retained'])
        self.assertNotIn('normal-exit', b.events)

    def test_recovered_hold_probe_uses_internal_not_ordinary_check(self):
        b = FakeBackend(existing=True, recovered=True)
        r = m.apply(b)
        self.assertTrue(r['ok'])
        self.assertNotIn('fresh-exit', b.events)
        self.assertIn('internal-probe', b.events)
        self.assertFalse(b.h.exists)

    def test_duplicate_click_is_noop(self):
        b = FakeBackend()
        b.acquired = False
        r = m.apply(b)
        self.assertEqual(r['mode'], 'already-running')
        self.assertEqual(b.events, [])

    def test_park_failure_reblocks_existing_without_closing(self):
        b = FakeBackend(existing=True, fail='park-monitor-bottom')
        r = m.apply(b)
        self.assertFalse(r['ok'])
        self.assertTrue(b.h.exists)
        self.assertTrue(r['offline_hold_retained'])
        self.assertNotIn('normal-exit', b.events)

    def test_launch_failure_keeps_hold_despite_empty_instant_snapshot(self):
        b = FakeBackend(fail='launch')
        r = m.apply(b)
        self.assertFalse(r['ok'])
        self.assertNotIn('no-main', b.events)
        self.assertNotIn('hold-release', b.events)
        self.assertTrue(b.h.exists)
        self.assertTrue(r['offline_hold_retained'])

    def test_late_main_without_captured_identity_keeps_hold(self):
        b = FakeBackend()
        def late_main(startup_hold=None):
            self.assertIs(startup_hold,b.h)
            b.events.append('late-main-not-yet-visible')
            raise m.LaunchError('new_main_not_found')
        b.await_main = late_main
        r = m.apply(b)
        self.assertTrue(r['unconfirmed_launch_identity_hold_retained'])
        self.assertTrue(b.h.exists)
        self.assertNotIn('no-main', b.events)
        self.assertNotIn('normal-exit', b.events)
        self.assertNotIn('hold-release', b.events)

    def test_unknown_block_keeps_js_disabled_and_attempts_exact_exit(self):
        b = FakeBackend()
        bad = good()
        bad['timeZone'] = 'Asia/Shanghai'
        b.real_results = [bad]
        original, count = b.h.acquire, [0]
        def faulty_acquire():
            count[0] += 1
            if count[0] == 2:
                b.events.append('hold-acquire-io-error')
                raise OSError('injected hold I/O failure')
            original()
        b.h.acquire = faulty_acquire
        r = m.apply(b)
        self.assertFalse(r['ok'])
        self.assertTrue(r['block_unknown'])
        self.assertNotIn('enable-js', b.events)
        self.assertIn('normal-exit', b.events)
        self.assertTrue(r['new_session_exited_normally'])
        self.assertLess(b.events.index('hold-acquire-io-error'), b.events.index('normal-exit'))

    def test_gui_progress_callback_is_optional_and_transaction_boundaries_unchanged(self):
        b = FakeBackend()
        stages = []
        r = m.apply(b, progress=stages.append)
        self.assertTrue(r['ok'])
        self.assertEqual(stages[0], 'preflight')
        self.assertLess(stages.index('disable-js'), stages.index('release-for-html-only'))
        self.assertLess(stages.index('real-page-js-disabled'), stages.index('enable-js'))


class BackendOfflineTests(unittest.TestCase):
    def backend(self):
        b = m.WindowsBackend.__new__(m.WindowsBackend)
        b.root = Path('/private/root').absolute()
        b.python = Path('/private/python.exe').absolute()
        b.pythonw = Path('/private/pythonw.exe').absolute()
        b.runtime = {'core_executable': str(Path('/private/core.exe').absolute())}
        b.guard = Mock()
        b.guard.windows_command_line_args.side_effect = lambda argv: list(argv)
        return b

    def snapshot(self, b):
        supervisor = dict(ProcessId=30, ParentProcessId=99, ExecutablePath=str(b.pythonw),
                          CommandLine=[str(b.pythonw), '-I', str(b.root / 'dns_service.py')])
        gate = dict(ProcessId=10, ParentProcessId=99, ExecutablePath=str(b.pythonw),
                    CommandLine=[str(b.pythonw), str(b.root / 'guard.py'), '--serve'])
        core = dict(ProcessId=20, ParentProcessId=10, ExecutablePath=b.runtime['core_executable'],
                    CommandLine=['ignored for identity-only core check'])
        worker = dict(ProcessId=40, ParentProcessId=30, ExecutablePath=str(b.pythonw),
                      CommandLine=[str(b.pythonw), '-I', str(b.root / 'dns_service.py'),
                                   '--worker', '--generation', 'a' * 32, '--supervisor-pid', '30'])
        return dict(tcp=[dict(LocalAddress='127.0.0.1', LocalPort=p, OwningProcess=pid)
                         for p, pid in ((17894, 10), (17895, 20), (53, 40))],
                    udp=[dict(LocalAddress='127.0.0.1', LocalPort=53, OwningProcess=40)],
                    processes=[gate, core, worker, supervisor])

    def test_service_identity_includes_dns_supervisor(self):
        b = self.backend()
        snapshot = self.snapshot(b)
        result = b.check_services(snapshot)
        self.assertEqual(result['dns_tcp']['ProcessId'], 40)
        snapshot['processes'] = [p for p in snapshot['processes'] if p['ProcessId'] != 30]
        with self.assertRaisesRegex(m.LaunchError, 'service_identity_mismatch'):
            b.check_services(snapshot)

    def test_worker_parent_generation_and_script_position_are_exact(self):
        for mutate in ('parent', 'generation', 'position'):
            with self.subTest(mutate=mutate):
                b = self.backend()
                snapshot = self.snapshot(b)
                worker = snapshot['processes'][2]
                if mutate == 'parent':
                    worker['ParentProcessId'] = 66
                elif mutate == 'generation':
                    worker['CommandLine'][5] = 'bad'
                else:
                    worker['CommandLine'].insert(2, '/some/other.py')
                with self.assertRaisesRegex(m.LaunchError, 'service_identity_mismatch'):
                    b.check_services(snapshot)

    def test_foreign_core_parent_and_wildcard_listener_rejected(self):
        for mutate in ('core', 'listener'):
            with self.subTest(mutate=mutate):
                b = self.backend()
                snapshot = self.snapshot(b)
                if mutate == 'core':
                    snapshot['processes'][1]['ParentProcessId'] = 777
                else:
                    snapshot['tcp'][0]['LocalAddress'] = '0.0.0.0'
                with self.assertRaisesRegex(m.LaunchError, 'service_identity_mismatch'):
                    b.check_services(snapshot)

    def test_launch_environment_is_restored_after_success_and_failure(self):
        for failure in (False, True):
            b = self.backend()
            observed = []
            def fake_launch():
                observed.append(m.os.environ.get('CLAUDE_DEV_TOOLS'))
                if failure:
                    raise ValueError('fake failure')
            b.guard.launch.side_effect = fake_launch
            with patch.dict(m.os.environ, {'CLAUDE_DEV_TOOLS': 'previous-value'}):
                if failure:
                    with self.assertRaises(ValueError):
                        b.launch()
                else:
                    b.launch()
                self.assertEqual(m.os.environ['CLAUDE_DEV_TOOLS'], 'previous-value')
            self.assertEqual(observed, ['undocked'])

    def test_internal_probe_is_fixed_connect_and_ignores_no_proxy(self):
        b = self.backend()
        b.guard.configured_allowlist.return_value = {'192.0.2.10'}
        with patch.object(m, 'one_held_fixed_exit_attempt', return_value=('192.0.2.10', {'result':'verified'})) as make:
            with patch.dict(m.os.environ, {'NO_PROXY': '*'}):
                self.assertEqual(b.internal_exit_probe(), '192.0.2.10')
        self.assertIs(make.call_args.args[0], b.guard)
        self.assertEqual(make.call_args.args[1], 'cloudflare_trace')
        self.assertLessEqual(make.call_args.args[2], m.HELD_EXIT_ATTEMPT_BUDGET)
        self.assertFalse(b.exit_preflight_diagnostic['permission_granted'])
        b.guard.verified_gate_for_launch.assert_not_called()

    def test_internal_probe_rejects_other_ip_and_non_200(self):
        for reason in ('outside_allowlist', 'http_status'):
            with self.subTest(reason=reason):
                b = self.backend()
                with patch.object(m, 'one_held_fixed_exit_attempt', side_effect=m.HeldExitPolicyFailure(reason)) as make:
                    with self.assertRaisesRegex(m.LaunchError, 'exit_not_allowed'):
                        b.internal_exit_probe()
                self.assertEqual(make.call_count, 1)
                self.assertEqual(b.exit_preflight_diagnostic['result'], 'hard_failure')

    def test_helper_grants_foreground_only_to_its_exact_child_and_passes_creation(self):
        b = self.backend()
        b.alive = Mock(return_value=True)
        b.helper_path = Mock(return_value=Path('/private/DevToolsUi.exe'))
        b.authorize_helper_foreground = Mock(return_value=True)
        process = Mock(pid=8765, returncode=0)
        process.communicate.return_value = (json.dumps(dict(ok=True, command='configure', pid=500,
                                                           data={'configured': True})), '')
        process.stdout.readline.return_value = json.dumps(dict(protocol=m.HELPER_FOREGROUND_PROTOCOL,
            ready=True,command='configure',pid=500,helperPid=8765,targetCreation=TARGET['creation'],
            exactTargetDevToolsAlreadyForeground=False))+'\n'
        process.poll.side_effect = [None,0]
        with patch.object(m.subprocess, 'Popen', return_value=process) as popen:
            result = b.helper('configure', dict(TARGET))
        self.assertTrue(result['configured'])
        b.authorize_helper_foreground.assert_called_once_with(8765)
        args = popen.call_args.args[0]
        self.assertEqual(args[-4:], ['configure', '500', TARGET['creation'],m.HELPER_FOREGROUND_FLAG])
        process.communicate.assert_called_once_with(input=m.HELPER_FOREGROUND_GO,timeout=35)
        process.kill.assert_not_called()

    def test_created_main_identity_is_captured_from_only_our_claude_popen(self):
        b = self.backend()
        b.candidate = Path(TARGET['image'])
        child = Mock(pid=500)
        original = Mock(return_value=child)
        submodule = SimpleNamespace(Popen=original)
        def fake_guard_launch():
            submodule.Popen(['powershell.exe', '-NoProfile'])
            submodule.Popen([str(b.candidate), '--proxy-server=http://127.0.0.1:17894'])
        b.guard = SimpleNamespace(subprocess=submodule, launch=fake_guard_launch)
        b.created_process_identity = Mock(return_value=dict(TARGET))
        b.launch()
        self.assertEqual(b._created_main, TARGET)
        b.created_process_identity.assert_called_once_with(child)
        self.assertIs(submodule.Popen, original)

    def test_await_main_rejects_competing_safe_instance_without_adopting(self):
        b = self.backend()
        b.candidate = Path(TARGET['image'])
        b._created_main = dict(TARGET)
        competitor = dict(TARGET, pid=501, creation='2123456789abcdef')
        b.find_main = Mock(return_value=competitor)
        b.now = Mock(return_value=1000)
        b.require_startup_hold = Mock()
        b.alive = Mock(return_value=True)
        b.guard = SimpleNamespace(claude_process_snapshot=Mock(return_value=[]))
        with self.assertRaisesRegex(m.LaunchError, 'ambiguous_main_process'):
            b.await_main(startup_hold=object())

    def test_live_locator_uses_shared_atomic_writer_after_boundary_validation(self):
        b = self.backend()
        b.here = b.root / 'native-launcher'
        b._lease_json_io = Mock()
        nonce = 'a' * 32
        with patch.object(m, 'physical_path', side_effect=lambda path, **_: path) as physical, \
             patch.object(m.os, 'replace') as legacy_replace:
            b.save_live_locator(nonce)
        physical.assert_called_once_with(b.here / 'live-pin.json', boundary=b.root, allow_missing=True)
        b._lease_json_io.atomic_json.assert_called_once_with(
            b.here / 'live-pin.json', {'schema': 1, 'nonce': nonce})
        legacy_replace.assert_not_called()

    def test_live_locator_atomic_failure_has_no_destructive_fallback(self):
        b = self.backend()
        b.here = b.root / 'native-launcher'
        b._lease_json_io = Mock()
        b._lease_json_io.atomic_json.side_effect = OSError('injected shared writer failure')
        with patch.object(m, 'physical_path', side_effect=lambda path, **_: path), \
             patch.object(Path, 'write_text', autospec=True) as write, \
             patch.object(m.os, 'replace') as legacy_replace, \
             patch.object(Path, 'unlink', autospec=True) as unlink:
            with self.assertRaisesRegex(OSError, 'injected shared writer failure'):
                b.save_live_locator('b' * 32)
        write.assert_not_called()
        legacy_replace.assert_not_called()
        unlink.assert_not_called()

    def test_publish_uses_shared_atomic_writer_and_keeps_state_unchanged(self):
        b = self.backend()
        b.here = b.root / 'native-launcher'
        b._lease_json_io = Mock()
        b.now = Mock(return_value=1234.5)
        state = {'ok': True, 'stage': 'ready'}
        with patch.object(m, 'physical_path', side_effect=lambda path, **_: path) as physical:
            b.publish(state)
        physical.assert_called_once_with(b.here / 'native-current.json', boundary=b.here, allow_missing=True)
        b._lease_json_io.atomic_json.assert_called_once_with(
            b.here / 'native-current.json', dict(state, at_unix=1234.5))
        self.assertNotIn('at_unix', state)

    def test_shared_writer_loads_only_validated_exact_private_source(self):
        b = self.backend()
        private_source = b.root / 'environment_lease.py'
        spec, module = SimpleNamespace(loader=Mock()), SimpleNamespace(atomic_json=Mock())
        with patch.object(m, 'physical_path', return_value=private_source) as physical, \
             patch.object(m.importlib.util, 'spec_from_file_location', return_value=spec) as load_spec, \
             patch.object(m.importlib.util, 'module_from_spec', return_value=module):
            self.assertIs(b.lease_json_io(), module)
            self.assertIs(b.lease_json_io(), module)
        physical.assert_called_once_with(private_source, boundary=b.root)
        load_spec.assert_called_once_with('claude_native_launch_lease_json_io', private_source)
        spec.loader.exec_module.assert_called_once_with(module)

    def test_shared_writer_rejects_invalid_private_path_before_loading(self):
        b = self.backend()
        with patch.object(m, 'physical_path', side_effect=m.LaunchError('invalid_path')), \
             patch.object(m.importlib.util, 'spec_from_file_location') as load_spec:
            with self.assertRaisesRegex(m.LaunchError, 'invalid_path'):
                b.lease_json_io()
        load_spec.assert_not_called()


class HelperReplyTests(unittest.TestCase):
    def reply(self, command='disable-js', data=None, **overrides):
        obj = dict(ok=True, command=command, pid=500,
                   data={'javascriptDisabled': True} if data is None else data)
        obj.update(overrides)
        return json.dumps(obj)

    def test_exact_command_pid_and_critical_acknowledgements(self):
        for command, field, value in [('disable-js', 'javascriptDisabled', True),
                                      ('enable-js', 'javascriptDisabled', False),
                                      ('configure', 'configured', True),
                                      ('reload', 'reloadRequested', True),
                                      ('hide', 'hidden', True)]:
            with self.subTest(command=command):
                result = m.helper_reply(command, 500, 0, self.reply(command, {field: value}))
                self.assertIs(result[field], value)
                with self.assertRaisesRegex(m.LaunchError, 'helper_failed'):
                    m.helper_reply(command, 500, 0, self.reply(command, {field: not value}))

    def test_wrong_command_wrong_pid_empty_data_and_nonzero_exit_rejected(self):
        for payload, exit_code in [(self.reply(command='enable-js'), 0),
                                   (self.reply(pid=501), 0),
                                   (self.reply(data={}), 0),
                                   (self.reply(data='not object'), 0),
                                   (self.reply(), 2),
                                   (self.reply(), None)]:
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(m.LaunchError, 'helper_failed'):
                    m.helper_reply('disable-js', 500, exit_code, payload)

    def test_pascal_case_keys_are_accepted(self):
        result = m.helper_reply('hide', 500, 0, json.dumps(
            dict(Ok=True, Command='hide', Pid=500, Data={'Hidden': True})))
        self.assertTrue(result['Hidden'])

    def test_generic_navigation_metadata_error_is_retryable_helper_failure(self):
        payload = json.dumps(dict(ok=False, error='MetadataNotReturnedOrPasteBlocked',
                                  rawConsoleLog='never copied'))
        with self.assertRaisesRegex(m.LaunchError, 'helper_failed'):
            m.helper_reply('verify', 500, 1, payload)

    def test_only_explicit_paste_warnings_require_user_handoff(self):
        for error in ('console_paste_required', 'self_xss_warning', 'paste_warning'):
            with self.subTest(error=error):
                payload = json.dumps(dict(ok=False, error=error))
                with self.assertRaisesRegex(m.LaunchError, 'console_paste_required'):
                    m.helper_reply('verify', 500, 1, payload)


class NavigationWaitTests(unittest.TestCase):
    def backend(self, responder):
        b = m.WindowsBackend.__new__(m.WindowsBackend)
        self.clock, self.events = [1000.0], []
        b.now = lambda: self.clock[0]
        def sleep(seconds):
            self.events.append(('sleep', seconds))
            self.clock[0] += seconds
        def helper(command, identity):
            self.assertEqual(identity, TARGET)
            self.events.append((command, None))
            return responder(command)
        b.sleep, b.helper = sleep, helper
        return b

    def test_waits_for_real_devtools_then_settles_before_fresh_verify(self):
        count = [0]
        def responder(command):
            if command == 'inspect':
                count[0] += 1
                return {'windows': [{'kind': 'devtools-error-page' if count[0] < 3 else 'devtools-claude'}]}
            self.assertGreaterEqual(count[0], 3)
            self.assertEqual(self.events[-2], ('sleep', .3))
            return dict(good(), epoch=self.clock[0] * 1000)
        b = self.backend(responder)
        result = b.wait_real_metadata(dict(TARGET))
        self.assertEqual(result['origin'], 'https://claude.ai')
        self.assertEqual([e[0] for e in self.events].count('verify'), 1)
        self.assertEqual([e for e in self.events if e == ('sleep', .4)], [('sleep', .4)] * 2)

    def test_lost_nonce_during_navigation_is_bounded_retry(self):
        verifies = [0]
        def responder(command):
            if command == 'inspect':
                return {'windows': [{'kind': 'devtools-claude'}]}
            verifies[0] += 1
            if verifies[0] == 1:
                raise m.LaunchError('helper_failed')
            return dict(good(), epoch=self.clock[0] * 1000)
        result = self.backend(responder).wait_real_metadata(dict(TARGET))
        self.assertEqual(result['timeZone'], 'America/New_York')
        self.assertEqual(verifies[0], 2)

    def test_error_page_wait_is_bounded_and_never_pastes_metadata(self):
        def responder(command):
            self.assertEqual(command, 'inspect')
            return {'windows': [{'kind': 'devtools-error-page'}]}
        b = self.backend(responder)
        with self.assertRaisesRegex(m.LaunchError, 'wrong_origin'):
            b.wait_real_metadata(dict(TARGET))
        self.assertGreaterEqual(self.clock[0], 1030)
        self.assertLess(self.clock[0], 1030.5)
        self.assertNotIn('verify', [e[0] for e in self.events])

    def test_explicit_paste_warning_is_not_retried(self):
        def responder(command):
            if command == 'inspect':
                return {'windows': [{'kind': 'devtools-claude'}]}
            raise m.LaunchError('console_paste_required')
        b = self.backend(responder)
        with self.assertRaisesRegex(m.LaunchError, 'console_paste_required'):
            b.wait_real_metadata(dict(TARGET))
        self.assertEqual([e[0] for e in self.events].count('verify'), 1)

    def test_actual_wrong_timezone_is_not_treated_as_navigation_delay(self):
        def responder(command):
            if command == 'inspect':
                return {'windows': [{'kind': 'devtools-claude'}]}
            return dict(good(), timeZone='Asia/Shanghai', epoch=self.clock[0] * 1000)
        b = self.backend(responder)
        with self.assertRaisesRegex(m.LaunchError, 'wrong_timezone'):
            b.wait_real_metadata(dict(TARGET))
        self.assertEqual([e[0] for e in self.events].count('verify'), 1)


class GuiDispatchTests(unittest.TestCase):
    def test_second_gui_returns_without_constructing_window_or_backend(self):
        factory, runner = Mock(), Mock()
        result = m.gui_apply(factory, gui_mutex_factory=lambda: FakeMutex(False), window_runner=runner)
        self.assertEqual(result['mode'], 'already-running')
        factory.assert_not_called()
        runner.assert_not_called()

    def test_gui_mutex_spans_entire_window_lifecycle(self):
        events = []
        class Mutex(FakeMutex):
            def __enter__(self):
                events.append('gui-lock-enter')
                return self
            def __exit__(self, *_):
                events.append('gui-lock-exit')
        def window_runner(factory):
            events.append('window-lifecycle')
            return {'ok': True}
        result = m.gui_apply(Mock(), gui_mutex_factory=Mutex, window_runner=window_runner)
        self.assertTrue(result['ok'])
        self.assertEqual(events, ['gui-lock-enter', 'window-lifecycle', 'gui-lock-exit'])

    def test_gui_start_does_not_run_blocking_work_and_poll_owns_ui_callbacks(self):
        scheduled, workers, stages, done = [], [], [], []
        factory = Mock(return_value=FakeBackend())
        coordinator = m.GuiCoordinator(factory,
            lambda delay, fn: scheduled.append((delay, fn)), workers.append,
            stages.append, done.append)
        coordinator.start()
        factory.assert_not_called()
        self.assertEqual(scheduled[0][0], 120)
        scheduled.pop(0)[1]()
        factory.assert_not_called()
        self.assertEqual(len(workers), 1)
        workers.pop()()  # Simulate the separate worker; no GUI methods called.
        self.assertEqual(stages, [])
        self.assertEqual(done, [])
        coordinator.poll()
        self.assertTrue(done[0]['ok'])
        self.assertTrue(coordinator.done)
        self.assertEqual(stages[0], 'preflight')
        coordinator.poll()
        self.assertEqual(len(done), 1)

    def test_gui_worker_factory_error_is_delivered_as_fixed_code(self):
        events = []
        coordinator = m.GuiCoordinator(lambda: (_ for _ in ()).throw(ValueError('private detail')),
                                       lambda *_: None, lambda _: None, lambda _: None, events.append)
        coordinator._work()
        coordinator.poll()
        self.assertEqual(events[0]['code'], 'unexpected_failure')
        self.assertNotIn('private detail', json.dumps(events))


if __name__ == '__main__':
    unittest.main(verbosity=2)
