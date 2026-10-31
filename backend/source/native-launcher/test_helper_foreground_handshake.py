"""Pure helper-pipe/Win32 fixtures. No app/window or native API is called."""
from pathlib import Path
import copy
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

import test_native_launch as base
m=base.m
TARGET=base.TARGET

def ready(command='configure',helper_pid=8765,**updates):
    value={'protocol':m.HELPER_FOREGROUND_PROTOCOL,'ready':True,'command':command,'pid':TARGET['pid'],'helperPid':helper_pid,'targetCreation':TARGET['creation'],'exactTargetDevToolsAlreadyForeground':False}
    value.update(updates)
    return json.dumps(value)+'\n'


class ReadyProtocol(unittest.TestCase):
    def test_exact_ready_is_bound_to_command_both_pids_and_target_creation(self):
        self.assertFalse(m.helper_ready_reply('configure',TARGET,8765,ready()))
        self.assertFalse(m.helper_ready_reply('configure',TARGET,8765,'\ufeff'+ready()))
        self.assertTrue(m.helper_ready_reply('configure',TARGET,8765,ready(exactTargetDevToolsAlreadyForeground=True)))
        for changes in ({'protocol':'other'},{'ready':1},{'command':'show'},{'pid':501},{'pid':True},{'helperPid':8766},{'helperPid':True},{'targetCreation':'0'*16},{'extra':'untrusted'},{'exactTargetDevToolsAlreadyForeground':1},{'exactTargetDevToolsAlreadyForeground':None}):
            with self.subTest(changes=changes),self.assertRaisesRegex(m.LaunchError,'helper_ready_not_confirmed'):
                m.helper_ready_reply('configure',TARGET,8765,ready(**changes))
    def test_eof_nonjson_duplicate_and_oversized_or_multiline_ready_rejected(self):
        duplicate=ready().replace('"ready": true','"ready": true, "ready": true')
        for raw in ('',None,'not json\n',ready().rstrip('\n'),ready()+'\n','x'*2049+'\n',duplicate):
            with self.subTest(raw_type=type(raw).__name__),self.assertRaisesRegex(m.LaunchError,'helper_ready_not_confirmed'):
                m.helper_ready_reply('configure',TARGET,8765,raw)


class PipeHandshake(unittest.TestCase):
    def backend(self):
        b=m.WindowsBackend.__new__(m.WindowsBackend);b.root=Path('/fixture/guard').absolute();b.here=b.root/'native-launcher';b.alive=Mock(return_value=True);b.helper_path=Mock(return_value=Path('/fixture/DevToolsUi.exe'));b.authorize_helper_foreground=Mock(return_value=True);b.helper_failures=[]
        return b
    def process(self,command='configure',data=None):
        p=Mock(pid=8765,returncode=0);p.stdout.readline.return_value=ready(command);p.poll.side_effect=[None,0]
        p.communicate.return_value=(json.dumps({'ok':True,'command':command,'pid':TARGET['pid'],'data':data or {'configured':True}}),'')
        return p
    def test_ready_then_exact_child_grant_then_fixed_go_before_result(self):
        b=self.backend();p=self.process();events=[]
        def read(limit):events.append(('ready',limit));return ready()
        p.stdout.readline.side_effect=read
        def grant(pid):events.append(('grant',pid));return True
        b.authorize_helper_foreground.side_effect=grant
        def communicate(**kwargs):events.append(('go',kwargs));return json.dumps({'ok':True,'command':'configure','pid':500,'data':{'configured':True}}),''
        p.communicate.side_effect=communicate
        with patch.object(m.subprocess,'Popen',return_value=p) as spawn:self.assertTrue(b.helper('configure',TARGET)['configured'])
        self.assertEqual([e[0] for e in events],['ready','grant','go']);self.assertEqual(events[1][1],8765);self.assertEqual(events[2][1]['input'],'CLAUDE_FOREGROUND_GRANTED_V2\n')
        self.assertEqual(spawn.call_args.args[0][-1],m.HELPER_FOREGROUND_FLAG);self.assertEqual(spawn.call_args.kwargs['stdin'],m.subprocess.PIPE)
        self.assertEqual(spawn.call_args.kwargs['encoding'],'utf-8')
        wire=io.BytesIO();writer=io.TextIOWrapper(wire,encoding=spawn.call_args.kwargs['encoding'],write_through=True);writer.write(m.HELPER_FOREGROUND_GO)
        self.assertIn(wire.getvalue(),(b'CLAUDE_FOREGROUND_GRANTED_V2\n',b'CLAUDE_FOREGROUND_GRANTED_V2\r\n'));writer.detach()
        self.assertTrue(b.helper_foreground_grants[-1]['ready_confirmed']);self.assertTrue(b.helper_foreground_grants[-1]['grant_succeeded'])
    def test_exact_foreground_branch_has_distinct_token_when_os_grant_denied(self):
        b=self.backend();p=self.process();b.authorize_helper_foreground.return_value=False
        p.stdout.readline.return_value=ready(exactTargetDevToolsAlreadyForeground=True)
        with patch.object(m.subprocess,'Popen',return_value=p):self.assertTrue(b.helper('configure',TARGET)['configured'])
        p.communicate.assert_called_once_with(input='CLAUDE_ALREADY_TARGET_FOREGROUND_V2\n',timeout=35)
        self.assertFalse(b.helper_foreground_grants[-1]['grant_succeeded'])
        self.assertEqual(b.helper_foreground_grants[-1]['authorization_mode'],'existing-target-foreground')
    def test_denied_or_nontyped_truthy_grant_sends_no_go_and_kills_only_own_waiting_helper(self):
        for result in (False,None,1):
            b=self.backend();b.authorize_helper_foreground.return_value=result;p=self.process();p.poll.side_effect=None;p.poll.return_value=None
            with patch.object(m.subprocess,'Popen',return_value=p),self.assertRaisesRegex(m.LaunchError,'helper_foreground_denied'):b.helper('configure',TARGET)
            p.kill.assert_called_once();self.assertTrue(all('input' not in call.kwargs for call in p.communicate.call_args_list));self.assertIs(b.helper_foreground_grants[-1]['grant_succeeded'],False)
    def test_invalid_ready_never_attempts_grant_or_sends_go(self):
        b=self.backend();p=self.process();p.stdout.readline.return_value=ready(helperPid=999);p.poll.side_effect=None;p.poll.return_value=None
        with patch.object(m.subprocess,'Popen',return_value=p),self.assertRaisesRegex(m.LaunchError,'helper_ready_not_confirmed'):b.helper('configure',TARGET)
        b.authorize_helper_foreground.assert_not_called();p.kill.assert_called_once();self.assertTrue(all('input' not in call.kwargs for call in p.communicate.call_args_list));self.assertFalse(b.helper_foreground_grants[-1]['grant_attempted'])
    def test_dead_ready_child_cannot_receive_grant(self):
        b=self.backend();p=self.process();p.poll.side_effect=None;p.poll.return_value=0
        with patch.object(m.subprocess,'Popen',return_value=p),self.assertRaisesRegex(m.LaunchError,'helper_ready_not_confirmed'):b.helper('configure',TARGET)
        b.authorize_helper_foreground.assert_not_called();p.communicate.assert_not_called();p.kill.assert_not_called()
    def test_ready_timeout_is_bounded_without_grant(self):
        b=self.backend();p=self.process();p.poll.side_effect=None;p.poll.return_value=None;messages=Mock();messages.get.side_effect=m.queue.Empty
        with patch.object(m.subprocess,'Popen',return_value=p),patch.object(m.queue,'Queue',return_value=messages),self.assertRaisesRegex(m.LaunchError,'helper_ready_not_confirmed'):b.helper('configure',TARGET)
        messages.get.assert_called_once_with(timeout=5);b.authorize_helper_foreground.assert_not_called();p.kill.assert_called_once()
    def test_inspect_hide_and_park_keep_old_interface_and_need_no_foreground(self):
        for command,data in [('inspect',{'windows':[]}),('hide',{'hidden':True}),('park-monitor',{'parked':True}),('park-monitor-bottom',{'parked':True})]:
            b=self.backend();p=self.process(command,data);p.poll.side_effect=None;p.poll.return_value=0
            with patch.object(m.subprocess,'Popen',return_value=p) as spawn:b.helper(command,TARGET)
            self.assertNotIn(m.HELPER_FOREGROUND_FLAG,spawn.call_args.args[0]);self.assertEqual(spawn.call_args.kwargs['stdin'],m.subprocess.DEVNULL);p.stdout.readline.assert_not_called();b.authorize_helper_foreground.assert_not_called();p.communicate.assert_called_once_with(timeout=35)
            self.assertEqual(spawn.call_args.kwargs['encoding'],'utf-8-sig')
    def test_final_helper_error_still_cannot_become_success_after_valid_grant(self):
        b=self.backend();p=self.process();p.returncode=2;p.communicate.return_value=(json.dumps({'ok':False,'command':'configure','pid':500,'error':'CannotActivateExpectedWindow','data':None}),'')
        with patch.object(m.subprocess,'Popen',return_value=p),self.assertRaisesRegex(m.LaunchError,'helper_failed'):b.helper('configure',TARGET)
        self.assertTrue(b.helper_foreground_grants[-1]['grant_succeeded']);self.assertEqual(b.helper_failures[-1]['error'],'CannotActivateExpectedWindow')
    def test_publish_records_sanitized_grant_decision_without_mutating_state(self):
        b=self.backend();b.now=Mock(return_value=1000);b._lease_json_io=Mock();b.helper_foreground_grants=[{'command':'configure','helper_pid':8765,'ready_confirmed':True,'grant_attempted':True,'grant_succeeded':False,'foreground_owner_matches_parent':False,'win32_error':0}];state={'ok':False}
        with patch.object(m,'physical_path',side_effect=lambda value,**kwargs:value):b.publish(state)
        report=b._lease_json_io.atomic_json.call_args.args[1];self.assertEqual(report['helper_foreground_grants'],b.helper_foreground_grants);self.assertEqual(state,{'ok':False});self.assertNotIn('title',str(report).lower())


class NativeGrantResult(unittest.TestCase):
    def test_native_bool_return_is_checked_and_foreground_owner_is_recorded_without_title(self):
        for allowed in (0,1):
            b=m.WindowsBackend.__new__(m.WindowsBackend)
            user=SimpleNamespace(AllowSetForegroundWindow=Mock(return_value=allowed),GetForegroundWindow=Mock(return_value=777),GetWindowThreadProcessId=Mock())
            def owner(hwnd,pointer):pointer._obj.value=m.os.getpid();return 1
            user.GetWindowThreadProcessId.side_effect=owner
            with patch.object(m.C,'WinDLL',return_value=user),patch.object(m.C,'set_last_error') as clear,patch.object(m.C,'get_last_error',return_value=0):
                self.assertIs(b.authorize_helper_foreground(8765),bool(allowed))
            user.AllowSetForegroundWindow.assert_called_once_with(8765);clear.assert_called_once_with(0);self.assertTrue(b._last_foreground_grant['foreground_owner_matches_parent']);self.assertEqual(set(b._last_foreground_grant),{'foreground_owner_matches_parent','win32_error'})
    def test_no_foreground_all_or_invalid_helper_pid_can_reach_api(self):
        b=m.WindowsBackend.__new__(m.WindowsBackend)
        with patch.object(m.C,'WinDLL') as api:
            for pid in (0,-1,0xffffffff,True,'8765'):
                with self.assertRaises(m.LaunchError):b.authorize_helper_foreground(pid)
        api.assert_not_called()


class ActivationDiagnostics(unittest.TestCase):
    def value(self):
        window={key:False for key in ('exists','visible','minimized','enabled','disabledStyle','noActivateStyle','topmostStyle','ownerPresent','ownerIsTargetProcess','differentLastPopup','lastPopupVisible','lastPopupIsTargetProcess')}
        fg={'present':True,'pid':123,'isTargetProcess':False,'isHelperProcess':False}
        return {'activationTarget':'devtools','before':dict(window),'after':dict(window),'foregroundBefore':dict(fg),'foregroundAfter':dict(fg),'showWindowPreviouslyVisible':True,'setForegroundReturned':False,'elapsedMilliseconds':1880}
    def test_only_exact_typed_sanitized_state_is_retained(self):
        value=self.value();result=m.activation_failure_metadata(value);self.assertEqual(result,value);self.assertIsNot(result,value)
        for layer in ('outer','before','foregroundBefore'):
            value=self.value();dest=value if layer=='outer' else value[layer];dest['windowTitle']='not-retained';self.assertIsNone(m.activation_failure_metadata(value))
        value=self.value();value['foregroundAfter']['pid']=True;self.assertIsNone(m.activation_failure_metadata(value))
    def test_valid_activation_failure_diagnostics_are_persisted_but_do_not_allow_success(self):
        fixture=PipeHandshake();b=fixture.backend();p=fixture.process();p.returncode=2
        p.communicate.return_value=(json.dumps({'ok':False,'command':'configure','pid':500,'error':'CannotActivateExpectedWindow','data':self.value()}),'')
        with patch.object(m.subprocess,'Popen',return_value=p),self.assertRaises(m.LaunchError):b.helper('configure',TARGET)
        self.assertEqual(b.helper_failures[-1]['activation_diagnostic'],self.value())


if __name__=='__main__':unittest.main()
