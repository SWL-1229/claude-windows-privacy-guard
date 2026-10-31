"""Browser service startup order fixtures; no real app/network/services changed."""
import contextlib,importlib.util,io,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('browser_startup_preflight_under_test',ROOT/'claude_browser_launch.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class BrowserServicePreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()

    def test_existing_desktop_service_backend_is_reused_without_app_launch(self):
        backend=Mock();backend.ensure_services.return_value={'gate':1,'core':2,'dns_tcp':3,'dns_udp':3}
        factory=Mock(return_value=backend)
        self.assertEqual(m.ensure_shared_services(self.root,backend_factory=factory),backend.ensure_services.return_value)
        factory.assert_called_once_with(self.root);backend.ensure_services.assert_called_once_with()
        backend.launch.assert_not_called();backend.preflight.assert_not_called()

    def test_foreign_service_failure_is_sanitized_not_bypassed(self):
        backend=Mock();backend.ensure_services.side_effect=ValueError('PRIVATE-DATA-DO-NOT-PRINT')
        with self.assertRaises(m.LaunchFailure) as e:m.ensure_shared_services(self.root,backend_factory=Mock(return_value=backend))
        self.assertEqual(e.exception.code,'shared_services_not_ready')
        self.assertNotIn('PRIVATE-DATA',str(e.exception));backend.launch.assert_not_called()

    def runtime(self):
        for name in ('node.exe','msedge.exe'):(self.root/name).write_text('fixture; never executable')
        (self.root/'environment-runtime.json').write_text(json.dumps({'node_executable':str(self.root/'node.exe'),'browser_executable':str(self.root/'msedge.exe')}))

    def test_main_starts_services_before_follower_and_browser(self):
        self.runtime();events=[]
        with patch.object(m,'ROOT',self.root),patch.dict(os.environ),patch.object(sys,'argv',['browser.py','--console']),\
             patch.object(m,'ensure_shared_services',side_effect=lambda root:events.append('services')),\
             patch.object(m,'ensure_ingress_follower',side_effect=lambda root:events.append('follower')),\
             patch.object(m,'environment_preflight',side_effect=lambda root:events.append('environment')),\
             patch.object(m,'existing_environment',return_value=None),\
             patch.object(m,'launch_environment',side_effect=lambda *a,**k:events.append('browser') or {'outcome':'fixture'}),\
             contextlib.redirect_stdout(io.StringIO()):
            m.main()
        self.assertEqual(events,['services','follower','environment','browser'])

    def test_main_service_failure_does_not_launch_or_clear_a_hold(self):
        self.runtime();(self.root/'hold.block').write_text('user-owned-lock')
        with patch.object(m,'ROOT',self.root),patch.dict(os.environ),\
             patch.object(m,'ensure_shared_services',side_effect=m.LaunchFailure('shared_services_not_ready')),\
             patch.object(m,'ensure_ingress_follower') as follow,patch.object(m,'launch_environment') as launch:
            with self.assertRaises(m.LaunchFailure):m.main()
        follow.assert_not_called();launch.assert_not_called()
        self.assertEqual((self.root/'hold.block').read_text(),'user-owned-lock')

    def test_error_text_distinguishes_service_and_follower_from_bad_exit(self):
        for code in ('shared_services_not_ready','ingress_follower_not_ready','exit_outside_allowlist'):
            self.assertIn(code if code!='exit_outside_allowlist' else '出口',m.launch_failure_message(m.LaunchFailure(code)))

if __name__=='__main__':unittest.main()
