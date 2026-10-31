"""Offline launch-boundary tests: no real process, account, UI, or network."""
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location(
    'scoped_environment_candidate', Path(__file__).with_name('native_desktop_launch.py'))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

TARGET = Path('C:/isolated-test/package/app/Claude.exe').absolute()
IDENTITY = dict(pid=513, creation='0123456789abcdef', image=str(TARGET))
EXPECTED = dict(TZ='America/New_York', LANG='en_US.UTF-8', LC_ALL='en_US.UTF-8')


class ScopedLaunchEnvironmentTests(unittest.TestCase):
    def backend(self, plan, popen=None, identity=None):
        b = m.WindowsBackend.__new__(m.WindowsBackend)
        b.candidate = TARGET
        child = SimpleNamespace(pid=513)
        original = popen or Mock(return_value=child)
        module = SimpleNamespace(Popen=original)
        b.guard = SimpleNamespace(subprocess=module,
                                  launch=lambda: plan(module))
        b.created_process_identity = identity or Mock(return_value=dict(IDENTITY))
        return b, child, original, module

    def assert_expected(self, env):
        for name, value in EXPECTED.items():
            self.assertEqual(env[name], value)

    def test_explicit_environment_copied_and_proxy_arguments_preserved(self):
        explicit = dict(TZ='Asia/Shanghai', LANG='zh_CN.UTF-8', LC_ALL='zh_CN.UTF-8',
                        HTTPS_PROXY='http://127.0.0.1:17894', NO_PROXY='', KEEP='unchanged')
        before = explicit.copy()
        command = [str(TARGET), '--proxy-server=http://127.0.0.1:17894', '--lang=en-US']
        command_before = list(command)
        b, child, original, module = self.backend(
            lambda sub: sub.Popen(command, env=explicit, creationflags=37, cwd='C:/example'))
        with patch.dict(os.environ, {'TZ': 'Asia/Shanghai', 'LANG': 'zh-CN'}, clear=True):
            parent_before = dict(os.environ)
            b.launch()
            self.assertEqual(dict(os.environ), parent_before)
        passed = original.call_args.kwargs
        self.assert_expected(passed['env'])
        self.assertIsNot(passed['env'], explicit)
        self.assertEqual(explicit, before)
        self.assertEqual(passed['env']['HTTPS_PROXY'], before['HTTPS_PROXY'])
        self.assertEqual(passed['env']['NO_PROXY'], '')
        self.assertEqual(passed['env']['KEEP'], 'unchanged')
        self.assertEqual(passed['creationflags'], 37)
        self.assertEqual(passed['cwd'], 'C:/example')
        self.assertEqual(command, command_before)
        self.assertEqual(original.call_args.args,
                         (command_before + ['--disable-backgrounding-occluded-windows'],))
        self.assertIs(b._created_process, child)
        self.assertEqual(b._created_main, IDENTITY)
        b.created_process_identity.assert_called_once_with(child)
        self.assertIs(module.Popen, original)

    def test_missing_environment_inherits_a_copy_and_does_not_change_parent(self):
        b, _, original, _ = self.backend(lambda sub: sub.Popen([str(TARGET)]))
        with patch.dict(os.environ, {'TZ': 'Asia/Shanghai', 'LANG': 'zh-CN',
                                     'KEEP': 'parent-value'}, clear=True):
            parent_before = dict(os.environ)
            b.launch()
            self.assertEqual(dict(os.environ), parent_before)
        env = original.call_args.kwargs['env']
        self.assert_expected(env)
        self.assertEqual(env['KEEP'], 'parent-value')
        self.assertEqual(env['CLAUDE_DEV_TOOLS'], 'undocked')

    def test_explicit_none_uses_inheritance_and_empty_env_stays_otherwise_empty(self):
        for supplied in (None, {}):
            with self.subTest(supplied=supplied):
                b, _, original, _ = self.backend(
                    lambda sub: sub.Popen([str(TARGET)], env=supplied))
                with patch.dict(os.environ, {'KEEP': 'parent-value'}, clear=True):
                    b.launch()
                env = original.call_args.kwargs['env']
                self.assert_expected(env)
                if supplied is None:
                    self.assertEqual(env['KEEP'], 'parent-value')
                else:
                    self.assertEqual(env, EXPECTED)
                    self.assertEqual(supplied, {})

    def test_preflight_and_same_basename_at_another_path_are_not_modified(self):
        explicit = {'TZ': 'Asia/Shanghai', 'KEEP': 'unchanged'}
        commands = [['powershell.exe', '-NoProfile'],
                    [str(TARGET.parent.parent / 'other' / 'Claude.exe')],
                    str(TARGET), []]
        def plan(sub):
            for command in commands:
                sub.Popen(command, env=explicit, creationflags=19)
        b, _, original, module = self.backend(plan)
        b.launch()
        for call in original.call_args_list:
            self.assertIs(call.kwargs['env'], explicit)
            self.assertEqual(call.kwargs['creationflags'], 19)
        self.assertEqual(explicit, {'TZ': 'Asia/Shanghai', 'KEEP': 'unchanged'})
        self.assertIsNone(b._created_process)
        self.assertIsNone(b._created_main)
        b.created_process_identity.assert_not_called()
        self.assertIs(module.Popen, original)

    def test_popen_failure_preserves_exact_exception_and_restores_interceptor(self):
        failure = OSError('expected process creation failure')
        popen = Mock(side_effect=failure)
        b, _, _, module = self.backend(lambda sub: sub.Popen([str(TARGET)]), popen=popen)
        with patch.dict(os.environ, {'CLAUDE_DEV_TOOLS': 'prior', 'TZ': 'Asia/Shanghai'}, clear=True):
            before = dict(os.environ)
            with self.assertRaises(OSError) as result:
                b.launch()
            self.assertIs(result.exception, failure)
            self.assertEqual(dict(os.environ), before)
        self.assertIs(module.Popen, popen)
        b.created_process_identity.assert_not_called()
        self.assertIsNone(b._created_process)
        self.assertIsNone(b._created_main)

    def test_identity_failure_keeps_created_handle_for_existing_rollback_path(self):
        failure = m.LaunchError('ambiguous_main_process')
        identity = Mock(side_effect=failure)
        b, child, original, module = self.backend(
            lambda sub: sub.Popen([str(TARGET)]), identity=identity)
        with self.assertRaises(m.LaunchError) as result:
            b.launch()
        self.assertIs(result.exception, failure)
        self.assertIs(b._created_process, child)
        self.assertIsNone(b._created_main)
        self.assertIs(module.Popen, original)
        identity.assert_called_once_with(child)

    def test_non_target_then_target_records_only_target_and_preserves_first_call(self):
        preflight_env = {'TZ': 'Asia/Shanghai'}
        preflight, target = SimpleNamespace(pid=101), SimpleNamespace(pid=513)
        original = Mock(side_effect=[preflight, target])
        def plan(sub):
            sub.Popen(['powershell.exe', '-NoProfile'], env=preflight_env)
            sub.Popen([str(TARGET)], env={'HTTP_PROXY': 'http://127.0.0.1:17894'})
        b, _, _, module = self.backend(plan, popen=original)
        b.launch()
        self.assertIs(original.call_args_list[0].kwargs['env'], preflight_env)
        self.assert_expected(original.call_args_list[1].kwargs['env'])
        self.assertIs(b._created_process, target)
        b.created_process_identity.assert_called_once_with(target)
        self.assertIs(module.Popen, original)


if __name__ == '__main__':
    unittest.main(verbosity=2)
