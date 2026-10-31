import threading
import time
import unittest
from foreground_gui import UserForegroundRetry, ForegroundRetryUnavailable


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.now = [100.0]
        self.bridge = UserForegroundRetry(
            lambda: self.events.append('present'),
            lambda: self.events.append('resolved'), clock=lambda: self.now[0])

    def worker(self, attempt):
        result = {}
        def work():
            try:
                result['value'] = self.bridge.request(attempt)
            except Exception as error:
                result['error'] = error
        thread = threading.Thread(target=work)
        thread.start()
        limit = time.monotonic() + 2
        while self.bridge._active is None and thread.is_alive() and time.monotonic() < limit:
            time.sleep(.001)
        return thread, result

    def test_no_attempt_until_actual_continue(self):
        seen = []
        thread, result = self.worker(lambda: seen.append(threading.get_ident()) or 'fresh-helper')
        self.bridge.poll()
        self.assertEqual(self.events, ['present'])
        self.assertEqual(seen, [])
        self.assertTrue(thread.is_alive())
        self.assertTrue(self.bridge.continue_pending())
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result, {'value': 'fresh-helper'})
        self.assertEqual(seen, [threading.get_ident()])
        self.assertEqual(self.events, ['present', 'resolved'])

    def test_double_click_cannot_retry_twice(self):
        seen = []
        thread, _ = self.worker(lambda: seen.append('attempt'))
        self.assertTrue(self.bridge.continue_pending())
        self.assertFalse(self.bridge.continue_pending())
        thread.join(2)
        self.assertEqual(seen, ['attempt'])

    def test_denied_os_grant_propagates_without_implicit_retry(self):
        seen = []
        def denied():
            seen.append('fresh-helper')
            raise ForegroundRetryUnavailable('os_grant_denied')
        thread, result = self.worker(denied)
        self.bridge.continue_pending()
        thread.join(2)
        self.assertEqual(str(result['error']), 'os_grant_denied')
        self.assertEqual(seen, ['fresh-helper'])

    def test_timeout_before_click_never_invokes_attempt(self):
        seen = []
        thread, result = self.worker(lambda: seen.append('unsafe'))
        self.now[0] += 601
        self.assertFalse(self.bridge.continue_pending())
        thread.join(2)
        self.assertEqual(seen, [])
        self.assertEqual(str(result['error']), 'user_continue_timeout')

    def test_worker_timeout_never_invokes_attempt(self):
        seen = []
        thread, result = self.worker(lambda: seen.append('unsafe'))
        self.now[0] += 601
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(seen, [])
        self.assertEqual(str(result['error']), 'user_continue_timeout')

    def test_cancel_pending_never_invokes_attempt(self):
        seen = []
        thread, result = self.worker(lambda: seen.append('unsafe'))
        self.bridge.close()
        thread.join(2)
        self.assertEqual(seen, [])
        self.assertEqual(str(result['error']), 'gui_closed')
        self.assertFalse(self.bridge.continue_pending())

    def test_no_gui_thread_blocking_request(self):
        with self.assertRaisesRegex(ForegroundRetryUnavailable, 'worker_request_required'):
            self.bridge.request(lambda: None)

    def test_only_ui_thread_can_continue(self):
        thread, result = self.worker(lambda: 'ok')
        errors = []
        def other_thread():
            try:
                self.bridge.continue_pending()
            except Exception as error:
                errors.append(error)
        other = threading.Thread(target=other_thread)
        other.start(); other.join(2)
        self.assertEqual(str(errors[0]), 'gui_thread_required')
        self.assertTrue(thread.is_alive())
        self.bridge.close(); thread.join(2)
        self.assertEqual(str(result['error']), 'gui_closed')

    def test_only_ui_thread_can_poll(self):
        errors = []
        thread = threading.Thread(target=lambda: self.catch(self.bridge.poll, errors))
        thread.start(); thread.join(2)
        self.assertEqual(str(errors[0]), 'gui_thread_required')

    def test_only_ui_thread_can_close(self):
        errors = []
        thread = threading.Thread(target=lambda: self.catch(self.bridge.close, errors))
        thread.start(); thread.join(2)
        self.assertEqual(str(errors[0]), 'gui_thread_required')

    @staticmethod
    def catch(action, errors):
        try:
            action()
        except Exception as error:
            errors.append(error)

    def test_presentation_failure_denies_request(self):
        def fail():
            raise RuntimeError('cannot show')
        self.bridge._on_pending = fail
        seen = []
        thread, result = self.worker(lambda: seen.append('unsafe'))
        self.bridge.poll(); thread.join(2)
        self.assertEqual(seen, [])
        self.assertEqual(str(result['error']), 'retry_presentation_failed')

    def test_second_pending_request_rejected(self):
        thread, first = self.worker(lambda: 'ok')
        second, result = self.worker(lambda: 'unsafe')
        second.join(2)
        self.assertEqual(str(result['error']), 'retry_not_available')
        self.bridge.continue_pending(); thread.join(2)
        self.assertEqual(first['value'], 'ok')

    def test_queue_display_never_runs_attempt(self):
        seen = []
        thread, result = self.worker(lambda: seen.append('unsafe'))
        self.bridge.poll(); self.bridge.poll()
        self.assertEqual(self.events, ['present'])
        self.assertEqual(seen, [])
        self.bridge.close(); thread.join(2)

    def test_closed_bridge_rejects_new_requests(self):
        self.bridge.close()
        thread, result = self.worker(lambda: 'unsafe')
        thread.join(2)
        self.assertEqual(str(result['error']), 'retry_not_available')

    def test_timeout_ranges_bounded(self):
        for value in (0, 601, 1e9):
            with self.assertRaises(ValueError):
                UserForegroundRetry(lambda: None, lambda: None, pending_timeout=value)

    def test_expired_unpolled_request_does_not_block_next_request(self):
        first, result = self.worker(lambda: 'unsafe')
        self.now[0] += 601
        first.join(2)
        self.assertEqual(str(result['error']), 'user_continue_timeout')
        second, next_result = self.worker(lambda: 'fresh')
        self.bridge.poll()
        self.assertEqual(self.events, ['present'])
        self.bridge.continue_pending(); second.join(2)
        self.assertEqual(next_result['value'], 'fresh')

    def test_started_callback_is_not_abandoned_after_former_ten_second_deadline(self):
        # Deliberately violate the supplied attempt's usual <=8s bound to
        # prove the bridge cannot send the worker into rollback before this
        # callback acknowledges cleanup or transfers its exact helper.
        started=threading.Event()
        release=threading.Event()
        observations=[]
        def slow_attempt():
            started.set()
            if not release.wait(13):
                raise RuntimeError('test release timeout')
            return 'transferred-helper'
        thread,result=self.worker(slow_attempt)
        def observe():
            if not started.wait(2):
                return
            self.now[0]+=1000
            time.sleep(10.2)
            observations.append(thread.is_alive() and result=={})
            release.set()
        observer=threading.Thread(target=observe)
        observer.start()
        self.assertTrue(self.bridge.continue_pending())
        observer.join(2);thread.join(2)
        self.assertEqual(observations,[True])
        self.assertEqual(result,{'value':'transferred-helper'})

    def test_exact_importlib_module_load_works_without_sys_modules_registration(self):
        import importlib.util
        from pathlib import Path
        spec=importlib.util.spec_from_file_location('claude_native_foreground_gui_test',Path(__file__).with_name('foreground_gui.py'))
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        bridge=module.UserForegroundRetry(lambda:None,lambda:None)
        self.assertIsNotNone(bridge)
        bridge.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
