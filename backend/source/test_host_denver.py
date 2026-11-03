from copy import deepcopy
import ctypes as C
import json,sys,unittest
from pathlib import Path
from unittest.mock import patch
import browser_system_timezone as host
def identity(pid):
    return {'pid': pid, 'creation': f'{pid:016x}', 'image': 'fixed-fixture.exe'}

def good_observation():
    return {'result': 2, 'key': 'Mountain Standard Time', 'bias': 420, 'standard_bias': 0, 'daylight_bias': -60, 'dynamic_dst_disabled': 0, 'standard_rule': host.STANDARD_RULE, 'daylight_rule': host.DAYLIGHT_RULE}

class FakeReader:

    def __init__(self):
        self.value = good_observation()
        self.sessions = {11: 1, 12: 1, 13: 1}
        self.reads = 0

    def read_timezone(self):
        self.reads += 1
        return deepcopy(self.value)

    def session_id(self, pid):
        return self.sessions[pid]

class HostTimezoneTests(unittest.TestCase):

    def setUp(self):
        self.reader = FakeReader()
        self.identities = {pid: identity(pid) for pid in (11, 12, 13)}
        self.calls = []
        self.identify = lambda pid: deepcopy(self.identities.get(pid))

    def check(self, **changes):
        kwargs = {'identify': self.identify, 'same_identity': lambda a, b: a == b, 'reader': self.reader, 'current_pid': 13}
        kwargs.update(changes)
        return host.require_eastern_system_timezone(identity(11), identity(12), **kwargs)

    def denied(self, **kwargs):
        with self.assertRaises(host.HostTimezoneError):
            self.check(**kwargs)

    def test_current_eastern_and_each_call_reads_again(self):
        self.assertTrue(self.check()['session_verified'])
        self.assertTrue(self.check()['session_verified'])
        self.assertEqual(self.reader.reads, 2)

    def test_no_host_timestamp_is_returned_to_refresh_runtime(self):
        self.assertEqual(set(self.check()), {'source', 'timezone', 'session_verified'})

    def test_both_standard_and_daylight_current_states_allowed(self):
        for state in (1, 2):
            self.reader.value['result'] = state
            self.check()

    def test_no_dst_unknown_invalid_result_and_boolean_rejected(self):
        for state in (0, 4294967295, True, '2', None, -1, 3):
            with self.subTest(state=state):
                self.reader.value['result'] = state
                self.denied()

    def test_actual_missing_api_fails_closed(self):
        with patch.object(host.C, 'WinDLL', side_effect=AttributeError('missing API')):
            self.denied(reader=None)

    def test_bad_win32_layout_fails_closed(self):
        original = host.C.sizeof
        with patch.object(host.C, 'sizeof', side_effect=lambda value: 999 if value is host.DYNAMIC_TIME_ZONE_INFORMATION else original(value)):
            self.denied(reader=None)

    def test_each_bias_dst_or_key_mismatch_rejected(self):
        changes = ({'key': 'China Standard Time'}, {'key': ''}, {'bias': 240}, {'standard_bias': 60}, {'daylight_bias': 0}, {'dynamic_dst_disabled': 1}, {'dynamic_dst_disabled': False}, {'bias': '420'})
        for change in changes:
            with self.subTest(change=change):
                self.reader.value = good_observation()
                self.reader.value.update(change)
                self.denied()

    def test_wrong_or_missing_dst_transition_rejected(self):
        for key in ('standard_rule', 'daylight_rule'):
            for value in ((), (0,) * 8, (0, 3, 0, 1, 2, 0, 0, 0), None, 'US'):
                with self.subTest(key=key, value=value):
                    self.reader.value = good_observation()
                    self.reader.value[key] = value
                    self.denied()

    def test_bool_in_rule_rejected(self):
        self.reader.value['standard_rule'] = (False, 11, 0, 1, 2, 0, 0, 0)
        self.denied()

    def test_missing_timezone_field_rejected(self):
        for key in good_observation():
            with self.subTest(key=key):
                self.reader.value = good_observation()
                del self.reader.value[key]
                self.denied()

    def test_wrong_monitor_controller_or_target_session_rejected(self):
        for pid in (11, 12, 13):
            with self.subTest(pid=pid):
                self.reader.sessions = {11: 1, 12: 1, 13: 1}
                self.reader.sessions[pid] = 2
                self.denied()

    def test_session_api_error_or_invalid_value_rejected(self):
        for value in (None, True, -1, 4294967295):
            self.reader.sessions[11] = value
            self.denied()
        with patch.object(self.reader, 'session_id', side_effect=OSError('cannot inspect')):
            self.denied()

    def test_identity_before_sampling_must_be_exact(self):
        for pid in (11, 12):
            with self.subTest(pid=pid):
                old = deepcopy(self.identities)
                self.identities[pid]['creation'] = 'f' * 16
                self.denied()
                self.identities = old

    def test_identity_reuse_during_sampling_rejected(self):
        original = self.reader.read_timezone
        for pid in (11, 12, 13):
            with self.subTest(pid=pid):
                self.identities = {n: identity(n) for n in (11, 12, 13)}

                def changed():
                    value = original()
                    self.identities[pid]['creation'] = 'f' * 16
                    return value
                with patch.object(self.reader, 'read_timezone', side_effect=changed):
                    self.denied()

    def test_disappearing_identity_rejected(self):
        self.identities.pop(12)
        self.denied()

    def test_timezone_changes_between_observations_rejected(self):
        self.check()
        self.reader.value['key'] = 'China Standard Time'
        self.denied()

    def test_win_api_error_never_uses_old_success(self):
        self.check()
        with patch.object(self.reader, 'read_timezone', side_effect=OSError('API failure')):
            self.denied()
