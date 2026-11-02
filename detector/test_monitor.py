from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock,patch
import checks
import monitor


class LiveEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.now=time.time()
        self.target={'pid':123,'creation':f'{int((self.now-20+11_644_473_600)*10_000_000):016x}','image':'C:\\Claude.exe'}
        self.record={'schema':1,'kind':'native','target':self.target,'monitor':{'pid':124},'nonce':'a'*32}
        self.lease={'schema':1,'nonce':'a'*32,'ok':True,'checked_at':self.now-.2,'written_at':self.now-.1,'reason':'verified'}
        self.leases=Mock()
        self.leases.alive.return_value=True

    def test_live_proof_requires_process_monitor_and_exact_nonce(self):
        self.assertTrue(monitor.lease_valid(self.record,self.lease,self.leases,self.now))
        for key,value in [('nonce','b'*32),('checked_at',self.now-5),('written_at',self.now+1),('ok',False)]:
            self.assertFalse(monitor.lease_valid(self.record,dict(self.lease,**{key:value}),self.leases,self.now))
        self.leases.alive.return_value=False
        self.assertFalse(monitor.lease_valid(self.record,self.lease,self.leases,self.now))

    def test_nrpt_requires_all_exact_domains_and_only_loopback(self):
        roots=('claude.ai','claude.com','anthropic.com','claude.app','claudeusercontent.com','claudemcpcontent.com')
        rows=[{'Namespace':[prefix+root],'NameServers':['127.0.0.1']} for root in roots for prefix in ('','.')]
        self.assertTrue(monitor.nrpt_matches(rows))
        self.assertFalse(monitor.nrpt_matches(rows[:-1]))
        rows[-1]['NameServers']=['127.0.0.1','192.0.2.53']
        self.assertFalse(monitor.nrpt_matches(rows))

    def fixture(self, root, *, current=True, hold=False, runtime=True):
        live=monitor.LiveMonitor.__new__(monitor.LiveMonitor)
        live.root=Path(root);live.leases=self.leases;live.watchdog=Mock()
        live.roles={};live.events=[];live.last_signature=None;live.inventory_at=self.now;live.inventory_error=None
        live.unregistered_native=[]
        live.identities={'gate':self.target};live.guard_sha='fixed-sha';live.nrpt=True;live.aux_at=self.now;live.wfp=None
        live.owned=lambda role:True
        live.registrations=lambda:[self.record] if runtime else []
        live.records_error=False
        (live.root/'policy.json').write_text('{"allowed_exit_ips":["192.0.2.5"]}')
        if hold:(live.root/'hold.block').touch()
        status={'pid':123,'updated':self.now-.1 if current else self.now-10,'loaded_source_sha256':'fixed-sha',
                'allowed':True,'exit_ip':'192.0.2.5','application_transmission_state':'permitted'}
        live.leases.read_json.side_effect=lambda path,root:status if Path(path).name=='status.json' else self.lease if Path(path).name=='lease.json' else {}
        live.leases.paths.return_value=(live.root/'registration.json',live.root/'lease.json')
        live.watchdog.active_monitor.return_value={'kind':'native'}
        return live

    def test_live_native_values_come_from_fresh_proof_without_network_or_ui(self):
        with tempfile.TemporaryDirectory() as d,patch('checks.tls_probe',side_effect=AssertionError('no network')):
            live=self.fixture(d)
            result=live.snapshot()
            rows={r['key']:r for r in result['rows']}
            self.assertEqual(rows['admission']['state'],'pass')
            self.assertEqual(rows['exit']['value'],'192.0.2.5')
            self.assertEqual(rows['desktop0_timezone']['state'],'pass')
            self.assertEqual(rows['desktop0_rtc']['state'],'pass')
            live.watchdog.native_check.assert_not_called() # no competing DevTools polls

    def test_lost_monitor_and_stale_exit_remove_green(self):
        with tempfile.TemporaryDirectory() as d:
            live=self.fixture(d,current=False)
            live.watchdog.active_monitor.return_value=None
            rows={r['key']:r for r in live.snapshot()['rows']}
            self.assertEqual(rows['exit']['state'],'unknown')
            self.assertEqual(rows['desktop0_runtime']['state'],'unknown')
            self.assertEqual(rows['desktop0_timezone']['state'],'unknown')

    def test_current_hold_overrides_earlier_allow_and_does_not_remove_hold(self):
        with tempfile.TemporaryDirectory() as d:
            live=self.fixture(d,hold=True,runtime=False)
            result=live.snapshot()
            rows={r['key']:r for r in result['rows']}
            self.assertEqual(rows['admission']['state'],'fail')
            self.assertEqual(rows['desktop_runtime']['state'],'off')
            self.assertTrue((Path(d)/'hold.block').exists())
            count=len(result['events'])
            self.assertEqual(len(live.snapshot()['events']),count)

    def test_readable_reason_includes_actual_follower_failure(self):
        self.assertIn('家宽',monitor.readable_reason('main_final_not_pinned_residential'))

    def test_running_unregistered_claude_is_not_reported_as_stopped(self):
        with tempfile.TemporaryDirectory() as d:
            live=self.fixture(d,runtime=False)
            live.unregistered_native=[self.target]
            rows={r['key']:r for r in live.snapshot()['rows']}
            self.assertEqual(rows['desktop_runtime']['state'],'fail')
            self.assertIn('登记',rows['desktop_runtime']['value'])
            self.assertEqual(rows['desktop_timezone']['state'],'unknown')

    def test_inventory_read_error_is_unknown_not_stopped(self):
        with tempfile.TemporaryDirectory() as d:
            live=self.fixture(d,runtime=False)
            live.inventory_error='service_identity_unavailable'
            live.owned=lambda role:False
            rows={r['key']:r for r in live.snapshot()['rows']}
            for key in ('services','admission','exit','dns'):
                self.assertEqual(rows[key]['state'],'unknown')


if __name__=='__main__':unittest.main()
