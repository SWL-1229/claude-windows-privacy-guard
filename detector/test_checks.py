import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch,Mock
import checks


class EvidenceTests(unittest.TestCase):
    def test_future_and_stale_timestamps_never_pass(self):
        self.assertTrue(checks.fresh(99,100))
        for v in [0,101,95,float('nan'),float('inf'),None,True,'2026-01-01T00:00:00']:
            self.assertFalse(checks.fresh(v,100))

    def test_expired_pass_is_unknown_on_export(self):
        item=checks.row('x','network','许可','pass','ok','','',measured=checks.stamp(100),ttl=4)
        self.assertEqual(checks.effective_state(item,103),'pass')
        self.assertEqual(checks.effective_state(item,105),'unknown')
        report={'rows':[item]}
        self.assertEqual(checks.export_report(report,now=105)['rows'][0]['state'],'unknown')
        self.assertEqual(report['rows'][0]['state'],'pass')

    def test_export_redacts_ips_without_mutating_source(self):
        report={'rows':[checks.row('x','network','出口','unknown','192.0.2.5','另一个 198.51.100.10','本机')]}
        self.assertNotIn('192.0.2.5',json.dumps(checks.export_report(report)))
        self.assertIn('192.0.2.5',json.dumps(checks.export_report(report,False)))
        self.assertEqual(report['rows'][0]['value'],'192.0.2.5')
        report['rows'][0]['value']='2001:db8::1234'
        self.assertNotIn('2001:db8::1234',json.dumps(checks.export_report(report)))

    def test_rtc_acceptance_requires_all_observed_pages(self):
        page={'rtcAccepted':True,'rtcNoRawAddressObserved':True,'environmentMatches':True,'mainDocumentLoaded':True}
        self.assertTrue(checks.accepted_rtc({'complete_target_inventory':True,'pages':[page]}))
        self.assertFalse(checks.accepted_rtc({'complete_target_inventory':True,'pages':[]}))
        self.assertFalse(checks.accepted_rtc({'pages':[page]}))
        self.assertFalse(checks.accepted_rtc({'complete_target_inventory':True,'pages':[page,dict(page,rtcAccepted=False)]}))

    def test_document_acceptance_rejects_navigation_and_error_documents(self):
        page=dict(environmentMatches=True,mainDocumentLoaded=True,isErrorDocument=False,
                  securityOriginMatchesProtected=True,protectedHttpsDocument=True,unreachableDocument=False)
        self.assertTrue(checks.document_accepted({'complete_target_inventory':True,'pages':[page]}))
        self.assertFalse(checks.document_accepted({'complete_target_inventory':True,'pages':[]}))
        for k in page:
            changed=dict(page);changed[k]=not page[k]
            self.assertFalse(checks.document_accepted({'complete_target_inventory':True,'pages':[page,changed]}))

    def test_safe_errors_never_export_payloads(self):
        self.assertEqual(checks.safe_code(ValueError('service_identity_mismatch')),'service_identity_mismatch')
        self.assertEqual(checks.safe_code(ValueError('password=secret /Users/example')),'ValueError')

    def test_invalid_destination_never_opens_socket(self):
        with patch('checks.socket.socket') as opened:
            with self.assertRaises(ValueError):checks.tls_probe(7897,'claude.ai')
            with self.assertRaises(ValueError):checks.tls_probe(17894,'evil.example')
            opened.assert_not_called()

    def test_https_uses_connect_before_tls_without_local_dns(self):
        channel=Mock()
        response=Mock(status=200)
        response.read.return_value=b'{"ip":"192.0.2.1"}'
        def tunnel(connection):
            self.assertEqual(connection._tunnel_host,'api.ipify.org')
            self.assertEqual(connection._tunnel_port,443)
            self.assertIs(connection.sock,channel)
        with patch('checks.socket.socket',return_value=channel), \
             patch('checks.socket.getaddrinfo',side_effect=AssertionError('local DNS forbidden')), \
             patch('checks.http.client.HTTPSConnection._tunnel',tunnel), \
             patch('checks.ssl.SSLContext.wrap_socket',return_value=channel) as wrap, \
             patch('checks.http.client.HTTPSConnection.request') as request, \
             patch('checks.http.client.HTTPSConnection.getresponse',return_value=response):
            result=checks.tls_probe(17894,'api.ipify.org','/?format=json',body=True)
        self.assertEqual(result['status'],200)
        channel.connect.assert_called_once_with(('127.0.0.1',17894))
        self.assertEqual(wrap.call_args.kwargs['server_hostname'],'api.ipify.org')
        self.assertEqual(request.call_args.args[:2],('GET','/?format=json'))

    def test_file_boundary_and_size(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve()
            p=root/'ok.json';p.write_text('{}')
            self.assertEqual(checks.read_small(p,root),{})
            with self.assertRaises(ValueError):checks.read_small(root.parent/'x.json',root)
            p.write_text('x'*2_000_001)
            with self.assertRaises(ValueError):checks.read_small(p,root)

    def test_no_live_services_do_not_trigger_external_probes(self):
        c=checks.Collector();c.roles={'gate':None,'core':None}
        with patch('checks.tls_probe') as probe:
            c.network();probe.assert_not_called()
        self.assertEqual(c.rows[0]['state'],'unknown')

    def test_status_without_owner_or_freshness_never_authorizes(self):
        leases=Mock()
        for role,record in [(None,{'pid':1,'updated':100}),({'ProcessId':2},{'pid':1,'updated':100}),({'ProcessId':1},{'pid':1,'updated':90})]:
            self.assertFalse(checks.owned_gate_state(record,role,leases,Path('.'),now=100))
        leases.identity.assert_not_called()

    def test_empty_report_does_not_invent_success(self):
        c=checks.Collector()
        with patch.object(c,'services',side_effect=ValueError('service_unavailable')):
            result=c.collect()
        self.assertFalse(any(row['state']=='pass' for row in result['rows']))
        self.assertTrue(any(row['key']=='dns_leak' and row['state']=='unknown' for row in result['rows']))


if __name__=='__main__':unittest.main()
