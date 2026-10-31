"""Publication/configuration boundaries only; no real installation or network."""
from pathlib import Path
import importlib.util,json,sys,tempfile,unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
build=load('source_package_builder',HERE/'build.py')
config=load('source_package_configurator',HERE/'configure.py')

class PackagingTests(unittest.TestCase):
    def test_manifest_matches_every_exported_source(self):
        self.assertGreaterEqual(len(build.verify_source()),25)

    def test_distribution_has_empty_allowlist(self):
        m=load('empty_distribution_policy',HERE/'source/deployment_allowlist.py')
        self.assertEqual(m.ALLOWED,frozenset());self.assertEqual(m.PRIMARY,'')

    def test_existing_output_never_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d).resolve();(p/'keep').write_text('original')
            with self.assertRaisesRegex(ValueError,'output_exists'):build.fresh_destination(p)
            self.assertEqual((p/'keep').read_text(),'original')

    def test_live_installation_name_refused(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,'live_installation'):
                build.fresh_destination(Path(d).resolve()/'.claude-network-guard')

    def test_relative_or_parent_traversal_refused(self):
        for p in (Path('relative'),Path.cwd()/'..'/'potential-output'):
            with self.assertRaises(ValueError):build.fresh_destination(p)

    def test_private_loopback_reserved_or_noncanonical_public_ip_refused(self):
        for value in ('127.0.0.1','192.168.1.1','192.0.2.1','::1','8.8.8.8\n',123):
            with self.subTest(value=value),self.assertRaises(ValueError):config.public_ipv4(value)
        self.assertEqual(config.public_ipv4('8.8.8.8'),'8.8.8.8') # parse only; no requests

    def valid(self):
        return {'mixed-port':17895,'bind-address':'127.0.0.1','allow-lan':False,'ipv6':False,
            'mode':'rule','external-controller':'127.0.0.1:17896','rules':['MATCH,PINNED-RESIDENTIAL'],
            'proxies':[{'name':'PINNED-ENTRY','type':'socks5','server':'fixture.example','port':1080},
                       {'name':'PINNED-RESIDENTIAL','type':'socks5','server':'8.8.8.8','port':1080,
                        'username':'fixture','password':'not-a-real-password','udp':False,'dialer-proxy':'PINNED-ENTRY'}]}

    def test_exclusive_topology_keeps_secret_local_and_rotates_controller_secret(self):
        original=self.valid();a=config.topology(original,'8.8.8.8');b=config.topology(original,'8.8.8.8')
        self.assertEqual(len(a['secret']),64);self.assertNotEqual(a['secret'],b['secret'])
        self.assertNotIn('secret',original);self.assertEqual(a['rules'],['MATCH,PINNED-RESIDENTIAL'])

    def test_direct_fallback_extra_listener_ipv6_and_wrong_final_rejected(self):
        for key,value in [('rules',['MATCH,DIRECT']),('listeners',[{}]),('ipv6',True),('allow-lan',True),('mixed-port',7897),('port',8080),('dns',{'enable':True,'listen':'0.0.0.0:53'})]:
            data=self.valid();data[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):config.topology(data,'8.8.8.8')
        data=self.valid();data['proxies'][1]['server']='1.1.1.1'
        with self.assertRaises(ValueError):config.topology(data,'8.8.8.8')

    def test_malformed_secret_input_never_printed(self):
        with patch.object(sys,'argv',['configure.py','--output','unused','--settings','unused','--core-config','unused']),patch.object(config,'prepare',side_effect=ValueError('SECRET-DO-NOT-PRINT')):
            import contextlib,io
            with contextlib.redirect_stdout(io.StringIO()) as out:code=config.main()
        self.assertEqual(code,2);self.assertNotIn('SECRET-DO-NOT-PRINT',out.getvalue())

    def test_all_exported_python_syntax_compiles_without_importing_or_launching(self):
        for p in (HERE/'source').rglob('*.py'):
            compile(p.read_text(encoding='utf8'),str(p),'exec')

if __name__=='__main__':unittest.main()
