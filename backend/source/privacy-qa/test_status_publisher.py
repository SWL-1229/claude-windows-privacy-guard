"""Account-free protocol, parent binding and destination tests."""
from pathlib import Path
import importlib.util
import io
import json
import sys
import unittest
from unittest.mock import patch

QA=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('guard_status_publisher',QA/'status_publisher.py')
pub=importlib.util.module_from_spec(spec)
spec.loader.exec_module(pub)


def status():
    return {'schema_version':1,'kind':'browser','process_pid':12,
            'environment_scope':'isolated-browser-all-web-targets-v1',
            'profile_scope':'qa-isolated','environment_check_ok':False,
            'counts':{},'error_codes':[]}


class ProtocolTests(unittest.TestCase):
    def raw(self,number=1,value=None,**extra):
        return (json.dumps({'id':number,'status':status() if value is None else value,**extra})+'\n').encode()

    def test_valid_status(self):
        number,value=pub.frame(self.raw(),1)
        self.assertEqual(number,1)
        self.assertEqual(value,status())

    def test_sequence_and_extra_commands_refused(self):
        for raw in (self.raw(2),self.raw(True),self.raw(path='elsewhere'),self.raw(command='run')):
            with self.subTest(raw=raw):
                with self.assertRaises(pub.leases.LeaseError):pub.frame(raw,1)

    def test_bounded_complete_ndjson_only(self):
        for raw in (self.raw()[:-1],b'x'*32769,b'',self.raw().decode()):
            with self.assertRaises(pub.leases.LeaseError):pub.frame(raw,1)

    def test_scope_kind_and_pid_are_exact(self):
        for field,value in (('kind','electron'),('environment_scope','other'),('profile_scope','ordinary'),('schema_version',True),('process_pid',True),('process_pid',0),('environment_check_ok',1),('environment_check_pending',1)):
            data=status();data[field]=value
            with self.subTest(field=field,value=value):
                with self.assertRaises(pub.leases.LeaseError):pub.frame(self.raw(value=data),1)

    def test_arbitrary_payload_fields_refused(self):
        for field in ('path','cookie','url','command'):
            data=status();data[field]='not-a-supported-interface'
            with self.assertRaises(pub.leases.LeaseError):pub.frame(self.raw(value=data),1)

    def test_duplicate_keys_even_nested_refused(self):
        for raw in (b'{"id":1,"id":1,"status":{}}\n',b'{"id":1,"status":{"counts":{"a":1,"a":2}}}\n'):
            with self.assertRaisesRegex(pub.leases.LeaseError,'publisher_duplicate_key'):pub.frame(raw,1)

    def invoke(self,parent=77,alive=True,source=None):
        owner={'pid':77,'creation':'1234567890abcdef','image':str(pub.ROOT/'node.exe')}
        writes=[];replies=[]
        stream=type('Input',(),{'buffer':io.BytesIO(self.raw() if source is None else source)})()
        with patch.object(pub.leases,'identity',return_value=owner),patch.object(pub.leases,'parents',return_value={pub.os.getpid():parent}),patch.object(pub.leases,'read_json',return_value={'node_executable':owner['image']}),patch.object(pub.leases,'alive',return_value=alive),patch.object(pub.leases,'atomic_json',side_effect=lambda p,v:writes.append((p,v))),patch.object(pub,'emit',side_effect=replies.append),patch.object(sys,'stdin',stream),patch.object(sys,'argv',['publisher','--controller-pid','77']):
            pub.main()
        return writes,replies

    def test_destination_derived_only_from_owning_controller(self):
        writes,replies=self.invoke()
        self.assertEqual(writes,[(pub.ROOT/'privacy-qa'/'runs'/'environment-browser-77.json',status())])
        self.assertTrue(replies[0]['ready']);self.assertEqual(replies[1],{'id':1,'ok':True})

    def test_wrong_parent_refused_before_ready_or_write(self):
        with self.assertRaisesRegex(pub.leases.LeaseError,'publisher_parent_invalid'):self.invoke(parent=78)

    def test_dead_or_replaced_controller_refused_before_write(self):
        with self.assertRaisesRegex(pub.leases.LeaseError,'publisher_parent_exited'):self.invoke(alive=False)

    def test_eof_after_ready_is_clean(self):
        writes,replies=self.invoke(source=b'')
        self.assertEqual(writes,[]);self.assertEqual(len(replies),1)


if __name__=='__main__':unittest.main()
