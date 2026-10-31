/** Pure private-stdio protocol tests: no process, file or network starts. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {StatusPublisher} from './status_publisher.mjs';

const RUNTIME=JSON.stringify({python_executable:String.raw`C:\Fixture\python.exe`});
const tick=()=>new Promise(resolve=>setImmediate(resolve));
function fixture(){
  const child=new EventEmitter();child.pid=1234;child.exitCode=null;child.stdin=new PassThrough();child.stdout=new PassThrough();
  let killed=0,written='';child.stdin.on('data',chunk=>written+=chunk);
  child.kill=()=>{killed++;child.exitCode=1;child.emit('exit',1);};
  child.stdin.on('finish',()=>{child.exitCode=0;child.emit('exit',0);});
  let spawnArguments;
  const publisher=new StatusPublisher({readRuntime:async()=>RUNTIME,spawnChild:(...args)=>{spawnArguments=args;return child;}});
  const respond=value=>child.stdout.write(JSON.stringify(value)+'\n');
  const ready=async()=>{await tick();respond({ready:true,pid:1234,controller_creation:'1234567890abcdef'});await publisher.ready;};
  return {publisher,child,respond,ready,get killed(){return killed;},get written(){return written;},get spawnArguments(){return spawnArguments;}};
}

test('publisher uses only fixed private-stdio child arguments',async()=>{
  const f=fixture();await f.ready();const [exe,args,options]=f.spawnArguments;
  assert.equal(exe,String.raw`C:\Fixture\python.exe`);assert.equal(args[0],'-B');assert.ok(args[1].endsWith('status_publisher.py'));assert.deepEqual(args.slice(2),['--controller-pid',String(process.pid)]);
  assert.deepEqual(options.stdio,['pipe','pipe','ignore']);assert.equal(options.windowsHide,true);assert.equal(args.some(x=>x.includes('status-path')),false);await f.publisher.close();
});
test('publish resolves only after its atomic-write ACK',async()=>{
  const f=fixture();await f.ready();let done=false;const pending=f.publisher.publish({kind:'browser'}).then(()=>done=true);await tick();assert.equal(done,false);
  assert.deepEqual(JSON.parse(f.written.trim()),{id:1,status:{kind:'browser'}});f.respond({id:1,ok:true});await pending;assert.equal(done,true);await f.publisher.close();
});
test('publication sequence waits for preceding ACK',async()=>{
  const f=fixture();await f.ready();const one=f.publisher.publish({number:1}),two=f.publisher.publish({number:2});await tick();assert.equal(f.written.trim().split('\n').length,1);
  f.respond({id:1,ok:true});await one;await tick();assert.equal(f.written.trim().split('\n').length,2);f.respond({id:2,ok:true});await two;await f.publisher.close();
});
test('child loss rejects pending and every later publication',async()=>{
  const f=fixture();await f.ready();const pending=f.publisher.publish({});await tick();f.child.exitCode=1;f.child.emit('exit',1);await assert.rejects(pending,/publisher_exited/);await assert.rejects(f.publisher.publish({}),/publisher_exited/);await f.publisher.close();
});
test('unexpected ACK cannot complete a write and kills only owned publisher',async()=>{
  const f=fixture();await f.ready();const pending=f.publisher.publish({});await tick();f.respond({id:2,ok:true});await assert.rejects(pending,/publisher_ack_invalid/);assert.equal(f.killed,1);await f.publisher.close();
});
test('negative ACK rejects write permanently without retry',async()=>{
  const f=fixture();await f.ready();const pending=f.publisher.publish({});await tick();f.respond({ok:false,code:'lease_write_failed'});await assert.rejects(pending,/publisher_write_failed/);await assert.rejects(f.publisher.publish({}),/publisher_write_failed/);assert.equal(f.written.trim().split('\n').length,1);await f.publisher.close();
});
test('response identity must match exact owned publisher',async()=>{
  const f=fixture();await tick();f.respond({ready:true,pid:4321,controller_creation:'1234567890abcdef'});await assert.rejects(f.publisher.ready,/publisher_identity_invalid/);assert.equal(f.killed,1);await f.publisher.close();
});
test('response creation stamp must be exactly 16 lowercase hexadecimal digits',async()=>{
  const f=fixture();await tick();f.respond({ready:true,pid:1234,controller_creation:'junk1234567890abcdef'});await assert.rejects(f.publisher.ready,/publisher_identity_invalid/);await f.publisher.close();
});
test('repeated ready response is refused',async()=>{
  const f=fixture();await f.ready();f.respond({ready:true,pid:1234,controller_creation:'1234567890abcdef'});await assert.rejects(f.publisher.publish({}),/publisher_identity_invalid/);await f.publisher.close();
});
test('unexpected ACK fields are refused',async()=>{
  const f=fixture();await f.ready();const pending=f.publisher.publish({});await tick();f.respond({id:1,ok:true,path:'not-an-interface'});await assert.rejects(pending,/publisher_ack_invalid/);await f.publisher.close();
});
test('oversize outgoing frames never reach child and fail permanently',async()=>{
  const f=fixture();await f.ready();await assert.rejects(f.publisher.publish({value:'x'.repeat(32768)}),/publisher_frame_limit/);assert.equal(f.written,'');await f.publisher.close();
});
test('oversize incoming data fails with bounded protocol code',async()=>{
  const f=fixture();await tick();f.child.stdout.write('x'.repeat(32769));await assert.rejects(f.publisher.ready,/publisher_response_limit/);await f.publisher.close();
});
test('early close cannot spawn a late publisher after runtime resolves',async()=>{
  let runtimeResolve,spawns=0;const p=new StatusPublisher({readRuntime:()=>new Promise(r=>runtimeResolve=r),spawnChild:()=>{spawns++;throw Error('should not spawn');}});
  await p.close();runtimeResolve(RUNTIME);await assert.rejects(p.ready,/publisher_closed/);assert.equal(spawns,0);
});
test('invalid runtime never starts a child',async()=>{
  let spawns=0;const p=new StatusPublisher({readRuntime:async()=>JSON.stringify({python_executable:'relative.exe'}),spawnChild:()=>spawns++});await assert.rejects(p.ready,/publisher_runtime_invalid/);assert.equal(spawns,0);await p.close();
});
