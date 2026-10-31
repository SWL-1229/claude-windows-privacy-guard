/** Pure protocol/config fixtures. No executable is started or real profile read. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {EnvironmentController,PrivatePipeTransport,parseJsonStrict,validateConfig,validateProtocolCall,protectedUrl,METADATA_EXPRESSION,consumeLifecycleMarker} from './claude_environment_controller.mjs';

const EXE=String.raw`C:\Program Files\Fixture\Claude.exe`;
const ROOT=String.raw`C:\FixtureGuard`;
const BASE_ARGS=['--proxy-server=http://127.0.0.1:17894','--proxy-bypass-list=<-loopback>','--disable-quic','--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1','--webrtc-ip-handling-policy=disable_non_proxied_udp','--lang=en-US','--accept-lang=en-US,en'];
function config(kind='electron') {return {schema_version:1,kind,exe:EXE,args:[...BASE_ARGS,...(kind==='browser'?[String.raw`--user-data-dir=C:\FixtureGuard\privacy-qa\runs\new-profile`]:[])],domains:['claude.ai','anthropic.com'],timezone:'America/New_York',locale:'en_US'};}
function checked(kind='electron'){return validateConfig(config(kind),[{kind,exe:EXE}],ROOT);}
const METADATA={timeZone:'America/New_York',locale:'en-US',language:'en-US',languages:['en-US','en'],januaryOffset:300,julyOffset:240};
class FakePipe {
  constructor(){this.handlers=[];this.calls=[];this.targets=[];this.sessions=new Map();this.frames=new Map();this.nextLoader=0;this.commitMode='fresh';this.failMethods=new Set();this.metadata=METADATA;this.closed=false;}
  on(fn){this.handlers.push(fn);return()=>this.handlers=this.handlers.filter(x=>x!==fn);}
  frame(sessionId){
    if(!this.frames.has(sessionId)){
      const id=this.sessions.get(sessionId)??sessionId?.replace(/^manual-/,'');
      const url=this.targets.find(info=>info.targetId===id)?.url??'about:blank';
      let securityOrigin=':';try{securityOrigin=new URL(url).origin;}catch{}
      this.frames.set(sessionId,{id:'frame-'+sessionId,url,securityOrigin,loaderId:'initial-loader-'+sessionId});
    }
    return this.frames.get(sessionId);
  }
  commit(sessionId,url){
    const frame=this.frame(sessionId);
    if(this.commitMode==='same-loader')return;
    frame.loaderId='committed-loader-'+(++this.nextLoader);
    frame.url=url??frame.url;
    frame.securityOrigin=new URL(frame.url).origin;
    if(this.commitMode==='error-page'){frame.url='chrome-error://chromewebdata/';frame.securityOrigin='chrome-error://chromewebdata';}
    if(this.commitMode==='unreachable')frame.unreachableUrl='https://claude.ai/private-unreachable?token=never-persisted';
    if(this.commitMode==='wrong-origin')frame.securityOrigin='https://unrelated.invalid';
    if(this.commitMode==='missing-loader')delete frame.loaderId;
  }
  async call(method,params={},sessionId){
    validateProtocolCall(method,params,sessionId);this.calls.push({method,params,sessionId});
    if(this.failMethods.has(method))throw Error('fixture error containing secret-account-url');
    if(method==='Browser.getVersion')return{product:'Chrome/155.0.0.0',userAgent:'not-persisted'};
    if(method==='Target.getTargets')return{targetInfos:this.targets};
    if(method==='Target.attachToTarget')return{sessionId:'manual-'+params.targetId};
    if(method==='Page.getFrameTree')return{frameTree:{frame:{...this.frame(sessionId)}}};
    if(method==='Page.navigate'||method==='Page.reload')this.commit(sessionId,params.url);
    if(method==='Runtime.evaluate')return{result:{value:JSON.stringify(this.metadata)}};
    return{};
  }
  emit(msg){if(msg.method==='Target.attachedToTarget'){const p=msg.params;this.sessions.set(p.sessionId,p.targetInfo.targetId);this.targets=this.targets.filter(t=>t.targetId!==p.targetInfo.targetId);this.targets.push(p.targetInfo);}else if(msg.method==='Target.targetInfoChanged'){const info=msg.params.targetInfo;this.targets=this.targets.map(t=>t.targetId===info.targetId?info:t);}else if(msg.method==='Target.detachedFromTarget'){const id=this.sessions.get(msg.params.sessionId);this.targets=this.targets.filter(t=>t.targetId!==id);}for(const fn of this.handlers)fn(msg);}
  close(){this.closed=true;}
}
async function fixtureController(kind='electron'){const pipe=new FakePipe();const statuses=[];const controller=new EnvironmentController(checked(kind),pipe,async s=>statuses.push(s));await controller.start({monitor:false});return{pipe,controller,statuses};}
const target=(id,type='page',url='https://claude.ai/private-account?token=not-real')=>({targetId:id,type,url,attached:true});
async function attach(fixture,id,type='page',url,paused=true){fixture.pipe.emit({method:'Target.attachedToTarget',params:{sessionId:'session-'+id,targetInfo:target(id,type,url),waitingForDebugger:paused}});await fixture.controller.flush();}

test('strict JSON rejects duplicate keys including nested keys',()=>{assert.throws(()=>parseJsonStrict('{"kind":"browser","kind":"electron"}'));assert.throws(()=>parseJsonStrict('{"x":{"a":1,"a":2}}'));assert.deepEqual(parseJsonStrict('{"x":[1,{"a":"\\\""}]}'),{x:[1,{a:'"'}]});});
test('unknown schema properties and unauthorized paths are refused',()=>{assert.throws(()=>validateConfig({...config(),extra:true},[{kind:'electron',exe:EXE}],ROOT));assert.throws(()=>validateConfig(config(),[],ROOT));});
test('only approved timezone and locale accepted',()=>{assert.throws(()=>validateConfig({...config(),timezone:'Asia/Shanghai'},[{kind:'electron',exe:EXE}],ROOT));assert.equal(checked().timezone,'America/New_York');});
test('TCP debugging and unsafe flags refused',()=>{for(const arg of ['--remote-debugging-port=9222','--inspect=9229','--remote-debugging-pipe','--no-sandbox','--load-extension=C:\\Fixture','--PROXY-SERVER=http://127.0.0.1:7897'])assert.throws(()=>validateConfig({...config(),args:[...BASE_ARGS,arg]},[{kind:'electron',exe:EXE}],ROOT));});
test('bad proxy, duplicate flags and missing protection refused',()=>{assert.throws(()=>validateConfig({...config(),args:[...BASE_ARGS,'--disable-quic']},[{kind:'electron',exe:EXE}],ROOT));assert.throws(()=>validateConfig({...config(),args:BASE_ARGS.filter(x=>x!=='--disable-quic')},[{kind:'electron',exe:EXE}],ROOT));assert.throws(()=>validateConfig({...config(),args:BASE_ARGS.map(x=>x.startsWith('--proxy-server')?'--proxy-server=http://example.com:80':x)},[{kind:'electron',exe:EXE}],ROOT));});
test('modern RTC and resolver exclusion accepted; old forms refused',()=>{assert.ok(checked());for(const arg of ['--force-webrtc-ip-handling-policy=disable_non_proxied_udp','--host-resolver-rules=MAP * ~NOTFOUND'])assert.throws(()=>validateConfig({...config(),args:[...BASE_ARGS.filter(x=>!x.startsWith(arg.split('=')[0]+'=')),arg]},[{kind:'electron',exe:EXE}],ROOT));});
test('browser must use dedicated profile; standard profile rejected',()=>{assert.ok(checked('browser').profile);const c=config('browser');c.args=c.args.filter(x=>!x.startsWith('--user-data-dir'));assert.throws(()=>validateConfig(c,[{kind:'browser',exe:EXE}],ROOT));c.args.push(String.raw`--user-data-dir=C:\Users\Fixture\Microsoft\Edge\User Data`);assert.throws(()=>validateConfig(c,[{kind:'browser',exe:EXE}],ROOT));});
test('domain matching does not include lookalikes or credentials',()=>{assert.equal(protectedUrl('https://sub.claude.ai/test',['claude.ai']),true);assert.equal(protectedUrl('https://claude.ai.evil.example',['claude.ai']),false);assert.equal(protectedUrl('https://notclaude.ai',['claude.ai']),false);assert.equal(protectedUrl('https://user:pass@claude.ai',['claude.ai']),false);assert.equal(protectedUrl('blob:https://claude.ai/uuid',['claude.ai']),true);});
test('arbitrary protocol methods and metadata expressions refused',()=>{for(const method of ['Network.getAllCookies','Runtime.callFunctionOn','Page.navigate','Fetch.enable'])assert.throws(()=>validateProtocolCall(method,{},'session'));assert.throws(()=>validateProtocolCall('Runtime.evaluate',{expression:'document.cookie',returnByValue:true,silent:true,includeCommandLineAPI:false},'session'));});
test('headers allow only English or reset and no authorization headers',()=>{validateProtocolCall('Network.setExtraHTTPHeaders',{headers:{'Accept-Language':'en-US,en;q=0.9'}},'session');validateProtocolCall('Network.setExtraHTTPHeaders',{headers:{}},'session');assert.throws(()=>validateProtocolCall('Network.setExtraHTTPHeaders',{headers:{Authorization:'secret'}},'session'));});
test('Electron page overrides before resume and metadata after resume',async()=>{const f=await fixtureController();await attach(f,'page1','page','file:///signed-program/wrapper.html');const calls=f.pipe.calls.filter(c=>c.sessionId==='session-page1').map(c=>c.method);assert.ok(calls.indexOf('Emulation.setTimezoneOverride')<calls.indexOf('Runtime.runIfWaitingForDebugger'));assert.ok(calls.indexOf('Runtime.evaluate')>calls.indexOf('Runtime.runIfWaitingForDebugger'));assert.equal(f.controller.snapshot().counts.covered_pages,1);assert.equal(f.controller.snapshot().protected_environment_verified,false);});
test('Electron iframe configured and metadata checked',async()=>{const f=await fixtureController();await attach(f,'frame1','iframe');assert.equal(f.controller.snapshot().counts.covered_iframes,1);assert.equal(f.controller.snapshot().counts.metadata_matches,1);});
test('isolated browser external targets use actual system metadata without emulation setters',async()=>{const f=await fixtureController('browser');await attach(f,'other','page','https://example.com/');const calls=f.pipe.calls.filter(c=>c.sessionId==='session-other');assert.equal(calls.some(c=>c.method==='Emulation.setTimezoneOverride'||c.method==='Emulation.setLocaleOverride'),false);assert.ok(calls.some(c=>c.method==='Runtime.evaluate'));assert.equal(f.controller.records.get('session-other').metadataConfirmed,true);});
test('isolated browser leaving product domains never clears its environment',async()=>{const f=await fixtureController('browser');await attach(f,'blank','page','about:blank');f.pipe.emit({method:'Target.targetInfoChanged',params:{targetInfo:target('blank','page','https://example.com/')}});await f.controller.flush();assert.equal(f.pipe.calls.some(c=>c.sessionId==='session-blank'&&c.method==='Emulation.setTimezoneOverride'&&c.params.timezoneId===''),false);assert.equal(f.controller.records.get('session-blank').inScope,true);assert.equal(f.controller.snapshot().counts.navigation_scope_resets,0);});
test('existing unpaused target explicitly reported',async()=>{const pipe=new FakePipe();pipe.targets=[target('existing')];const c=new EnvironmentController(checked(),pipe);await c.start({monitor:false});assert.equal(c.snapshot().counts.early_unpaused_targets,1);assert.ok(c.snapshot().error_codes.includes('early_unpaused_target'));});
test('worker unsupported emulation is reported; metadata inheritance can pass',async()=>{const f=await fixtureController();f.pipe.failMethods.add('Emulation.setTimezoneOverride');await attach(f,'worker','worker');assert.equal(f.controller.snapshot().counts.workers_inherited_verified,1);assert.ok(f.controller.snapshot().error_codes.includes('worker_override_unavailable'));});
test('worker mismatch is not passed off as covered',async()=>{const f=await fixtureController();f.pipe.metadata={...METADATA,timeZone:'Asia/Shanghai'};await attach(f,'worker','worker');assert.equal(f.controller.snapshot().counts.workers_unverified,1);assert.ok(f.controller.snapshot().error_codes.includes('worker_environment_unverified'));assert.equal(f.controller.snapshot().status,'partial');});
test('setup errors still resume paused child and remain partial',async()=>{const f=await fixtureController();f.pipe.failMethods.add('Network.setExtraHTTPHeaders');await attach(f,'failed');assert.ok(f.pipe.calls.some(c=>c.sessionId==='session-failed'&&c.method==='Runtime.runIfWaitingForDebugger'));assert.equal(f.controller.snapshot().status,'partial');});
test('status never includes target URL, account, raw error or arbitrary metadata',async()=>{const f=await fixtureController();f.pipe.failMethods.add('Network.setExtraHTTPHeaders');await attach(f,'private');const serialized=JSON.stringify(f.statuses);for(const item of ['private-account','token=not-real','secret-account-url','https://claude.ai','not-persisted'])assert.equal(serialized.includes(item),false);});
test('metadata expression is the fixed account-free expression only',()=>{validateProtocolCall('Runtime.evaluate',{expression:METADATA_EXPRESSION,returnByValue:true,silent:true,includeCommandLineAPI:false},'session');assert.equal(/cookie|document\.|localStorage|fetch\(/i.test(METADATA_EXPRESSION),false);});
test('shutdown closes only owned child via private protocol',async()=>{const f=await fixtureController();await f.controller.stop();assert.ok(f.pipe.calls.some(c=>c.method==='Browser.close'));assert.equal(f.pipe.closed,true);});
test('pipe protocol uses private streams and null-delimited frames',async()=>{const child=new EventEmitter();child.stdio=[null,null,null,new PassThrough(),new PassThrough()];const pipe=new PrivatePipeTransport(child);let sent='';child.stdio[3].on('data',chunk=>sent+=chunk);const answer=pipe.call('Browser.getVersion');assert.ok(sent.endsWith('\0'));child.stdio[4].write(JSON.stringify({id:1,result:{product:'Chrome/155.0.0.0'}})+'\0');assert.equal((await answer).product,'Chrome/155.0.0.0');pipe.close();});

test('navigation protocol allows only fixed Claude GET and ordinary reload',()=>{
  validateProtocolCall('Page.navigate',{url:'https://claude.ai/'},'owned');
  validateProtocolCall('Page.reload',{ignoreCache:false},'owned');
  for(const params of [{url:'https://evil.example/'},{url:'https://claude.ai/?token=private'},{url:'https://claude.ai/',referrer:'private'}])assert.throws(()=>validateProtocolCall('Page.navigate',params,'owned'));
  assert.throws(()=>validateProtocolCall('Page.reload',{ignoreCache:true},'owned'));
  assert.throws(()=>validateProtocolCall('Page.navigate',{url:'https://claude.ai/'}));
});
test('activation waits for prepared metadata and never starts unrelated targets',async()=>{
  const f=await fixtureController('browser');await attach(f,'other','page','https://example.com/');
  await f.controller.activate();assert.equal(f.controller.snapshot().activation_complete,false);
  assert.equal(f.pipe.calls.some(c=>c.method==='Page.navigate'||c.method==='Page.reload'),false);
  assert.equal(f.controller.snapshot().document_health.accepted,false);
  assert.deepEqual(f.controller.snapshot().document_health.pages,[]);
  assert.equal(f.pipe.closed,false);
});
test('browser activation navigates a prepared blank page once and rechecks metadata',async()=>{
  const f=await fixtureController('browser');await attach(f,'blank','page','about:blank');
  const before=f.controller.snapshot().counts.metadata_matches;
  const previousLoader=f.pipe.frame('session-blank').loaderId;
  await f.controller.activate();await f.controller.activate();
  const navigation=f.pipe.calls.filter(c=>c.method==='Page.navigate');
  assert.equal(navigation.length,1);assert.deepEqual(navigation[0].params,{url:'https://claude.ai/'});
  assert.equal(f.controller.snapshot().activation_complete,true);
  assert.notEqual(f.pipe.frame('session-blank').loaderId,previousLoader);
  assert.equal(f.controller.snapshot().document_health.accepted,true);
  assert.equal(f.controller.snapshot().document_health.pages[0].freshDocument,true);
  assert.ok(f.controller.snapshot().counts.metadata_matches>before);
});
test('Electron activation reloads protected HTTPS page but never local wrapper',async()=>{
  const f=await fixtureController();await attach(f,'wrapper','page','file:///signed-app/wrapper.html');await attach(f,'claude');
  await f.controller.activate();const reloads=f.pipe.calls.filter(c=>c.method==='Page.reload');
  assert.equal(reloads.length,1);assert.equal(reloads[0].sessionId,'session-claude');
  assert.deepEqual(reloads[0].params,{ignoreCache:false});assert.equal(f.controller.snapshot().activation_complete,true);
});
test('Electron wrapper-only activation stays incomplete instead of reloading local code',async()=>{
  const f=await fixtureController();await attach(f,'wrapper','page','file:///signed-app/wrapper.html');await f.controller.activate();
  assert.equal(f.controller.snapshot().activation_complete,false);assert.equal(f.pipe.calls.some(c=>c.method==='Page.reload'),false);
});
test('activation failure is not repeated and cannot report complete',async()=>{
  const f=await fixtureController('browser');await attach(f,'blank','page','about:blank');f.pipe.failMethods.add('Page.navigate');
  await f.controller.activate();await f.controller.activate();assert.equal(f.controller.snapshot().activation_complete,false);
  assert.equal(f.pipe.calls.filter(c=>c.method==='Page.navigate').length,1);
  assert.equal(f.controller.snapshot().document_health.accepted,false);
  assert.deepEqual(f.controller.snapshot().document_health.pages,[]);
  assert.equal(f.pipe.closed,false);
});

test('fresh error or unreachable document cannot pass activation even with correct runtime metadata',async()=>{
  for(const mode of ['error-page','unreachable']){
    const f=await fixtureController('browser');await attach(f,'page');
    f.pipe.commitMode=mode;
    await f.controller.activate();
    const status=f.controller.snapshot();
    assert.equal(status.environment_check_ok,true);
    assert.equal(status.activation_complete,false);
    assert.equal(status.document_health.accepted,false);
    assert.equal(status.document_health.pages[0].freshDocument,true);
    assert.equal(status.document_health.pages[0].isErrorDocument,true);
    assert.equal(f.pipe.closed,false);
    assert.equal(JSON.stringify(f.statuses).includes('private-unreachable'),false);
    await f.controller.stop();
  }
});

test('healthy metadata and protected URL cannot reuse the pre-reload document loader as activation proof',async()=>{
  const f=await fixtureController();await attach(f,'page');
  f.pipe.commitMode='same-loader';f.controller.documentHealthDeadlineMs=0;
  const before=f.pipe.frame('session-page').loaderId;
  await f.controller.activate();
  const status=f.controller.snapshot();
  assert.equal(status.environment_check_ok,true);
  assert.equal(status.activation_complete,false);
  assert.equal(status.document_health.pages[0].freshDocument,false);
  assert.equal(status.document_health.pages[0].isErrorDocument,false);
  assert.equal(status.document_health.pages[0].securityOriginMatchesProtected,true);
  assert.equal(f.pipe.frame('session-page').loaderId,before);
  assert.equal(f.pipe.closed,false);
});

test('activation requires both pre-navigation and committed loader IDs plus protected security origin',async()=>{
  for(const mode of ['missing-prior-loader','missing-loader','wrong-origin']){
    const f=await fixtureController('browser');await attach(f,'page');
    f.controller.documentHealthDeadlineMs=0;
    if(mode==='missing-prior-loader')delete f.pipe.frame('session-page').loaderId;
    else f.pipe.commitMode=mode;
    await f.controller.activate();
    const status=f.controller.snapshot();
    assert.equal(status.environment_check_ok,true);
    assert.equal(status.activation_complete,false);
    assert.equal(status.document_health.accepted,false);
    if(mode==='wrong-origin')assert.equal(status.document_health.pages[0].securityOriginMatchesProtected,false);
    else assert.equal(status.document_health.pages[0].freshDocument,false);
    assert.equal(f.pipe.closed,false);
    await f.controller.stop();
  }
});
test('browser unknown non-protected target is not reported as a protection gap',async()=>{
  const f=await fixtureController('browser');await attach(f,'other','other','edge://unrelated-internal/',false);
  assert.equal(f.controller.snapshot().counts.unknown_target_types,0);assert.equal(f.controller.snapshot().counts.early_unpaused_targets,0);
  assert.equal(f.controller.snapshot().counts.unprotected_targets,0);assert.equal(f.controller.snapshot().counts.internal_targets_ignored,1);
  assert.equal(f.controller.snapshot().error_codes.includes('unknown_target_type_unverified'),false);
});
test('target URL remains private even after navigation and activation',async()=>{
  const f=await fixtureController();await attach(f,'secret');
  f.pipe.emit({method:'Target.targetInfoChanged',params:{targetInfo:target('secret','page','https://claude.ai/private-updated?key=not-real')}});await f.controller.flush();
  await f.controller.activate();const output=JSON.stringify(f.statuses);assert.equal(output.includes('private-updated'),false);assert.equal(output.includes('not-real'),false);
});
test('exact empty lifecycle markers are consumed once; payloads and directories refused',async()=>{
  const tempRoot=await fs.realpath(os.tmpdir());
  const base=await fs.realpath(await fs.mkdtemp(path.join(tempRoot,'claude-controller-marker-')));
  const statusPath=path.join(base,'environment-browser-123.json');
  try{
    assert.equal(await consumeLifecycleMarker(statusPath,'.activate'),false);
    await fs.writeFile(statusPath+'.activate','');assert.equal(await consumeLifecycleMarker(statusPath,'.activate'),true);
    assert.equal(await consumeLifecycleMarker(statusPath,'.activate'),false);
    await fs.writeFile(statusPath+'.stop','payload');await assert.rejects(consumeLifecycleMarker(statusPath,'.stop'));
    assert.equal(await fs.readFile(statusPath+'.stop','utf8'),'payload');
    await assert.rejects(consumeLifecycleMarker(statusPath,'.arbitrary'));
    await fs.unlink(statusPath+'.stop');await fs.mkdir(statusPath+'.stop');await assert.rejects(consumeLifecycleMarker(statusPath,'.stop'));
  }finally{
    assert.equal(path.dirname(base),tempRoot);assert.ok(path.basename(base).startsWith('claude-controller-marker-'));
    await fs.rm(base,{recursive:true,force:true});
  }
});
test('idle reconcile publishes a liveness heartbeat without new targets',async()=>{
  const f=await fixtureController('browser');const before=f.statuses.length;
  await f.controller.reconcile();assert.equal(f.statuses.length,before+1);
  const report=f.statuses.at(-1);assert.equal(typeof report.at,'string');assert.equal(report.counts.attached,0);
});

test('a real metadata sweep, not a status heartbeat, renews environment permission',async()=>{
  const f=await fixtureController('browser');await attach(f,'page');
  assert.equal(f.controller.snapshot().environment_check_ok,false);
  const before=f.pipe.calls.filter(c=>c.method==='Runtime.evaluate').length;
  await f.controller.reconcile();const first=f.controller.snapshot();
  assert.equal(first.environment_check_ok,true);assert.equal(typeof first.environment_check_at,'string');
  assert.equal(first.counts.environment_checks,1);
  await f.controller.publish();assert.equal(f.controller.snapshot().counts.environment_checks,1);
  await f.controller.reconcile();assert.equal(f.controller.snapshot().counts.environment_checks,2);
  assert.ok(f.pipe.calls.filter(c=>c.method==='Runtime.evaluate').length>=before+2);
});
test('external frame and worker are included in the same periodic sweep',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');await attach(f,'external-frame','iframe','https://example.com/');await attach(f,'external-worker','worker','https://example.com/worker.js');
  const before=f.pipe.calls.length;await f.controller.reconcile();
  const checked=new Set(f.pipe.calls.slice(before).filter(c=>c.method==='Runtime.evaluate').map(c=>c.sessionId));
  assert.deepEqual(checked,new Set(['session-main','session-external-frame','session-external-worker']));
  assert.equal(f.controller.snapshot().environment_check_ok,true);
});
test('changing existing page timezone revokes permission and closes only the owned browser',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');await f.controller.reconcile();
  const lastGood=f.controller.snapshot().environment_check_at;
  f.pipe.metadata={...METADATA,timeZone:'Asia/Shanghai'};await f.controller.reconcile();
  const state=f.controller.snapshot();assert.equal(state.environment_check_ok,false);assert.equal(state.environment_check_at,lastGood);
  assert.ok(state.error_codes.includes('continuous_environment_mismatch'));assert.equal(state.counts.environment_check_failures,1);
  assert.equal(f.pipe.calls.filter(c=>c.method==='Browser.close').length,1);assert.equal(f.pipe.closed,true);
  assert.ok(f.statuses.some(s=>s.environment_check_ok===false&&s.status==='environment_failed'));
});
test('same verified sessions retain only their original TTL while metadata is pending',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');await f.controller.reconcile();
  const lastGood=f.controller.snapshot().environment_check_at;f.pipe.failMethods.add('Runtime.evaluate');
  await f.controller.reconcile();assert.equal(f.controller.snapshot().environment_check_ok,true);assert.equal(f.controller.snapshot().environment_check_at,lastGood);assert.equal(f.pipe.closed,false);assert.equal(f.controller.snapshot().last_environment_diagnostic,'metadata_unavailable');assert.equal(f.controller.snapshot().counts.environment_check_failures,0);assert.equal(f.controller.snapshot().environment_check_pending,true);await f.controller.stop();
});
test('private pipe failure revokes the environment instead of waiting for a fake heartbeat',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');await f.controller.reconcile();
  f.pipe.emit({method:'PrivatePipe.failed'});await f.controller.flush();if(f.controller.failing)await f.controller.failing;
  assert.equal(f.controller.snapshot().environment_check_ok,false);assert.equal(f.pipe.closed,true);
});
test('failure to persist revocation does not prevent owned browser shutdown',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');await f.controller.reconcile();
  f.controller.writeStatus=async()=>{throw Error('fixture failure');};
  await f.controller.failClosed('fixture_failure');assert.equal(f.pipe.closed,true);assert.ok(f.controller.snapshot().error_codes.includes('revocation_status_write_failed'));
});
test('unknown executable web target is refused while internal browser targets stay ignored',async()=>{
  const f=await fixtureController('browser');await attach(f,'internal','other','edge://internal/');
  assert.equal(f.pipe.closed,false);await attach(f,'web-unknown','other','https://example.com/');
  assert.equal(f.pipe.closed,true);assert.equal(f.controller.snapshot().environment_check_ok,false);assert.ok(f.controller.snapshot().error_codes.includes('unsupported_executable_target'));
});
test('normally retired worker during a sweep is not mistaken for leaked metadata',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');await attach(f,'worker','worker');
  const original=f.pipe.call.bind(f.pipe);f.pipe.call=async(method,params,session)=>{
    if(method==='Runtime.evaluate'&&session==='session-worker'){f.pipe.targets=f.pipe.targets.filter(t=>t.targetId!=='worker');throw Error('context retired');}
    return original(method,params,session);
  };
  await f.controller.reconcile();assert.equal(f.controller.snapshot().environment_check_ok,true);assert.equal(f.pipe.closed,false);
});
test('new unconfigured target cannot be hidden by renewing the old target heartbeat',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');await f.controller.reconcile();
  const good=f.controller.snapshot().environment_check_at;const original=f.pipe.call.bind(f.pipe);
  f.pipe.call=async(method,params,session)=>{if(method==='Runtime.evaluate'&&!f.pipe.targets.some(t=>t.targetId==='new-page'))f.pipe.targets.push(target('new-page'));return original(method,params,session);};
  await f.controller.checkEnvironment();assert.equal(f.controller.snapshot().environment_check_ok,false);assert.equal(f.controller.snapshot().environment_check_at,good);assert.equal(f.pipe.closed,false);
  await f.controller.stop();
});
test('short-lived worker already retired before initial inspection does not close healthy parent',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');const original=f.pipe.call.bind(f.pipe);
  f.pipe.call=async(method,params,session)=>{if(method==='Runtime.evaluate'&&session==='session-quick'){f.pipe.targets=f.pipe.targets.filter(t=>t.targetId!=='quick');throw Error('worker already ended');}return original(method,params,session);};
  await attach(f,'quick','worker');await f.controller.reconcile();
  assert.equal(f.controller.snapshot().environment_check_ok,true);assert.equal(f.controller.snapshot().counts.retired_before_metadata,1);assert.equal(f.controller.snapshot().counts.workers_unverified,0);assert.equal(f.pipe.closed,false);
});
test('static scope labels distinguish an isolated QA fixture from the one persistent Claude profile',()=>{
  const qa=new EnvironmentController(checked('browser'),new FakePipe()).snapshot();
  assert.equal(qa.environment_scope,'isolated-browser-all-web-targets-v1');assert.equal(qa.profile_scope,'qa-isolated');
  const cfg={...checked('browser'),profile:fileURLToPath(new URL('../browser-profiles/edge-claude',import.meta.url))};
  const persistent=new EnvironmentController(cfg,new FakePipe()).snapshot();assert.equal(persistent.profile_scope,'claude-persistent');
});
test('one transient destroyed context is retried without withdrawing a still-good timestamp',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');await f.controller.reconcile();const original=f.pipe.call.bind(f.pipe);let unavailable=true;
  f.pipe.call=async(method,params,session)=>{if(method==='Runtime.evaluate'&&unavailable){unavailable=false;throw Error('execution context destroyed');}return original(method,params,session);};
  await f.controller.reconcile();assert.equal(f.controller.snapshot().environment_check_ok,true);assert.equal(f.controller.snapshot().last_environment_diagnostic,'verified');assert.equal(f.pipe.closed,false);
});

test('pending unavailable context expires at the original grant, without timestamp refresh',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');await f.controller.reconcile();
  const expired=new Date(Date.now()-4100).toISOString();f.controller.status.environment_check_at=expired;f.pipe.failMethods.add('Runtime.evaluate');
  await f.controller.reconcile();assert.equal(f.controller.snapshot().environment_check_ok,false);assert.equal(f.controller.snapshot().environment_check_pending,true);assert.equal(f.controller.snapshot().environment_check_at,expired);assert.equal(f.pipe.closed,false);await f.controller.stop();
});
test('same session string with a replaced target identity never inherits a pending grant',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');await f.controller.reconcile();const good=f.controller.snapshot().environment_check_at;
  const record=f.controller.records.get('session-main');f.controller.byTarget.delete('main');record.targetId='replacement';f.controller.byTarget.set('replacement','session-main');f.pipe.targets=[target('replacement')];f.pipe.failMethods.add('Runtime.evaluate');
  await f.controller.reconcile();assert.equal(f.controller.snapshot().environment_check_ok,false);assert.equal(f.controller.snapshot().environment_check_at,good);await f.controller.stop();
});
test('a newly confirmed session cannot inherit the old set grant while any metadata is missing',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');await f.controller.reconcile();const good=f.controller.snapshot().environment_check_at;await attach(f,'new');f.pipe.failMethods.add('Runtime.evaluate');
  await f.controller.reconcile();assert.equal(f.controller.snapshot().environment_check_ok,false);assert.equal(f.controller.snapshot().environment_check_at,good);await f.controller.stop();
});
test('unconfigured formerly verified session cannot retain a pending grant',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');await f.controller.reconcile();f.controller.records.get('session-main').configured=false;f.pipe.failMethods.add('Runtime.evaluate');
  await f.controller.reconcile();assert.equal(f.controller.snapshot().environment_check_ok,false);assert.equal(f.controller.snapshot().last_environment_diagnostic,'scope_changed');await f.controller.stop();
});
test('pending sweep schedules a real recheck within 100ms instead of the next one-second tick',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');await f.controller.reconcile();const good=f.controller.snapshot().environment_check_at;f.pipe.failMethods.add('Runtime.evaluate');
  await f.controller.reconcile();assert.equal(f.controller.snapshot().environment_check_at,good);f.pipe.failMethods.delete('Runtime.evaluate');
  const before=Date.now();while(f.controller.snapshot().environment_check_pending&&Date.now()-before<200)await new Promise(r=>setTimeout(r,5));
  assert.equal(f.controller.snapshot().environment_check_pending,false);assert.equal(f.controller.snapshot().environment_check_ok,true);assert.ok(Date.now()-before<=150);assert.notEqual(f.controller.snapshot().environment_check_at,good);await f.controller.stop();
});
test('normal controller performs real metadata sweeps at the 200ms interval and stops its timer',async()=>{
  const pipe=new FakePipe(),c=new EnvironmentController(checked('browser'),pipe);await c.start();
  pipe.emit({method:'Target.attachedToTarget',params:{sessionId:'session-main',targetInfo:target('main'),waitingForDebugger:true}});await c.flush();
  const before=c.snapshot().counts.environment_checks;await new Promise(r=>setTimeout(r,460));assert.ok(c.snapshot().counts.environment_checks>=before+2);
  await c.stop();const stopped=c.snapshot().counts.environment_checks;await new Promise(r=>setTimeout(r,260));assert.equal(c.snapshot().counts.environment_checks,stopped);
});
test('normal stop cancels a pending immediate recheck before it can read another target',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');await f.controller.reconcile();f.controller.schedulePendingCheck();await f.controller.stop();
  const calls=f.pipe.calls.filter(c=>c.method==='Target.getTargets').length;await new Promise(r=>setTimeout(r,120));assert.equal(f.pipe.calls.filter(c=>c.method==='Target.getTargets').length,calls);
});
for(const [field,value] of [['locale','zh-CN'],['language','zh-CN'],['januaryOffset',-480],['julyOffset',-480]])test('real '+field+' mismatch never uses the navigation pending grant',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');await f.controller.reconcile();const good=f.controller.snapshot().environment_check_at;f.pipe.metadata={...METADATA,[field]:value};await f.controller.reconcile();
  assert.equal(f.controller.snapshot().environment_check_ok,false);assert.equal(f.controller.snapshot().environment_check_pending,false);assert.equal(f.controller.snapshot().environment_check_at,good);assert.equal(f.pipe.closed,true);assert.ok(f.controller.snapshot().error_codes.includes('continuous_environment_mismatch'));
});

async function navigationFixture(){
  const f=await fixtureController('browser');await attach(f,'main');await f.controller.reconcile();
  f.pipe.emit({method:'Page.frameStartedLoading',sessionId:'session-main',params:{frameId:'frame-session-main'}});
  await f.controller.refreshNavigationGuard();return f;
}
test('navigation eligibility requires the main frame of a previously fully verified binding',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');
  f.controller.observeNavigation({method:'Page.frameStartedLoading',sessionId:'session-main',params:{frameId:'frame-session-main'}});assert.equal(f.controller.navigationWindow,null);
  await f.controller.reconcile();f.controller.observeNavigation({method:'Page.frameStartedLoading',sessionId:'session-main',params:{frameId:'other-frame'}});assert.equal(f.controller.navigationWindow,null);
  f.controller.observeNavigation({method:'Page.frameStartedNavigating',sessionId:'session-main',params:{frameId:'frame-session-main'}});await f.controller.refreshNavigationGuard();
  const guard=f.controller.snapshot().navigation_guard;assert.equal(guard.mode,'known_navigation_configuration');assert.equal(guard.bindings_verified,true);assert.equal(Date.parse(guard.deadline_at)-Date.parse(guard.started_at),15000);await f.controller.stop();
});
test('known navigation continuity is separately reported without renewing unavailable JS time',async()=>{
  const f=await navigationFixture();const original=new Date(Date.now()-6000).toISOString();f.controller.status.environment_check_at=original;
  f.controller.navigationWindow.firstRuntimeCheckedAt=original;f.controller.navigationWindow.startedAt=Date.now()-5900;f.controller.navigationWindow.deadlineAt=f.controller.navigationWindow.startedAt+15000;
  f.pipe.failMethods.add('Runtime.evaluate');await f.controller.reconcile();const s=f.controller.snapshot();
  assert.equal(s.environment_check_at,original);assert.equal(s.environment_check_ok,false);assert.equal(s.environment_check_pending,true);assert.equal(s.last_environment_diagnostic,'navigation_configuration_pending');assert.equal(s.navigation_guard.first_runtime_checked_at,original);assert.ok(Date.parse(s.navigation_guard.checked_at)>Date.parse(original));await f.controller.stop();
});
test('a loading window cannot extend its original deadline through redirects or old-document JS success',async()=>{
  const f=await navigationFixture();const first={...f.controller.snapshot().navigation_guard};await f.controller.reconcile();
  assert.ok(f.controller.snapshot().navigation_guard);f.controller.observeNavigation({method:'Page.frameStartedNavigating',sessionId:'session-main',params:{frameId:'frame-session-main'}});await f.controller.refreshNavigationGuard();
  assert.equal(f.controller.snapshot().navigation_guard.started_at,first.started_at);assert.equal(f.controller.snapshot().navigation_guard.deadline_at,first.deadline_at);assert.equal(f.controller.snapshot().navigation_guard.first_runtime_checked_at,first.first_runtime_checked_at);
  f.pipe.emit({method:'Page.frameStoppedLoading',sessionId:'session-main',params:{frameId:'frame-session-main'}});assert.ok(f.controller.navigationWindow);await f.controller.reconcile();assert.equal(f.controller.navigationWindow,null);assert.equal(f.controller.snapshot().navigation_guard,null);await f.controller.stop();
});
test('fifteen-second navigation deadline withdraws continuity even with fresh root replies',async()=>{
  const f=await navigationFixture();f.controller.navigationWindow.deadlineAt=Date.now()-1;assert.equal(await f.controller.refreshNavigationGuard(),false);
  assert.equal(f.controller.snapshot().navigation_guard,null);assert.equal(f.controller.snapshot().environment_check_ok,false);assert.equal(f.controller.snapshot().counts.navigation_deadline_expirations,1);
  f.controller.observeNavigation({method:'Page.frameStartedLoading',sessionId:'session-main',params:{frameId:'frame-session-main'}});assert.equal(await f.controller.refreshNavigationGuard(),false);assert.equal(f.controller.snapshot().navigation_guard,null);await f.controller.stop();
});
test('root target proof requires attached identity and rejects new targets',async()=>{
  for(const mutation of ['detached','new-target']){
    const f=await navigationFixture();if(mutation==='detached')f.pipe.targets[0].attached=false;else f.pipe.targets.push(target('unknown'));
    assert.equal(await f.controller.refreshNavigationGuard(),false);assert.equal(f.controller.snapshot().navigation_guard,null);assert.equal(f.controller.snapshot().environment_check_ok,false);await f.controller.stop();
  }
});
test('new private session or detached binding revokes navigation synchronously before queued work',async()=>{
  for(const method of ['Target.attachedToTarget','Target.detachedFromTarget']){
    const f=await navigationFixture();assert.ok(f.controller.snapshot().navigation_guard);
    const msg=method==='Target.attachedToTarget'?{method,params:{sessionId:'new-session',targetInfo:target('new')}}:{method,params:{sessionId:'session-main'}};
    f.pipe.emit(msg);assert.equal(f.controller.snapshot().navigation_guard,null);assert.equal(f.controller.snapshot().environment_check_ok,false);await f.controller.flush();await f.controller.stop();
  }
});
test('a configuration change or unavailable root response cannot renew navigation continuity',async()=>{
  for(const mutation of ['configuration','root-unavailable']){
    const f=await navigationFixture();if(mutation==='configuration')await f.controller.configure(f.controller.records.get('session-main'));else f.pipe.failMethods.add('Target.getTargets');
    assert.equal(await f.controller.refreshNavigationGuard(),false);assert.equal(f.controller.snapshot().navigation_guard,null);assert.equal(f.controller.snapshot().environment_check_ok,false);await f.controller.stop();
  }
});
test('real timezone mismatch during navigation immediately closes without a continuity exemption',async()=>{
  const f=await navigationFixture();f.pipe.metadata={...METADATA,timeZone:'Asia/Shanghai'};await f.controller.reconcile();assert.equal(f.pipe.closed,true);assert.equal(f.controller.snapshot().navigation_guard,null);assert.equal(f.controller.snapshot().environment_check_ok,false);await f.controller.stop();
});
test('pipe failure revokes navigation immediately without waiting for event queue',async()=>{
  const f=await navigationFixture();f.pipe.emit({method:'PrivatePipe.failed'});assert.equal(f.controller.snapshot().navigation_guard,null);assert.equal(f.controller.snapshot().environment_check_ok,false);await f.controller.failing;assert.equal(f.pipe.closed,true);
});
test('an unrelated worker timeout never inherits a page navigation continuity allowance',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');await attach(f,'worker','worker');await f.controller.reconcile();
  f.controller.observeNavigation({method:'Page.frameStartedLoading',sessionId:'session-main',params:{frameId:'frame-session-main'}});await f.controller.refreshNavigationGuard();
  const original=f.pipe.call.bind(f.pipe);f.pipe.call=async(method,params,session)=>{if(method==='Runtime.evaluate'&&session==='session-worker')throw Error('unrelated worker unavailable');return original(method,params,session);};
  await f.controller.reconcile();assert.equal(f.controller.snapshot().navigation_guard,null);assert.equal(f.controller.snapshot().environment_check_ok,false);await f.controller.stop();
});
test('navigation completion persists exact previous phase identity only after stop and a real full JS sweep',async()=>{
  const f=await navigationFixture(),phase={...f.controller.snapshot().navigation_guard};await f.controller.reconcile();assert.deepEqual(f.controller.snapshot().navigation_completions,[]);
  f.controller.observeNavigation({method:'Page.frameStoppedLoading',sessionId:'session-main',params:{frameId:'frame-session-main'}});assert.deepEqual(f.controller.snapshot().navigation_completions,[]);await f.controller.reconcile();
  const completed=f.controller.snapshot().navigation_completions;assert.equal(completed.length,1);assert.deepEqual(Object.keys(completed[0]).sort(),['schema','mode','started_at','deadline_at','first_runtime_checked_at','stopped_at','runtime_checked_at'].sort());
  assert.equal(completed[0].started_at,phase.started_at);assert.equal(completed[0].deadline_at,phase.deadline_at);assert.equal(completed[0].first_runtime_checked_at,phase.first_runtime_checked_at);assert.ok(Date.parse(completed[0].runtime_checked_at)>=Date.parse(completed[0].stopped_at));
  f.controller.observeNavigation({method:'Page.frameStartedLoading',sessionId:'session-main',params:{frameId:'frame-session-main'}});await f.controller.refreshNavigationGuard();assert.deepEqual(f.controller.snapshot().navigation_completions,completed);await f.controller.stop();
});
test('completion ring retains sixteen real completed windows without shifting any active deadline',async()=>{
  const f=await fixtureController('browser');await attach(f,'main');await f.controller.reconcile();
  for(let n=0;n<18;n++){f.controller.observeNavigation({method:'Page.frameStartedLoading',sessionId:'session-main',params:{frameId:'frame-session-main'}});await f.controller.refreshNavigationGuard();f.controller.observeNavigation({method:'Page.frameStoppedLoading',sessionId:'session-main',params:{frameId:'frame-session-main'}});await f.controller.reconcile();}
  assert.equal(f.controller.snapshot().navigation_completions.length,16);assert.equal(f.controller.snapshot().counts.navigation_windows_started,18);await f.controller.stop();
});
test('a sweep whose JS ran before stop cannot become post-stop completion while waiting for root proof',async()=>{
  const f=await navigationFixture(),original=f.pipe.call.bind(f.pipe);let evaluated=false,stopDuringRoot=true;
  f.pipe.call=async(method,params,session)=>{
    if(method==='Runtime.evaluate'){const result=await original(method,params,session);evaluated=true;return result;}
    if(method==='Target.getTargets'&&evaluated&&stopDuringRoot){stopDuringRoot=false;f.controller.observeNavigation({method:'Page.frameStoppedLoading',sessionId:'session-main',params:{frameId:'frame-session-main'}});}
    return original(method,params,session);
  };
  await f.controller.reconcile();assert.deepEqual(f.controller.snapshot().navigation_completions,[]);assert.ok(f.controller.navigationWindow);
  await f.controller.reconcile();assert.equal(f.controller.snapshot().navigation_completions.length,1);assert.equal(f.controller.navigationWindow,null);await f.controller.stop();
});
