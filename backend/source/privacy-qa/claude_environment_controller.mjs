/** Candidate Claude locale controller. No TCP server and no arbitrary CDP API.
 * Importing this module never launches an application. The CLI launches only an
 * independently discovered, signed executable after strict configuration checks.
 * Caller owns the network hold: keep it active until coverage is inspected.
 */
import {spawn} from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {StatusPublisher} from './status_publisher.mjs';

const BASE=path.dirname(fileURLToPath(import.meta.url));
const ROOT=path.dirname(BASE);
export const DOMAIN_ROOTS=Object.freeze(['claude.ai','claude.com','anthropic.com','claude.app','claudeusercontent.com','claudemcpcontent.com']);
const PAGE_TYPES=new Set(['page','iframe']);
const WORKER_TYPES=new Set(['worker','service_worker','shared_worker']);
const TARGET_TYPES=new Set([...PAGE_TYPES,...WORKER_TYPES]);
const LIMITS=Object.freeze([
  'Caller owns the scoped network lease and launch hold; this controller reports verified metadata and closes only its own browser on environment failure.',
  'Locale emulation and English request headers do not independently change navigator.language; verify startup/profile language separately.',
  'Workers and pre-existing/unpaused targets may have incomplete coverage. Counts are not proof of no earlier requests.',
  'No cookies, account fields, page DOM or URLs are included in the status file.'
]);
export const METADATA_EXPRESSION='JSON.stringify({timeZone:Intl.DateTimeFormat().resolvedOptions().timeZone,locale:Intl.DateTimeFormat().resolvedOptions().locale,language:navigator.language,languages:Array.from(navigator.languages),januaryOffset:new Date("2026-01-15T12:00:00Z").getTimezoneOffset(),julyOffset:new Date("2026-07-15T12:00:00Z").getTimezoneOffset()})';

// Fixed, opt-in local diagnostics. It never reads DOM content, account fields,
// cookies or storage, configures no STUN/TURN server, and requests no media.
export const QA_EXPRESSION = `(async()=>JSON.stringify(await (async()=>{
  const environment={timeZone:Intl.DateTimeFormat().resolvedOptions().timeZone,locale:Intl.DateTimeFormat().resolvedOptions().locale,language:navigator.language,languages:Array.from(navigator.languages),januaryOffset:new Date("2026-01-15T12:00:00Z").getTimezoneOffset(),julyOffset:new Date("2026-07-15T12:00:00Z").getTimezoneOffset()};
  const empty=()=>({total:0,privateIPv4:0,linkLocalIPv4:0,loopbackIPv4:0,publicIPv4:0,ulaIPv6:0,linkLocalIPv6:0,loopbackIPv6:0,globalIPv6:0,unspecifiedIPv4:0,unspecifiedIPv6:0,mdns:0,noAddress:0,otherAddress:0,host:0,srflx:0,prflx:0,relay:0,unknownType:0});
  const rtc={status:'api_unavailable',gatheringComplete:false,statsAvailable:false,events:empty(),sdp:empty(),stats:empty()};
  const add=(bucket,type,address)=>{
    bucket.total++;bucket[['host','srflx','prflx','relay'].includes(type)?type:'unknownType']++;
    if(typeof address!=='string'||!address){bucket.noAddress++;return;}
    const a=address.toLowerCase().replace(/^\\[|\\]$/g,'').split('%')[0];
    if(a.endsWith('.local')){bucket.mdns++;return;}
    const p=a.split('.').map(Number);
    if(p.length===4&&p.every(x=>Number.isInteger(x)&&x>=0&&x<=255)){
      if(p.every(x=>x===0))bucket.unspecifiedIPv4++;
      else if(p[0]===10||(p[0]===172&&p[1]>=16&&p[1]<=31)||(p[0]===192&&p[1]===168))bucket.privateIPv4++;
      else if(p[0]===169&&p[1]===254)bucket.linkLocalIPv4++;
      else if(p[0]===127)bucket.loopbackIPv4++;else bucket.publicIPv4++;return;
    }
    if(a.includes(':')){
      if(/^[0:]+$/.test(a))bucket.unspecifiedIPv6++;
      else if(/^f[cd]/.test(a))bucket.ulaIPv6++;else if(/^fe[89ab]/.test(a))bucket.linkLocalIPv6++;
      else if(a==='::1'||a==='0:0:0:0:0:0:0:1')bucket.loopbackIPv6++;else bucket.globalIPv6++;return;
    }
    bucket.otherAddress++;
  };
  const parse=(bucket,line)=>{const p=line.replace(/^a=/,'').trim().split(/\\s+/);if(p[0]?.startsWith('candidate:')&&p[6]==='typ')add(bucket,p[7],p[4]);};
  const result={mainDocumentLoaded:typeof document==='object'&&document.readyState==='complete',environment,rtc};
  if(typeof globalThis.RTCPeerConnection!=='function')return result;
  let pc,timer;const deadline=Date.now()+2500;
  const bounded=async promise=>{let t;try{return await Promise.race([promise,new Promise((_,reject)=>{t=setTimeout(()=>reject(Error('local_probe_timeout')),Math.max(1,deadline-Date.now()));})]);}finally{clearTimeout(t);}};
  try{
    pc=new RTCPeerConnection({iceServers:[],iceCandidatePoolSize:0});
    const complete=new Promise(resolve=>{
      timer=setTimeout(()=>resolve(false),2000);
      pc.onicecandidate=e=>{if(e.candidate){const c=e.candidate;if(typeof c.address==='string')add(rtc.events,c.type,c.address);else parse(rtc.events,c.candidate??'');}else resolve(true);};
      pc.onicegatheringstatechange=()=>{if(pc.iceGatheringState==='complete')resolve(true);};
    });
    pc.createDataChannel('local-privacy-check');await bounded(pc.setLocalDescription(await bounded(pc.createOffer())));
    rtc.gatheringComplete=await complete;rtc.status=rtc.gatheringComplete?'complete':'timed_out';
    for(const line of (pc.localDescription?.sdp??'').split(/\\r?\\n/))if(line.startsWith('a=candidate:'))parse(rtc.sdp,line);
    try{const stats=await bounded(pc.getStats());stats.forEach(s=>{if(s.type==='local-candidate')add(rtc.stats,s.candidateType,s.address??s.ip??'');});rtc.statsAvailable=true;}catch{}
  }catch{rtc.status='probe_failed';}finally{clearTimeout(timer);try{pc?.close();}catch{}}
  return result;
})()))()`;


// Fixed read-only loading metadata. No DOM text, element attributes, URL,
// request headers, credentials, cookies, storage, or network calls are read.
export const LOADING_RESOURCE_TYPES=Object.freeze(['script','css','img','fetch','xmlhttprequest','link','iframe','other']);
export const LOADING_STATUS_TYPES=Object.freeze(['success','redirect','clientError','serverError','unknown']);
export const LOADING_EXPRESSION=`JSON.stringify((()=>{
  const resourceCounts={script:0,css:0,img:0,fetch:0,xmlhttprequest:0,link:0,iframe:0,other:0};
  const responseStatusCounts={success:0,redirect:0,clientError:0,serverError:0,unknown:0};
  const clamp=n=>Number.isFinite(n)&&n>=0?Math.min(604800000,Math.floor(n)):null;
  const ready=typeof document==='object'?document.readyState:'unavailable';
  const out={readyState:['loading','interactive','complete'].includes(ready)?ready:'unavailable',performanceAvailable:false,documentAgeMs:null,domInteractiveMs:null,domContentLoadedMs:null,loadEventEndMs:null,resourceCounts,responseStatusCounts};
  try{
    if(typeof performance!=='object'||typeof performance.now!=='function'||typeof performance.getEntriesByType!=='function')return out;
    out.documentAgeMs=clamp(performance.now());if(out.documentAgeMs===null)return out;
    out.performanceAvailable=true;
    const nav=performance.getEntriesByType('navigation')[0];
    if(nav){out.domInteractiveMs=clamp(nav.domInteractive);out.domContentLoadedMs=clamp(nav.domContentLoadedEventEnd);out.loadEventEndMs=clamp(nav.loadEventEnd);}
    for(const entry of performance.getEntriesByType('resource').slice(0,8192)){
      const kind=['script','css','img','fetch','xmlhttprequest','link','iframe'].includes(entry.initiatorType)?entry.initiatorType:'other';
      resourceCounts[kind]++;
      const code=entry.responseStatus;
      responseStatusCounts[Number.isInteger(code)&&code>=200&&code<300?'success':Number.isInteger(code)&&code>=300&&code<400?'redirect':Number.isInteger(code)&&code>=400&&code<500?'clientError':Number.isInteger(code)&&code>=500&&code<600?'serverError':'unknown']++;
    }
  }catch{}
  return out;
})())`;
export function loadingSummary(value){
  if(!exact(value,['readyState','performanceAvailable','documentAgeMs','domInteractiveMs','domContentLoadedMs','loadEventEndMs','resourceCounts','responseStatusCounts'])||
      !['loading','interactive','complete','unavailable'].includes(value.readyState)||typeof value.performanceAvailable!=='boolean')reject('invalid_loading_result');
  for(const key of ['documentAgeMs','domInteractiveMs','domContentLoadedMs','loadEventEndMs'])if(value[key]!==null&&(!Number.isInteger(value[key])||value[key]<0||value[key]>604800000))reject('invalid_loading_result');
  for(const [name,keys] of [['resourceCounts',LOADING_RESOURCE_TYPES],['responseStatusCounts',LOADING_STATUS_TYPES]])
    if(!exact(value[name],keys)||keys.some(key=>!Number.isInteger(value[name][key])||value[name][key]<0||value[name][key]>8192))reject('invalid_loading_result');
  const resources=Object.values(value.resourceCounts).reduce((a,b)=>a+b,0),statuses=Object.values(value.responseStatusCounts).reduce((a,b)=>a+b,0);
  if(resources>8192||resources!==statuses||(!value.performanceAvailable&&
    (resources!==0||['documentAgeMs','domInteractiveMs','domContentLoadedMs','loadEventEndMs'].some(k=>value[k]!==null)))||
    (value.performanceAvailable&&value.documentAgeMs===null))reject('invalid_loading_result');
  return JSON.parse(JSON.stringify(value));
}

// Fixed availability-only observation; no DOM text, account, storage, URL or
// origin string leaves the renderer. It is never used as native-policy proof.
export const NATIVE_LOADING_EXPRESSION=`JSON.stringify((()=>{
  const load=JSON.parse(${LOADING_EXPRESSION});
  let isErrorDocument=null,securityOriginMatchesProtected=null,protectedHttpsDocument=null;
  try{
    const uri=typeof document==='object'?document.documentURI:'',u=new URL(location.href),roots=${JSON.stringify(DOMAIN_ROOTS)};
    const protectedHost=roots.some(root=>u.hostname===root||u.hostname.endsWith('.'+root));
    isErrorDocument=/^(?:chrome-error|edge-error):/i.test(uri)||/^(?:chrome-error|edge-error):/i.test(u.protocol);
    protectedHttpsDocument=u.protocol==='https:'&&u.port===''&&protectedHost;
    securityOriginMatchesProtected=protectedHttpsDocument&&globalThis.origin===u.origin;
  }catch{}
  return {...load,isErrorDocument,securityOriginMatchesProtected,protectedHttpsDocument};
})())`;

export const RTC_COUNT_KEYS=Object.freeze(['total','privateIPv4','linkLocalIPv4','loopbackIPv4','publicIPv4','ulaIPv6','linkLocalIPv6','loopbackIPv6','globalIPv6','unspecifiedIPv4','unspecifiedIPv6','mdns','noAddress','otherAddress','host','srflx','prflx','relay','unknownType']);
const RAW_RTC_KEYS=Object.freeze(['privateIPv4','linkLocalIPv4','loopbackIPv4','publicIPv4','ulaIPv6','linkLocalIPv6','loopbackIPv6','globalIPv6','otherAddress']);
const QA_STATUSES=new Set(['api_unavailable','complete','timed_out','probe_failed']);

function protectedSecurityOrigin(value,domains){
  try{const u=new URL(value);return u.protocol==='https:'&&!u.port&&!u.username&&!u.password&&u.pathname==='/'&&!u.search&&!u.hash&&domains.some(root=>u.hostname.toLowerCase().replace(/\.$/,'')===root||u.hostname.toLowerCase().replace(/\.$/,'').endsWith('.'+root));}catch{return false;}
}
export function documentHealthFromFrameTree(value,domains){
  const frame=value?.frameTree?.frame;
  if(!plain(frame)||typeof frame.url!=='string'||typeof frame.securityOrigin!=='string')return{isErrorDocument:null,securityOriginMatchesProtected:null,protectedHttpsDocument:null,unreachableDocument:null};
  const unreachable=typeof frame.unreachableUrl==='string'&&frame.unreachableUrl.length>0;
  let httpsDocument=false;try{const u=new URL(frame.url);httpsDocument=u.protocol==='https:'&&!u.port&&protectedUrl(frame.url,domains);}catch{}
  return{isErrorDocument:unreachable||/^(?:chrome-error|edge-error):/i.test(frame.url)||/^(?:chrome-error|edge-error):/i.test(frame.securityOrigin),securityOriginMatchesProtected:protectedSecurityOrigin(frame.securityOrigin,domains),protectedHttpsDocument:httpsDocument,unreachableDocument:unreachable};
}
function rtcSummary(value){
  if(!exact(value,['status','gatheringComplete','statsAvailable','events','sdp','stats'])||!QA_STATUSES.has(value.status)||typeof value.gatheringComplete!=='boolean'||typeof value.statsAvailable!=='boolean')reject('invalid_qa_result');
  const out={status:value.status,gatheringComplete:value.gatheringComplete,statsAvailable:value.statsAvailable};
  for(const source of ['events','sdp','stats']){
    if(!exact(value[source],RTC_COUNT_KEYS)||RTC_COUNT_KEYS.some(k=>!Number.isInteger(value[source][k])||value[source][k]<0||value[source][k]>2048))reject('invalid_qa_result');
    out[source]=Object.fromEntries(RTC_COUNT_KEYS.map(k=>[k,value[source][k]]));
  }
  return out;
}


class SafeError extends Error { constructor(code){super(code);this.code=code;} }
const reject=code=>{throw new SafeError(code);};
const plain=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const exact=(obj,keys)=>plain(obj)&&Object.keys(obj).length===keys.length&&keys.every(key=>Object.hasOwn(obj,key));
const norm=value=>path.win32.normalize(value).toLowerCase();
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));

export function parseJsonStrict(text){
  if(typeof text!=='string'||Buffer.byteLength(text)>32768)reject('configuration_too_large');
  const source=text.replace(/^\uFEFF/,'');
  let parsed;try{parsed=JSON.parse(source);}catch{reject('invalid_configuration_json');}
  // JSON.parse accepts duplicate keys. Walk validated JSON solely to reject them.
  let i=0;const ws=()=>{while(/\s/.test(source[i]??'')&&i<source.length)i++;};
  const string=()=>{const start=i++;while(i<source.length){if(source[i]==='\\'){i+=2;continue;}if(source[i++]==='"')return JSON.parse(source.slice(start,i));}reject('invalid_configuration_json');};
  const value=()=>{ws();if(source[i]==='{'){i++;ws();const seen=new Set();while(source[i]!=='}'){const key=string();if(seen.has(key))reject('duplicate_configuration_key');seen.add(key);ws();i++;value();ws();if(source[i]===','){i++;ws();}else break;}i++;}else if(source[i]==='['){i++;ws();while(source[i]!==']'){value();ws();if(source[i]===','){i++;ws();}else break;}i++;}else if(source[i]==='"')string();else while(i<source.length&&!/[\s,\]}]/.test(source[i]))i++;};
  value();return parsed;
}

function validatedDomain(value){
  if(typeof value!=='string'||!DOMAIN_ROOTS.includes(value))reject('unauthorized_domain');
  return value;
}
export function protectedUrl(value,domains){
  if(value==='about:blank')return true;
  try{let url=new URL(value);if(url.protocol==='blob:')url=new URL(url.pathname);if(url.protocol!=='https:'||url.username||url.password)return false;const host=url.hostname.toLowerCase().replace(/\.$/,'');return domains.some(root=>host===root||host.endsWith('.'+root));}catch{return false;}
}

export function validateConfig(input,authorizedExecutables,root=ROOT){
  const nativeMode=input?.verification_mode==='native_process_policy_v1';
  if(!exact(input,['schema_version','kind','exe','args','domains','timezone','locale',...(Object.hasOwn(input??{},'verification_mode')?['verification_mode']:[])]))reject('invalid_configuration_schema');
  if(Object.hasOwn(input,'verification_mode')&&(!nativeMode||input.kind!=='browser'))reject('unsupported_verification_mode');
  if(input.schema_version!==1||!['electron','browser'].includes(input.kind))reject('unsupported_configuration');
  if(input.timezone!=='America/New_York'||input.locale!=='en_US')reject('unauthorized_locale');
  if(typeof input.exe!=='string'||!path.win32.isAbsolute(input.exe)||input.exe.includes('\0'))reject('invalid_executable');
  if(!Array.isArray(authorizedExecutables)||!authorizedExecutables.some(item=>item.kind===input.kind&&norm(item.exe)===norm(input.exe)))reject('unauthorized_executable');
  if(!Array.isArray(input.domains)||!input.domains.length||new Set(input.domains).size!==input.domains.length)reject('invalid_domain_list');
  input.domains.forEach(validatedDomain);
  if(!Array.isArray(input.args)||input.args.length>32||input.args.some(arg=>typeof arg!=='string'||arg.length>2048||/[\0\r\n]/.test(arg)))reject('invalid_arguments');
  const seen=new Set();let profile=null;let proxy=false;let bypass=false;let quic=false;let englishLanguage=false;let englishAccept=false;let resolver=false;let forcedRtc=false;let startPages=0;
  const standalone=new Set(['--disable-quic','--disable-background-networking','--no-first-run','--no-default-browser-check','--disable-sync','--disable-extensions','--disable-component-update','--disable-default-apps','--noerrdialogs']);
  for(const arg of input.args){
    if(!arg.startsWith('--')){startPages++;if(nativeMode&&arg!=='about:blank')reject('native_policy_requires_blank_start');if(arg!=='about:blank'){let url;try{url=new URL(arg);}catch{reject('unauthorized_start_url');}if(!protectedUrl(arg,input.domains)||url.search||url.hash)reject('unauthorized_start_url');}continue;}
    const equals=arg.indexOf('=');const key=equals<0?arg:arg.slice(0,equals);const value=equals<0?'':arg.slice(equals+1);
    if(key!==key.toLowerCase()||seen.has(key))reject('duplicate_or_noncanonical_argument');seen.add(key);
    if(standalone.has(arg)){if(arg==='--disable-quic')quic=true;continue;}
    if(nativeMode&&arg==='--edge-skip-compat-layer-relaunch')continue;
    if(key==='--proxy-server'){if(!/^http:\/\/127\.0\.0\.1:(\d{1,5})$/.test(value))reject('unauthorized_proxy');const port=Number(value.slice(value.lastIndexOf(':')+1));if(port<1||port>65535)reject('unauthorized_proxy');proxy=true;continue;}
    if(key==='--proxy-bypass-list'&&value==='<-loopback>'){bypass=true;continue;}
    if(key==='--host-resolver-rules'&&value==='MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'){resolver=true;continue;}
    if(key==='--force-webrtc-ip-handling-policy'&&value==='disable_non_proxied_udp'&&nativeMode){forcedRtc=true;continue;}
    if(key==='--webrtc-ip-handling-policy'&&value==='disable_non_proxied_udp'&&!nativeMode)continue;
    if(key==='--headless'&&value==='new')continue;
    if(key==='--lang'&&value==='en-US'){englishLanguage=true;continue;}
    if(key==='--accept-lang'&&value==='en-US,en'){englishAccept=true;continue;}
    if(key==='--user-data-dir'&&input.kind==='browser'){
      const allowedBases=[path.win32.join(root,'browser-profiles'),path.win32.join(root,'privacy-qa','runs')];
      if(!path.win32.isAbsolute(value)||!allowedBases.some(base=>norm(value).startsWith(norm(base)+'\\'))||value.includes('..'))reject('browser_profile_not_isolated');
      profile=value;continue;
    }
    // Includes remote-debugging-port, inspect, no-sandbox, load-extension and
    // caller-supplied remote-debugging-pipe. The controller adds the only pipe.
    reject('unauthorized_argument');
  }
  if(!proxy||!bypass||!quic)reject('required_network_arguments_missing');
  if(input.kind==='browser'&&!profile)reject('browser_profile_not_isolated');
  if(input.kind==='browser'&&(!englishLanguage||!englishAccept))reject('required_browser_language_arguments_missing');
  if(nativeMode&&(!resolver||!forcedRtc||startPages!==1))reject('required_native_policy_arguments_missing');
  return {...input,args:[...input.args],domains:[...input.domains],profile};
}

export function validateProtocolCall(method,params={},sessionId){
  const session=typeof sessionId==='string'&&sessionId.length>0&&sessionId.length<256;
  if(['Browser.getVersion','Browser.close','Target.getTargets'].includes(method)){if(sessionId!==undefined||!exact(params,[]))reject('unauthorized_protocol_parameters');return;}
  if(method==='Target.setDiscoverTargets'){if(sessionId!==undefined||!exact(params,['discover'])||params.discover!==true)reject('unauthorized_protocol_parameters');return;}
  if(method==='Target.setAutoAttach'){if(!exact(params,['autoAttach','waitForDebuggerOnStart','flatten'])||params.autoAttach!==true||params.waitForDebuggerOnStart!==true||params.flatten!==true)reject('unauthorized_protocol_parameters');return;}
  if(method==='Target.attachToTarget'){if(sessionId!==undefined||!exact(params,['targetId','flatten'])||typeof params.targetId!=='string'||params.targetId.length>256||params.flatten!==true)reject('unauthorized_protocol_parameters');return;}
  if(method==='Target.detachFromTarget'){if(sessionId!==undefined||!exact(params,['sessionId'])||typeof params.sessionId!=='string'||!params.sessionId||params.sessionId.length>256)reject('unauthorized_protocol_parameters');return;}
  if(!session)reject('target_session_required');
  if(method==='Emulation.setTimezoneOverride'){if(!exact(params,['timezoneId'])||!['America/New_York',''].includes(params.timezoneId))reject('unauthorized_protocol_parameters');return;}
  if(method==='Emulation.setLocaleOverride'){if(!exact(params,['locale'])||!['en_US',''].includes(params.locale))reject('unauthorized_protocol_parameters');return;}
  if(method==='Network.setExtraHTTPHeaders'){if(!exact(params,['headers'])||!plain(params.headers)||!(exact(params.headers,[])||(exact(params.headers,['Accept-Language'])&&params.headers['Accept-Language']==='en-US,en;q=0.9')))reject('unauthorized_protocol_parameters');return;}
  if(method==='Page.navigate'){if(!exact(params,['url'])||params.url!=='https://claude.ai/')reject('unauthorized_protocol_parameters');return;}
  if(method==='Page.reload'){if(!exact(params,['ignoreCache'])||params.ignoreCache!==false)reject('unauthorized_protocol_parameters');return;}
  if(['Page.enable','Page.getFrameTree'].includes(method)){if(!exact(params,[]))reject('unauthorized_protocol_parameters');return;}
  if(method==='Runtime.runIfWaitingForDebugger'){if(!exact(params,[]))reject('unauthorized_protocol_parameters');return;}
  if(method==='Runtime.evaluate'){
    const metadata=exact(params,['expression','returnByValue','silent','includeCommandLineAPI'])&&params.expression===METADATA_EXPRESSION;
    const qa=exact(params,['expression','returnByValue','silent','includeCommandLineAPI','awaitPromise'])&&params.expression===QA_EXPRESSION&&params.awaitPromise===true;
    const loading=exact(params,['expression','returnByValue','silent','includeCommandLineAPI'])&&params.expression===LOADING_EXPRESSION;
    const nativeLoading=exact(params,['expression','returnByValue','silent','includeCommandLineAPI'])&&params.expression===NATIVE_LOADING_EXPRESSION;
    if(!(metadata||qa||loading||nativeLoading)||params.returnByValue!==true||params.silent!==true||params.includeCommandLineAPI!==false)reject('unauthorized_metadata_expression');return;
  }
  reject('unauthorized_protocol_method');
}

export class PrivatePipeTransport {
  constructor(child){
    this.child=child;this.pending=new Map();this.handlers=new Set();this.sequence=0;this.buffer='';this.closed=false;
    child.stdio[4].setEncoding('utf8');child.stdio[4].on('data',chunk=>this.receive(chunk));
    child.once('exit',()=>this.failAll('child_exited'));child.once('error',()=>this.failAll('child_start_failed'));
    child.stdio[3].on('error',()=>this.failAll('private_pipe_failed'));
    child.stdio[4].on('error',()=>this.failAll('private_pipe_failed'));
  }
  receive(chunk){
    this.buffer+=chunk;if(Buffer.byteLength(this.buffer)>2*1024*1024){this.failAll('protocol_buffer_limit');this.close();return;}
    let end;while((end=this.buffer.indexOf('\0'))>=0){const raw=this.buffer.slice(0,end);this.buffer=this.buffer.slice(end+1);if(!raw)continue;let msg;try{msg=JSON.parse(raw);}catch{this.failAll('invalid_protocol_message');continue;}
      if(this.pending.has(msg.id)){const pending=this.pending.get(msg.id);this.pending.delete(msg.id);clearTimeout(pending.timer);if(msg.error){const codes={'Timezone override is already in effect':'cdp_timezone_override_in_effect','Another locale override is already in effect':'cdp_locale_override_in_effect','Command can only be executed on top-level targets':'cdp_top_level_only'};pending.reject(new SafeError(Object.hasOwn(codes,msg.error.message)?codes[msg.error.message]:'cdp_command_rejected'));}else pending.resolve(msg.result??{});}
      else if(typeof msg.method==='string')for(const handler of this.handlers)Promise.resolve(handler(msg)).catch(()=>{});
    }
  }
  call(method,params={},sessionId,timeout=8000){
    validateProtocolCall(method,params,sessionId);if(this.closed)return Promise.reject(new SafeError('private_pipe_closed'));
    return new Promise((resolve,rejectPromise)=>{const id=++this.sequence;const timer=setTimeout(()=>{this.pending.delete(id);rejectPromise(new SafeError('cdp_command_timeout'));},timeout);this.pending.set(id,{resolve,reject:rejectPromise,timer});
      this.child.stdio[3].write(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})})+'\0',error=>{if(error&&this.pending.has(id)){clearTimeout(timer);this.pending.delete(id);rejectPromise(new SafeError('private_pipe_write_failed'));}});
    });
  }
  on(handler){this.handlers.add(handler);return()=>this.handlers.delete(handler);}
  failAll(code){for(const pending of this.pending.values()){clearTimeout(pending.timer);pending.reject(new SafeError(code));}this.pending.clear();if(!this.closed)for(const handler of this.handlers)Promise.resolve(handler({method:'PrivatePipe.failed'})).catch(()=>{});}
  close(){if(this.closed)return;this.closed=true;this.failAll('private_pipe_closed');this.child.stdio[3].end();this.child.stdio[4].destroy();}
}

// Fixed queue error categories only: no exception text, stack, target URL or protocol payload.
export function queueFailureDiagnostic(error, source) {
  const stages=new Set(['reconcile','pending_reconcile','attach','detach','target_info','other']);
  const known=new Set(['cdp_command_timeout','cdp_command_rejected','cdp_timezone_override_in_effect','cdp_locale_override_in_effect','cdp_top_level_only','private_pipe_closed','private_pipe_write_failed','private_pipe_failed','child_exited','child_start_failed','protocol_buffer_limit','invalid_protocol_message','unauthorized_protocol_method','unauthorized_protocol_parameters','unauthorized_metadata_expression']);
  const publisher=new Set(['publisher_runtime_unavailable','publisher_closed','publisher_runtime_invalid','publisher_start_timeout','publisher_pipe_failed','publisher_start_failed','publisher_exited','publisher_response_limit','publisher_response_invalid','publisher_identity_invalid','publisher_write_failed','publisher_ack_invalid','publisher_frame_limit','publisher_ack_timeout']);
  let reason='other';
  try {
    if(typeof error?.code==='string'&&known.has(error.code))reason=error.code;
    else if(typeof error?.message==='string'&&publisher.has(error.message))reason=error.message;
    else if(error?.name==='TypeError')reason='logic_type_error';
    else if(error?.name==='RangeError')reason='logic_range_error';
  } catch {}
  return 'queue_'+(typeof source==='string'&&stages.has(source)?source:'other')+'_'+reason;
}
function queueEventSource(msg) {
  return ({'Target.attachedToTarget':'attach','Target.detachedFromTarget':'detach','Target.targetInfoChanged':'target_info'})[msg?.method]??'other';
}

export const STARTUP_NAVIGATION_CODES=Object.freeze(['ok','invalid_result','download_disallowed','net_proxy_connection_failed','net_tunnel_connection_failed','net_network_changed','net_connection_reset','net_connection_closed','net_connection_timed_out','net_timed_out','net_name_not_resolved','net_aborted','net_tls_or_certificate_error','net_access_denied','net_blocked','net_other_error']);
export function startupNavigationCode(result){
  try{
    if(!plain(result))return 'invalid_result';
    if(result.isDownload===true)return 'download_disallowed';
    const text=result.errorText;
    if(text===undefined||text==='')return 'ok';
    if(typeof text!=='string')return 'invalid_result';
    const mapping={'net::ERR_PROXY_CONNECTION_FAILED':'net_proxy_connection_failed','net::ERR_TUNNEL_CONNECTION_FAILED':'net_tunnel_connection_failed','net::ERR_NETWORK_CHANGED':'net_network_changed','net::ERR_CONNECTION_RESET':'net_connection_reset','net::ERR_CONNECTION_CLOSED':'net_connection_closed','net::ERR_CONNECTION_TIMED_OUT':'net_connection_timed_out','net::ERR_TIMED_OUT':'net_timed_out','net::ERR_NAME_NOT_RESOLVED':'net_name_not_resolved','net::ERR_ABORTED':'net_aborted','net::ERR_ACCESS_DENIED':'net_access_denied','net::ERR_BLOCKED_BY_CLIENT':'net_blocked','net::ERR_BLOCKED_BY_ADMINISTRATOR':'net_blocked'};
    if(Object.hasOwn(mapping,text))return mapping[text];
    if(text.startsWith('net::ERR_SSL_')||text.startsWith('net::ERR_CERT_')||text==='net::ERR_ECH_FALLBACK_CERTIFICATE_INVALID')return 'net_tls_or_certificate_error';
    return 'net_other_error';
  }catch{return 'invalid_result';}
}

export const ACTIVATION_STAGES=Object.freeze(['candidates','classify_url','before_document','navigation_command','document_observation','metadata_check','environment_check','complete']);
export const ACTIVATION_CODES=Object.freeze(['started','skipped_url','no_candidates','ok','cdp_command_timeout','cdp_command_rejected','private_pipe_closed','private_pipe_write_failed','identity_changed','budget_expired','document_not_accepted','metadata_not_verified','environment_not_verified','other_error']);
export const ACTIVATION_URL_CLASSES=Object.freeze(['blank','protected_https','unprotected_web','local','other','unavailable']);
export function activationUrlClass(value,domains=DOMAIN_ROOTS){
  if(typeof value!=='string')return 'unavailable';
  if(value==='about:blank')return 'blank';
  try{const u=new URL(value);if(u.protocol==='https:'&&protectedUrl(value,domains))return 'protected_https';if(['http:','https:'].includes(u.protocol))return 'unprotected_web';if(['file:','devtools:','chrome:','chrome-extension:','edge:'].includes(u.protocol))return 'local';return 'other';}catch{return 'other';}
}
function activationErrorCode(error){
  try{const mapping={cdp_command_timeout:'cdp_command_timeout',cdp_command_rejected:'cdp_command_rejected',private_pipe_closed:'private_pipe_closed',private_pipe_write_failed:'private_pipe_write_failed',activation_identity_changed:'identity_changed',activation_budget_expired:'budget_expired',activation_metadata_not_confirmed:'metadata_not_verified',activation_environment_not_confirmed:'environment_not_verified'};const code=error?.code;return typeof code==='string'&&Object.hasOwn(mapping,code)?mapping[code]:'other_error';}catch{return 'other_error';}
}

export const TARGET_TYPE_LABELS=Object.freeze(['page','iframe','worker','service_worker','shared_worker','other','tab','browser','unknown']);
export const TARGET_TYPE_EVENTS=Object.freeze(['type_change_seen','inventory_mismatch','promotion_started','promotion_verified','type_refused','stale_result_discarded','retired']);
export const TARGET_TYPE_SOURCES=Object.freeze(['target_info_event','reconcile','sweep','configuration','metadata']);
const targetTypeLabel=value=>TARGET_TYPE_LABELS.includes(value)?value:'unknown';
export const TARGET_LIFECYCLE_EVENTS=Object.freeze(['operation_failed','retirement_verified','retirement_refused','resume_verified']);
export const TARGET_LIFECYCLE_SOURCES=Object.freeze(['setup','resume','metadata','alias']);
export const TARGET_LIFECYCLE_REASONS=Object.freeze(['none','target_present','identity_changed','inventory_unavailable','inventory_invalid','cdp_command_timeout','cdp_command_rejected','private_pipe_closed','private_pipe_write_failed','other_error']);

export class EnvironmentController {
  constructor(config,transport,writeStatus=async()=>{}){
    this.config=config;this.transport=transport;this.writeStatus=writeStatus;this.records=new Map();this.byTarget=new Map();this.tasks=new Set();this.errors=new Set();this.stopped=false;this.timer=null;this.environmentCheck=null;this.failing=null;this.eventTail=Promise.resolve();this.verifiedSessions=new Map();this.pendingRecheckTimer=null;this.configurationGeneration=0;this.navigationWindow=null;this.navigationTimer=null;this.navigationRefresh=null;this.observationSequence=0;
    this.status={schema_version:1,kind:config.kind,process_pid:null,version:null,status:'starting',activation_attempted:false,activation_complete:false,protected_environment_verified:false,network_hold_managed_by_caller:true,environment_check_at:null,environment_check_ok:false,environment_check_pending:false,navigation_guard:null,last_environment_diagnostic:'not_checked',counts:{attached:0,covered_pages:0,covered_iframes:0,metadata_matches:0,metadata_mismatches:0,workers_inherited_verified:0,workers_unverified:0,unprotected_targets:0,unknown_target_types:0,early_unpaused_targets:0,navigation_scope_resets:0,command_errors:0,environment_checks:0,environment_check_failures:0,environment_pending_checks:0,retired_before_metadata:0,navigation_windows_started:0,navigation_proofs:0,navigation_invalidations:0,navigation_deadline_expirations:0},limits:LIMITS};
    this.status.environment_scope=config.kind==='browser'?'isolated-browser-all-web-targets-v1':'electron-targets-v1';
    this.status.profile_scope=config.kind==='browser'&&typeof config.profile==='string'&&norm(config.profile)===norm(path.join(ROOT,'browser-profiles','edge-claude'))?'claude-persistent':'qa-isolated';
    this.status.navigation_completions=[];this.documentHealthDeadlineMs=8000;this.activationBudgetMs=22000;
    this.topologySalt=randomUUID();this.topologyStarted=performance.now();this.topologySequence=0;this.topologyEvents=[];this.topologyExpiresAt=0;
    this.workerRuntimeChecks=new Map();this.workerRuntimeSequence=0;
    this.processedAttachments=new Map();this.unpausedAttachments=new Map();this.retiredUnpaused=new Map();this.unpausedRetirementProof=null;this.status.counts.unpaused_retired_verified=0;this.status.counts.retired_attachment_duplicates_ignored=0;
    this.browserAutoattachPending=new Map();this.browserWaitingSessions=new Map();this.browserResumedSessions=new Map();this.browserAliasSessions=new Map();this.browserObservedAliases=new Map();this.browserDetachedSessions=new Set();this.browserCanonicalRebindings=new Map();this.browserCanonicalRecoveryPending=new Map();this.reconcileQueued=false;this.verifiedScopeNavigationProof=null;this.scopeSuspension=null;this.rootInventoryHeartbeat=null;this.suspensionTimer=null;this.suspensionRefresh=null;
  }
  topologyEvent(event,{info=null,sessionId=null,paused=null,source='none',detail='none'}={}){
    const types=new Set(['page','iframe','worker','service_worker','shared_worker','browser','tab']);
    const hash=value=>typeof value==='string'&&value.length>0&&value.length<=256?createHash('sha256').update(this.topologySalt+'\0'+value).digest('hex').slice(0,16):null;
    const targetId=info?.targetId,existing=typeof targetId==='string'?this.byTarget.get(targetId):undefined;
    const item={seq:++this.topologySequence,elapsed_ms:Math.max(0,Math.min(86400000,Math.floor(performance.now()-this.topologyStarted))),event,type:types.has(info?.type)?info.type:'other',target_hash:hash(targetId),session_hash:hash(sessionId),paused:typeof paused==='boolean'?paused:null,source,detail,duplicate_target:typeof existing==='string'&&existing!==sessionId};
    // Preserve the first 32 startup events and the latest 32 events, bounded.
    if(this.topologyEvents.length===64)this.topologyEvents.splice(32,1);
    this.topologyEvents.push(item);
  }
  enableTopologyDiagnostics(){
    this.topologyExpiresAt=Date.now()+60000;
    this.topologyEvent('diagnostic_enabled');
  }
  topologySnapshot(){
    const now=Date.now();
    if(!this.topologyExpiresAt||now>this.topologyExpiresAt)return null;
    return {schema:1,scope:'bounded-target-topology-v1',checked_at:new Date(now).toISOString(),expires_at:new Date(this.topologyExpiresAt).toISOString(),events:this.topologyEvents.map(e=>({...e}))};
  }
  snapshot(){const suspension=this.suspensionSnapshot(),topology=this.topologySnapshot(),workerProof=this.workerEvidenceForNavigation(),retirementProof=this.retirementEvidenceForNavigation(),scopeProof=this.verifiedScopeEvidenceForNavigation();const value={...(suspension?{suspension_guard:suspension}:{}),...(topology?{topology_diagnostic:topology}:{}),...(workerProof?{worker_navigation_evidence:workerProof}:{}),...(retirementProof?{unpaused_retirement_evidence:retirementProof}:{}),...(scopeProof?{verified_scope_navigation_evidence:scopeProof}:{}),...this.status,configuration_generation:this.configurationGeneration,status:this.errors.size&&this.status.status==='monitoring'?'partial':this.status.status,at:new Date().toISOString(),counts:{...this.status.counts},error_codes:[...this.errors].sort()};return this.config.kind==='browser'?this.boundedBrowserDiagnostics(value):value;}
  boundedBrowserDiagnostics(value){
    // Diagnostic detail must not exhaust the private publisher's 32768-byte
    // frame. Reserve its envelope; never remove admission facts or proofs.
    const bytes=()=>Buffer.byteLength(JSON.stringify({id:9007199254740991,status:value})+'\n','utf8');
    if(bytes()<=32000)return value;
    for(const key of ['topology_diagnostic','target_type_diagnostic','activation_diagnostic','target_lifecycle_diagnostic','autoattach_pending_diagnostic']){
      if(!plain(value[key])||!Array.isArray(value[key].events))continue;
      value[key]={...value[key],events:[...value[key].events]};
      while(bytes()>32000&&value[key].events.length>1)value[key].events.shift();
      if(bytes()<=32000)return value;
    }
    // Whole optional diagnostics may be omitted; partial QA/page records must
    // never be presented with their original accepted=true decision.
    for(const key of ['topology_diagnostic','target_type_diagnostic','qa_diagnostic','loading_diagnostic','document_health','activation_navigation_diagnostic','activation_diagnostic','target_lifecycle_diagnostic','autoattach_pending_diagnostic']){
      delete value[key];if(bytes()<=32000)return value;
    }
    // An oversized mandatory status remains an ordinary publisher failure.
    // No lease, navigation evidence, counts or timestamps are pruned to fit.
    return value;
  }
  scopeSuspensionHealthy(){
    return this.config.kind==='browser'&&!this.stopped&&this.status.activation_complete===true&&
      [...this.errors].every(code=>code==='early_unpaused_target')&&
      ['metadata_mismatches','command_errors','workers_unverified','unprotected_targets','unknown_target_types','environment_check_failures'].every(key=>this.status.counts[key]===0);
  }
  beginScopeSuspension(){
    if(this.scopeSuspension||!this.scopeSuspensionHealthy()||!this.verifiedSessions.size)return;
    const baseline=Date.parse(this.status.environment_check_at),now=Date.now();
    if(!Number.isFinite(baseline)||baseline>now)return;
    this.scopeSuspension=Object.freeze({startedAt:now,deadlineAt:now+30000,firstRuntimeCheckedAt:this.status.environment_check_at,monotonicDeadline:performance.now()+30000});
  }
  clearScopeSuspension(){this.scopeSuspension=null;}
  suspensionSnapshot(){
    const phase=this.scopeSuspension,heartbeat=this.rootInventoryHeartbeat,now=Date.now();
    if(!phase||!heartbeat||!this.scopeSuspensionHealthy()||this.status.environment_check_pending!==true||
      this.status.environment_check_ok!==false||this.status.navigation_guard!==null||
      now<phase.startedAt||now>=phase.deadlineAt||performance.now()>=phase.monotonicDeadline||
      !['scope_changed','configuration_changed','navigation_configuration_pending','navigation_deadline_expired','metadata_unavailable'].includes(this.status.last_environment_diagnostic)||
      !Number.isSafeInteger(this.configurationGeneration)||heartbeat.generation>this.configurationGeneration||
      now<heartbeat.checkedAt||now-heartbeat.checkedAt>=4000)return null;
    return {schema:1,mode:'zero_byte_scope_transition',started_at:new Date(phase.startedAt).toISOString(),
      checked_at:new Date(heartbeat.checkedAt).toISOString(),deadline_at:new Date(phase.deadlineAt).toISOString(),
      first_runtime_checked_at:phase.firstRuntimeCheckedAt,configuration_generation:heartbeat.generation,
      inventory_complete:true,inventory_fingerprint:heartbeat.fingerprint,target_count:heartbeat.targetCount};
  }
  async rootInventory(timeout){
    const startedAt=Date.now(),startedMono=performance.now(),generation=this.configurationGeneration;
    let result;
    try{result=await this.transport.call('Target.getTargets',{},undefined,timeout??(this.config.kind==='browser'?1000:8000));}
    catch(error){
      if(this.config.kind==='browser'&&['cdp_command_timeout','cdp_command_rejected'].includes(error?.code)){
        // An unsuccessful read cannot renew root liveness or runtime evidence.
        // Pause application bytes and retain only the original cached heartbeat.
        this.invalidateNavigation('scope_changed');this.schedulePendingCheck();this.publishImmediate();
        reject('root_inventory_temporarily_unavailable');
      }
      throw error;
    }
    if(this.config.kind==='browser'){
      let infos;
      try{infos=this.browserInventoryInfos(result);}catch(error){this.error('target_type_inventory_invalid');throw error;}
      const now=Date.now(),elapsed=performance.now()-startedMono;
      if(!(elapsed>=0&&elapsed<1000&&startedAt<=now&&now-startedAt<1000)){
        this.invalidateNavigation('scope_changed');this.schedulePendingCheck();this.publishImmediate();reject('root_inventory_temporarily_unavailable');
      }
      if(infos.length>0){
        const bindings=infos.map(info=>[info.targetId,info.type,info.attached===true]).sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
        this.rootInventoryHeartbeat={checkedAt:startedAt,generation,targetCount:infos.length,
          fingerprint:createHash('sha256').update(this.topologySalt+'\0zero-byte-inventory-v1\0'+JSON.stringify(bindings)).digest('hex')};
      }
    }
    return result;
  }
  async refreshScopeSuspensionHeartbeat(){
    if(!this.scopeSuspension||this.stopped||this.suspensionRefresh)return;
    const phase=this.scopeSuspension;
    this.suspensionRefresh=(async()=>{
      try{await this.rootInventory();}
      catch(error){
        // A failed read provides no new heartbeat. Keep only the previous real
        // bounded snapshot; malformed inventory and private-pipe loss are hard failures.
        if(['target_type_inventory_invalid','private_pipe_closed','private_pipe_write_failed'].includes(error?.code))this.error(error.code);
      }
      if(!this.stopped&&this.scopeSuspension===phase)await this.publish();
    })();
    try{return await this.suspensionRefresh;}finally{this.suspensionRefresh=null;}
  }
  async publish(){await this.writeStatus(this.snapshot());}
  error(code){this.errors.add(code);this.status.counts.command_errors++;this.status.status='partial';this.status.environment_check_ok=false;if(this.config.kind==='browser')void this.failClosed(code);}
  queue(action,source='other'){const task=this.eventTail.then(action).catch(async(error)=>{this.errors.add(queueFailureDiagnostic(error,source));this.error('controller_event_failed');if(this.failing)await this.failing;}).finally(()=>this.tasks.delete(task));this.eventTail=task;this.tasks.add(task);return task;}
  queueReconcile(source='reconcile'){
    if(this.stopped||this.reconcileQueued||this.reconciling)return;
    this.reconcileQueued=true;
    return this.queue(async()=>{this.reconcileQueued=false;await this.reconcile();},source);
  }
  async flush(){while(this.tasks.size)await Promise.allSettled([...this.tasks]);await this.publish();}
  async start({monitor=true}={}){
    this.stopEvents=this.transport.on(msg=>{this.observeNavigation(msg);return this.queue(()=>this.event(msg),queueEventSource(msg));});
    const version=await this.transport.call('Browser.getVersion');if(typeof version.product==='string'&&/^[A-Za-z][A-Za-z ]*\/[0-9.]+$/.test(version.product))this.status.version=version.product;
    await this.transport.call('Target.setAutoAttach',{autoAttach:true,waitForDebuggerOnStart:true,flatten:true});
    await this.transport.call('Target.setDiscoverTargets',{discover:true});
    await this.flush();
    await this.reconcile();if(!this.stopped)this.status.status=this.errors.size?'partial':'monitoring';
    // This remains false: target metadata is narrower than full privacy proof.
    if(monitor&&!this.stopped){this.timer=setInterval(()=>{if(this.config.kind==='browser')this.queueReconcile('reconcile');else if(!this.reconciling)this.queue(()=>this.reconcile(),'reconcile');},200);if(this.config.kind==='browser')this.navigationTimer=setInterval(()=>{if(this.navigationWindow)void this.refreshNavigationGuard();},200);}
    if(monitor&&!this.stopped&&this.config.kind==='browser')this.suspensionTimer=setInterval(()=>{void this.refreshScopeSuspensionHeartbeat().catch(()=>this.error('suspension_status_write_failed'));},200);
    await this.flush();
  }
  // This is an isolated browser process, not an ordinary user browser. All of
  // its executable web targets retain the same environment, including OAuth,
  // cross-origin frames and workers. Routing is enforced by the scoped lease
  // gateway; leaving the six product domains must never clear emulation.
  scope(info){return this.config.kind==='electron'||TARGET_TYPES.has(info.type)||/^(?:https?:|blob:https?:|data:)/i.test(info.url??'');}
  invalidateNavigation(diagnostic='scope_changed'){
    if(['scope_changed','configuration_changed'].includes(diagnostic))this.beginScopeSuspension();
    this.verifiedScopeNavigationProof=null;
    this.topologyEvent('navigation_invalidated',{detail:['scope_changed','private_pipe_unavailable','navigation_deadline_expired','navigation_binding_unavailable','configuration_changed'].includes(diagnostic)?diagnostic:'other'});
    if(this.navigationWindow&&!this.navigationWindow.invalidated){this.navigationWindow.invalidated=true;this.status.counts.navigation_invalidations++;}
    this.status.navigation_guard=null;this.status.environment_check_ok=false;this.status.environment_check_pending=true;this.status.last_environment_diagnostic=diagnostic;
  }
  publishImmediate(){void this.publish().catch(()=>this.error('navigation_status_write_failed'));}
  recordTargetTypeDiagnostic(event,record,currentType,source,cachedType=record?.type){
    if(!TARGET_TYPE_EVENTS.includes(event)||!TARGET_TYPE_SOURCES.includes(source))reject('invalid_target_type_diagnostic');
    const hash=value=>typeof value==='string'&&value.length>0&&value.length<=256?createHash('sha256').update(this.topologySalt+'\\0'+value).digest('hex').slice(0,16):null;
    const events=this.status.target_type_diagnostic?.events??[];
    this.status.target_type_diagnostic={schema:1,scope:'fixed-target-type-reconciliation-v1',checked_at:new Date().toISOString(),events:[...events,{event,source,cached_type:targetTypeLabel(cachedType),current_type:targetTypeLabel(currentType),target_hash:hash(record?.targetId),session_hash:hash(record?.sessionId)}].slice(-32)};
  }
  recordLifecycleDiagnostic(event,record,source,reason='none'){
    if(this.config.kind!=='browser')return;
    if(!TARGET_LIFECYCLE_EVENTS.includes(event)||!TARGET_LIFECYCLE_SOURCES.includes(source)||!TARGET_LIFECYCLE_REASONS.includes(reason))reject('invalid_target_lifecycle_diagnostic');
    const hash=value=>typeof value==='string'&&value.length>0&&value.length<=256?createHash('sha256').update(this.topologySalt+'\0'+value).digest('hex').slice(0,16):null;
    const events=this.status.target_lifecycle_diagnostic?.events??[];
    this.status.target_lifecycle_diagnostic={schema:1,scope:'fixed-target-lifecycle-v1',checked_at:new Date().toISOString(),events:[...events,{event,source,reason,type:targetTypeLabel(record?.type),target_hash:hash(record?.targetId),session_hash:hash(record?.sessionId)}].slice(-8)};
  }
  lifecycleErrorReason(error){return TARGET_LIFECYCLE_REASONS.includes(error?.code)?error.code:'other_error';}
  recordPendingDiagnostic(event,info,reason='none',elapsed=0,rebind=null){
    if(this.config.kind!=='browser')return;
    const eventsAllowed=new Set(['pending','resolved','timeout','canonical_detached','alias_promoted','alias_refused']);
    const reasons=new Set(['none','target_absent','owned_canonical','unpaused_canonical','no_eligible_alias','identity_changed','inventory_not_exact','runtime_unavailable','runtime_mismatch','setup_failed','scope_transition_retry_pending','retry_budget_expired']);
    if(!eventsAllowed.has(event)||!reasons.has(reason))reject('invalid_autoattach_pending_diagnostic');
    const id=info?.targetId;
    const hash=value=>typeof value==='string'&&value.length>0&&value.length<=256?createHash('sha256').update(this.topologySalt+'\0'+value).digest('hex').slice(0,16):null;
    const age_bucket=elapsed<1000?'under_1s':elapsed<4000?'1_to_4s':elapsed<5000?'4_to_5s':'at_least_5s';
    const item={event,reason,type:targetTypeLabel(info?.type),target_hash:hash(id),age_bucket,
      canonical_count:[...this.records.values()].filter(r=>r.targetId===id).length,
      alias_count:[...this.browserAliasSessions.values()].filter(r=>r.targetId===id).length,
      waiting_count:[...this.browserWaitingSessions.values()].filter(targetId=>targetId===id).length,
      pending_count:this.browserAutoattachPending.size,
      previous_session_hash:hash(rebind?.previousSessionId),replacement_session_hash:hash(rebind?.replacementSessionId),
      unpaused_history_count:this.unpausedAttachments.size,retired_history_count:this.retiredUnpaused.size,rebind_count:this.browserCanonicalRebindings.size};
    const events=this.status.autoattach_pending_diagnostic?.events??[];
    const repeat=events.length&&JSON.stringify(events.at(-1))===JSON.stringify(item);
    this.status.autoattach_pending_diagnostic={schema:1,scope:'fixed-autoattach-pending-v1',checked_at:new Date().toISOString(),events:repeat?events:[...events,item].slice(-16)};
  }
  browserTypeContext(record){
    return {record,sessionId:record.sessionId,targetId:record.targetId,type:record.type,revision:record.typeRevision??0};
  }
  browserTypeContextCurrent(token){
    const r=token.record;
    return !this.stopped&&this.records.get(token.sessionId)===r&&this.byTarget.get(token.targetId)===token.sessionId&&r.sessionId===token.sessionId&&r.targetId===token.targetId&&r.type===token.type&&(r.typeRevision??0)===token.revision;
  }
  browserInventoryInfos(result){
    if(!plain(result)||!Array.isArray(result.targetInfos)||result.targetInfos.length>4096)reject('target_type_inventory_invalid');
    const ids=new Set();
    for(const info of result.targetInfos){
      if(!plain(info)||typeof info.targetId!=='string'||!info.targetId.length||info.targetId.length>256||ids.has(info.targetId)||typeof info.type!=='string'||!info.type.length||info.type.length>64)reject('target_type_inventory_invalid');
      ids.add(info.targetId);
    }
    return result.targetInfos;
  }
  beginBrowserTypeChange(record,info,source){
    if(this.config.kind!=='browser'||this.records.get(record.sessionId)!==record||this.byTarget.get(record.targetId)!==record.sessionId)return false;
    if(!plain(info)||info.targetId!==record.targetId||typeof info.type!=='string'||!info.type.length||info.type.length>64)reject('target_type_info_invalid');
    if(record.pendingTypeChange?.type===info.type)return true;
    this.recordTargetTypeDiagnostic('type_change_seen',record,info.type,source);
    record.typeRevision=(record.typeRevision??0)+1;record.pendingTypeChange={type:info.type,source};
    if(TARGET_TYPES.has(info.type))this.markBrowserPromotionUnpaused(record);
    record.configured=false;record.metadataConfirmed=false;record.configurationGeneration=0;
    record.configurationMode='unconfigured';record.systemRuntimeVerifiedAt=null;record.workerInheritedVerifiedAt=null;
    this.workerRuntimeChecks.delete(record.sessionId);this.verifiedSessions.delete(record.sessionId);this.configurationGeneration++;
    this.invalidateNavigation('scope_changed');this.publishImmediate();return true;
  }
  markBrowserPromotionUnpaused(record){
    const old=this.unpausedAttachments.get(record.sessionId);
    if(old!==undefined&&old!==record.targetId)reject('target_type_session_identity_changed');
    if(old===undefined){this.unpausedAttachments.set(record.sessionId,record.targetId);this.status.counts.early_unpaused_targets++;}
    this.errors.add('early_unpaused_target');
  }
  async retireAbsentBrowserTypeRecord(record,infos){
    if(this.records.get(record.sessionId)!==record||this.byTarget.get(record.targetId)!==record.sessionId||infos.some(info=>info.targetId===record.targetId))return false;
    this.records.delete(record.sessionId);this.byTarget.delete(record.targetId);this.workerRuntimeChecks.delete(record.sessionId);this.verifiedSessions.delete(record.sessionId);
    this.status.counts.retired_before_metadata++;
    this.recordTargetTypeDiagnostic('retired',record,'unknown','reconcile');
    if(!this.confirmUnpausedRetirements({targetInfos:infos})){await this.failClosed('target_type_retirement_not_verified');return false;}
    return true;
  }
  async reconcileBrowserRecordType(record,info,source){
    if(this.config.kind!=='browser')return false;
    if(!record.pendingTypeChange)this.beginBrowserTypeChange(record,info,source);
    const token=this.browserTypeContext(record),expected=record.pendingTypeChange?.type;
    if(typeof expected!=='string')return false;
    const result=await this.rootInventory(1000);
    const infos=this.browserInventoryInfos(result),observed=infos.find(item=>item.targetId===token.targetId);
    if(!this.browserTypeContextCurrent(token))return false;
    if(!observed){await this.retireAbsentBrowserTypeRecord(record,infos);return false;}
    if(observed.type!==expected){
      this.recordTargetTypeDiagnostic('inventory_mismatch',record,observed.type,source);
      if(source==='reconcile'&&TARGET_TYPES.has(observed.type))this.beginBrowserTypeChange(record,observed,'reconcile');
      this.schedulePendingCheck();return false;
    }
    if(observed.attached!==true){this.recordTargetTypeDiagnostic('inventory_mismatch',record,observed.type,source);this.schedulePendingCheck();return false;}
    if(!TARGET_TYPES.has(observed.type)){
      this.recordTargetTypeDiagnostic('type_refused',record,observed.type,source);
      await this.failClosed('unsupported_executable_target');return false;
    }
    this.recordTargetTypeDiagnostic('promotion_started',record,observed.type,source);
    this.markBrowserPromotionUnpaused(record);
    record.type=observed.type;record.url=typeof observed.url==='string'?observed.url:'';record.inScope=true;record.mainFrameId=null;
    record.configured=false;record.metadataConfirmed=false;record.configurationMode='unconfigured';record.configurationGeneration=0;
    record.emulationApplied=false;record.workerOverrideUnavailable=false;record.systemRuntimeVerifiedAt=null;record.workerInheritedVerifiedAt=null;
    const configuredToken=this.browserTypeContext(record);
    try{
      await this.configure(record,false,WORKER_TYPES.has(record.type));
      if(!this.browserTypeContextCurrent(configuredToken))return false;
      if(TARGET_TYPES.has(record.type))await this.transport.call('Target.setAutoAttach',{autoAttach:true,waitForDebuggerOnStart:true,flatten:true},record.sessionId);
      if(!this.browserTypeContextCurrent(configuredToken))return false;
      const matched=await this.verifyMetadata(record,WORKER_TYPES.has(record.type));
      if(!matched||!this.browserTypeContextCurrent(configuredToken))return false;
      const after=this.browserInventoryInfos(await this.rootInventory(1000));
      const same=after.find(item=>item.targetId===record.targetId);
      if(!this.browserTypeContextCurrent(configuredToken))return false;
      if(!same){await this.retireAbsentBrowserTypeRecord(record,after);return false;}
      if(same.type!==record.type||same.attached!==true){this.recordTargetTypeDiagnostic('inventory_mismatch',record,same.type,source);this.schedulePendingCheck();return false;}
      record.pendingTypeChange=null;this.status.counts.navigation_scope_resets++;
      this.recordTargetTypeDiagnostic('promotion_verified',record,same.type,source);
      return true;
    }catch(error){
      if(error?.code==='browser_target_type_changed'){this.recordTargetTypeDiagnostic('stale_result_discarded',record,record.type,source,configuredToken.type);this.schedulePendingCheck();return false;}
      throw error;
    }
  }
  async browserTargetInfoChanged(record,info){
    if(!plain(info)||info.targetId!==record.targetId||typeof info.type!=='string'||!info.type.length||info.type.length>64)reject('target_type_info_invalid');
    if(record.type!==info.type||record.pendingTypeChange){
      if(record.pendingTypeChange?.type!==info.type)this.beginBrowserTypeChange(record,info,'target_info_event');
      return this.reconcileBrowserRecordType(record,info,'target_info_event');
    }
    if(!TARGET_TYPES.has(info.type)&&this.scope(info)){
      this.recordTargetTypeDiagnostic('type_refused',record,info.type,'target_info_event');await this.failClosed('unsupported_executable_target');return false;
    }
    record.url=typeof info.url==='string'?info.url:'';record.inScope=this.scope(info);return true;
  }
  observeNavigation(msg){
    if(this.stopped||this.config.kind!=='browser')return;
    if(msg.method==='Target.targetCreated'){this.topologyEvent('target_created_observed',{info:msg.params?.targetInfo,source:'auto_event'});return;}
    if(msg.method==='Target.targetDestroyed'){this.topologyEvent('target_destroyed_observed',{info:{targetId:msg.params?.targetId},source:'auto_event'});return;}
    if(msg.method==='PrivatePipe.failed'){this.invalidateNavigation('private_pipe_unavailable');this.error('private_pipe_unavailable');return;}
    if(msg.method==='Target.targetInfoChanged'){
      const info=msg.params?.targetInfo,record=this.records.get(this.byTarget.get(info?.targetId));
      if(record&&(!plain(info)||typeof info.type!=='string'||!info.type.length||info.type.length>64)){this.error('target_type_info_invalid');return;}
      try{
        if(record&&(record.type!==info.type||(record.pendingTypeChange&&record.pendingTypeChange.type!==info.type)))this.beginBrowserTypeChange(record,info,'target_info_event');
        else if(record&&!TARGET_TYPES.has(record.type)&&this.scope(info))this.beginBrowserTypeChange(record,info,'target_info_event');
      }catch{this.error('target_type_info_invalid');}
      return;
    }
    if(msg.method==='Target.attachedToTarget'){
      const value=msg.params??{};this.topologyEvent('auto_attach_observed',{info:value.targetInfo,sessionId:value.sessionId,paused:value.waitingForDebugger===true,source:'auto_event'});
      if(this.browserDetachedSessions.has(value.sessionId)){this.error('attachment_session_identity_changed');return;}
      const known=this.records.get(value.sessionId)??this.browserAliasSessions.get(value.sessionId),knownId=known?.targetId??this.browserResumedSessions.get(value.sessionId)??this.processedAttachments.get(value.sessionId);
      if(knownId!==undefined&&(!plain(value.targetInfo)||knownId!==value.targetInfo.targetId||(known&&known.type!==value.targetInfo.type))){this.error('attachment_session_identity_changed');return;}
      if(plain(value.targetInfo)&&this.scope(value.targetInfo)&&typeof value.sessionId==='string'&&this.byTarget.has(value.targetInfo.targetId)&&this.byTarget.get(value.targetInfo.targetId)!==value.sessionId){
        if(!this.browserObservedAliases.has(value.sessionId)&&this.browserObservedAliases.size>=64){this.error('attachment_alias_limit');return;}
        this.browserObservedAliases.set(value.sessionId,value.targetInfo.targetId);
      }
      if(value.waitingForDebugger===true&&typeof value.sessionId==='string'&&plain(value.targetInfo)&&this.scope(value.targetInfo)&&typeof value.targetInfo.targetId==='string'&&!this.browserResumedSessions.has(value.sessionId)){
        const previous=this.browserWaitingSessions.get(value.sessionId);
        if(previous!==undefined&&previous!==value.targetInfo.targetId){this.error('attachment_session_identity_changed');return;}
        if(previous===undefined){
          if(this.browserWaitingSessions.size>=4096){this.error('attachment_history_limit');return;}
          this.browserWaitingSessions.set(value.sessionId,value.targetInfo.targetId);this.configurationGeneration++;
          const record=this.records.get(value.sessionId);if(record)record.waitingForResume=true;
          this.invalidateNavigation();this.publishImmediate();
        }
      }
      if(plain(value.targetInfo)&&this.scope(value.targetInfo)&&!this.records.has(value.sessionId)){this.configurationGeneration++;this.invalidateNavigation();this.publishImmediate();}
      return;
    }
    if(msg.method==='Target.detachedFromTarget'){
      const session=msg.params?.sessionId,known=this.records.get(session);this.topologyEvent('detach_observed',{info:known?{targetId:known.targetId,type:known.type}:null,sessionId:session,source:'auto_event'});
      if(known||this.browserAliasSessions.has(session)){
        if(this.browserDetachedSessions.size>=4096){this.error('attachment_history_limit');return;}
        this.browserDetachedSessions.add(session);
        if(known&&this.byTarget.get(known.targetId)===session){
          if(!Number.isFinite(known.canonicalDetachedAt))known.canonicalDetachedAt=performance.now();
          this.configurationGeneration++;this.invalidateNavigation();this.publishImmediate();
          this.recordPendingDiagnostic('canonical_detached',known);
        }
      }
      if(this.verifiedSessions.has(session)){
        this.invalidateNavigation();if(this.navigationWindow){this.navigationWindow.loading.delete(session);if(!this.navigationWindow.loading.size){this.navigationWindow.stoppedAt=Date.now();this.navigationWindow.stoppedSequence=++this.observationSequence;}}this.publishImmediate();
      }
      return;
    }
    if(!['Page.frameStartedLoading','Page.frameStartedNavigating','Page.frameStoppedLoading'].includes(msg.method))return;
    const record=this.records.get(msg.sessionId);
    if(!record||!PAGE_TYPES.has(record.type)||!record.mainFrameId||msg.params?.frameId!==record.mainFrameId)return;
    if(msg.method==='Page.frameStoppedLoading'){
      if(this.navigationWindow){this.navigationWindow.loading.delete(record.sessionId);if(!this.navigationWindow.loading.size){this.navigationWindow.stoppedAt=Date.now();this.navigationWindow.stoppedSequence=++this.observationSequence;}this.schedulePendingCheck();}
      return;
    }
    const live=[...this.records.values()].filter(r=>r.inScope&&TARGET_TYPES.has(r.type));
    // Native inheritance continuity requires the paired watchdog's fresh
    // WinAPI host-timezone/session check on every observation. Binding alone
    // cannot establish that mutable Windows settings stayed unchanged.
    if(!this.sameVerifiedSessions(live))return;
    this.beginScopeSuspension();
    if(!this.navigationWindow){
      const baseline=Date.parse(this.status.environment_check_at),now=Date.now();
      if(!this.status.environment_check_ok||!Number.isFinite(baseline)||baseline>now||now-baseline>=4000)return;
      this.navigationWindow={startedAt:now,deadlineAt:now+15000,firstRuntimeCheckedAt:this.status.environment_check_at,generation:this.configurationGeneration,bindings:new Map(this.verifiedSessions),scopeFingerprint:this.browserScopeFingerprint(this.verifiedSessions),loading:new Set(),participants:new Set(),stoppedAt:null,stoppedSequence:null,invalidated:false};
      this.status.counts.navigation_windows_started++;
    }
    // Redirects and repeated starts keep the first start/deadline, including
    // when old-document JavaScript still evaluates during the same loading.
    this.navigationWindow.loading.add(record.sessionId);this.navigationWindow.participants.add(record.sessionId);this.navigationWindow.stoppedAt=null;this.navigationWindow.stoppedSequence=null;
    void this.refreshNavigationGuard();
  }
  confirmUnpausedRetirements(result){
    if(!plain(result)||!Array.isArray(result.targetInfos))return false;
    const current=new Set();
    for(const info of result.targetInfos){if(!plain(info)||typeof info.targetId!=='string'||current.has(info.targetId))return false;current.add(info.targetId);}
    // Only a fresh browser-root inventory can prove an unpaused target gone.
    // A detach notification or a historical aggregate count is insufficient.
    for(const [session,targetId] of this.retiredUnpaused){if(current.has(targetId))return false;}
    for(const [session,targetId] of this.unpausedAttachments){
      if(!current.has(targetId)&&!this.records.has(session)&&this.byTarget.get(targetId)!==session)this.retiredUnpaused.set(session,targetId);
    }
    this.status.counts.unpaused_retired_verified=this.retiredUnpaused.size;
    return true;
  }
  retirementEvidenceForNavigation(){
    const proof=this.unpausedRetirementProof,nav=this.status.navigation_guard,window=this.navigationWindow,now=Date.now();
    if(!proof||this.stopped||!window||window.invalidated||!nav||window.generation!==this.configurationGeneration||
        now>=window.deadlineAt||proof.configuration_generation!==this.configurationGeneration||
        proof.navigation_started_at!==nav.started_at||proof.navigation_checked_at!==nav.checked_at||proof.checked_at!==nav.checked_at||
        proof.early_unpaused_total!==this.status.counts.early_unpaused_targets||proof.retired_unpaused_verified!==this.status.counts.unpaused_retired_verified||
        !Number.isFinite(Date.parse(proof.checked_at))||Date.parse(proof.checked_at)>now||now-Date.parse(proof.checked_at)>=4000)return null;
    return {...proof};
  }
  browserScopeFingerprint(bindings){
    if(!(bindings instanceof Map)||!bindings.size||bindings.size>4096)return null;
    const entries=[...bindings].map(([sid,binding])=>[sid,binding?.targetId,binding?.type,binding?.generation]);
    if(entries.some(e=>typeof e[0]!=='string'||!e[0].length||typeof e[1]!=='string'||!e[1].length||!TARGET_TYPES.has(e[2])||!Number.isSafeInteger(e[3])||e[3]<=0)||new Set(entries.map(e=>e[1])).size!==entries.length)return null;
    entries.sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
    return createHash('sha256').update(this.topologySalt+'\0scope-v1\0'+JSON.stringify(entries)).digest('hex');
  }
  verifiedScopeEvidenceForNavigation(){
    const proof=this.verifiedScopeNavigationProof,window=this.navigationWindow,nav=this.status.navigation_guard,now=Date.now();
    if(this.stopped||!proof||!window||window.invalidated||!nav||window.generation!==this.configurationGeneration||now>=window.deadlineAt||
        this.browserWaitingSessions.size||this.browserObservedAliases.size||this.browserAutoattachPending.size||[...this.browserAliasSessions.values()].some(alias=>alias.pending)||
        proof.configuration_generation!==this.configurationGeneration||proof.navigation_started_at!==nav.started_at||proof.navigation_checked_at!==nav.checked_at||
        proof.navigation_deadline_at!==nav.deadline_at||proof.first_runtime_checked_at!==nav.first_runtime_checked_at||proof.checked_at!==nav.checked_at||
        proof.baseline_scope_fingerprint!==window.scopeFingerprint||proof.current_scope_fingerprint!==window.scopeFingerprint||
        proof.early_unpaused_total!==this.status.counts.early_unpaused_targets||proof.retired_unpaused_verified!==this.status.counts.unpaused_retired_verified||
        proof.scope_target_count!==window.bindings.size||this.browserScopeFingerprint(window.bindings)!==window.scopeFingerprint||
        !Number.isFinite(Date.parse(proof.checked_at))||Date.parse(proof.checked_at)>now||now-Date.parse(proof.checked_at)>=4000)return null;
    return {...proof};
  }
  async ignoreRetiredDuplicate(sessionId,info){
    const processed=this.processedAttachments.get(sessionId);
    if(processed===undefined)return false;
    if(processed!==info.targetId){this.error('attachment_session_identity_changed');return true;}
    if(this.records.has(sessionId))return false;
    const current=await this.rootInventory();
    if(!plain(current)||!Array.isArray(current.targetInfos)||current.targetInfos.some(item=>item?.targetId===info.targetId)){
      this.error('retired_attachment_target_reappeared');return true;
    }
    if(!this.confirmUnpausedRetirements(current)){this.error('retired_attachment_inventory_invalid');return true;}
    this.status.counts.retired_attachment_duplicates_ignored++;
    if(this.config.kind==='browser'){this.browserWaitingSessions.delete(sessionId);this.browserObservedAliases.delete(sessionId);}
    this.topologyEvent('retired_duplicate_ignored',{info,sessionId,source:'auto_event'});
    return true;
  }
  navigationProof(result,window=this.navigationWindow){
    // For system-runtime records this proof is one necessary part of the
    // paired watchdog check; it is never independent host-timezone evidence.
    if(this.stopped||!window||window!==this.navigationWindow||window.invalidated)return false;
    if(this.config.kind==='browser'&&(this.browserWaitingSessions.size||this.browserObservedAliases.size||this.browserAutoattachPending.size||[...this.browserAliasSessions.values()].some(alias=>alias.pending))){this.invalidateNavigation('navigation_binding_unavailable');return false;}
    const now=Date.now();
    if(now>=window.deadlineAt){this.invalidateNavigation('navigation_deadline_expired');this.status.counts.navigation_deadline_expirations++;return false;}
    if(!this.confirmUnpausedRetirements(result)){this.invalidateNavigation('navigation_binding_unavailable');return false;}
    const infos=(result.targetInfos??[]).filter(info=>this.scope(info));
    const records=[...this.records.values()].filter(r=>r.inScope&&TARGET_TYPES.has(r.type));
    const same=window.generation===this.configurationGeneration&&records.length===window.bindings.size&&infos.length===window.bindings.size&&records.every(record=>{
      const before=window.bindings.get(record.sessionId),info=infos.find(x=>x.targetId===record.targetId);
      return before&&this.configurationReady(record)&&record.metadataConfirmed&&before.targetId===record.targetId&&before.type===record.type&&before.generation===record.configurationGeneration&&this.byTarget.get(record.targetId)===record.sessionId&&info?.attached===true&&info.type===record.type;
    });
    if(!same){this.invalidateNavigation('navigation_binding_unavailable');return false;}
    this.status.navigation_guard={schema:1,mode:'known_navigation_configuration',started_at:new Date(window.startedAt).toISOString(),checked_at:new Date(now).toISOString(),deadline_at:new Date(window.deadlineAt).toISOString(),bindings_verified:true,first_runtime_checked_at:window.firstRuntimeCheckedAt};
    const total=this.status.counts.early_unpaused_targets,retired=this.retiredUnpaused.size,live=total-retired;
    this.verifiedScopeNavigationProof=null;
    if(this.config.kind==='browser'&&window.scopeFingerprint&&Number.isSafeInteger(total)&&total>=1&&total<=4096&&total===this.unpausedAttachments.size&&
        Number.isSafeInteger(retired)&&retired>=0&&retired<=total&&Number.isSafeInteger(live)&&live>=0&&live<=records.length){
      const currentBindings=new Map(records.map(record=>[record.sessionId,{targetId:record.targetId,type:record.type,generation:record.configurationGeneration}]));
      const currentFingerprint=this.browserScopeFingerprint(currentBindings),liveEntries=[...this.unpausedAttachments].filter(([sid])=>!this.retiredUnpaused.has(sid));
      if(currentFingerprint===window.scopeFingerprint&&liveEntries.length===live&&liveEntries.every(([sid,tid])=>window.bindings.get(sid)?.targetId===tid&&this.byTarget.get(tid)===sid)){
        this.verifiedScopeNavigationProof={schema:1,mode:'complete_verified_scope_same_navigation_v1',checked_at:this.status.navigation_guard.checked_at,
          configuration_generation:this.configurationGeneration,scope_target_count:records.length,previously_verified_target_count:window.bindings.size,
          early_unpaused_total:total,retired_unpaused_verified:retired,live_unpaused_count:live,inventory_complete:true,bindings_verified:true,
          baseline_scope_fingerprint:window.scopeFingerprint,current_scope_fingerprint:currentFingerprint,
          navigation_started_at:this.status.navigation_guard.started_at,navigation_checked_at:this.status.navigation_guard.checked_at,
          navigation_deadline_at:this.status.navigation_guard.deadline_at,first_runtime_checked_at:window.firstRuntimeCheckedAt};
      }
    }
    this.unpausedRetirementProof=null;
    if(total>=2&&retired>=1&&Number.isSafeInteger(live)&&live>=0&&live<=1&&total===this.unpausedAttachments.size){
      const liveEntries=[...this.unpausedAttachments].filter(([session])=>!this.retiredUnpaused.has(session));
      if(liveEntries.every(([session,targetId])=>window.bindings.get(session)?.targetId===targetId&&this.byTarget.get(targetId)===session)){
        this.unpausedRetirementProof={schema:1,mode:'retired_unpaused_absent_from_root_inventory',checked_at:this.status.navigation_guard.checked_at,
          configuration_generation:this.configurationGeneration,early_unpaused_total:total,retired_unpaused_verified:retired,live_unpaused_count:live,
          inventory_complete:true,navigation_started_at:this.status.navigation_guard.started_at,navigation_checked_at:this.status.navigation_guard.checked_at};
      }
    }
    this.status.counts.navigation_proofs++;
    if(this.status.environment_check_pending){this.status.last_environment_diagnostic='navigation_configuration_pending';const age=now-Date.parse(this.status.environment_check_at);this.status.environment_check_ok=age>=0&&age<4000;}
    return true;
  }
  async refreshNavigationGuard(){
    if(this.stopped||!this.navigationWindow||this.navigationWindow.invalidated)return false;
    if(this.navigationRefresh)return this.navigationRefresh;
    const window=this.navigationWindow;
    this.navigationRefresh=(async()=>{try{const result=await this.rootInventory(1000);const ok=this.navigationProof(result,window);await this.publish();return ok;}catch(error){this.invalidateNavigation(error?.code==='root_inventory_temporarily_unavailable'?'scope_changed':'navigation_binding_unavailable');this.publishImmediate();return false;}})();
    try{return await this.navigationRefresh;}finally{this.navigationRefresh=null;}
  }
  async reconcile(){
    if(this.stopped||this.reconciling)return;this.reconciling=true;
    try{
      const result=await this.rootInventory();
      const inventory=this.config.kind==='browser'?this.browserInventoryInfos(result):(result.targetInfos??[]);
      if(this.config.kind==='browser'){
        for(const [id,recovery] of this.browserCanonicalRecoveryPending){
          this.browserCanonicalRecoveryPending.delete(id);
          if(this.byTarget.has(id))continue;
          if(performance.now()>=recovery.deadline){this.recordPendingDiagnostic('alias_refused',recovery.previous,'retry_budget_expired');continue;}
          await this.recoverDetachedCanonical(recovery.previous,recovery.canonicalReady,recovery);
          if(this.stopped)return;
        }
        const ids=new Set(inventory.map(info=>info.targetId));
        for(const id of this.browserAutoattachPending.keys())if(!ids.has(id)||this.byTarget.has(id)){
          this.recordPendingDiagnostic('resolved',inventory.find(info=>info.targetId===id)??{targetId:id},!ids.has(id)?'target_absent':'owned_canonical');
          this.browserAutoattachPending.delete(id);
        }
      }
      for(const info of inventory){
        if(this.config.kind==='browser'){
          const record=this.records.get(this.byTarget.get(info.targetId));
          if(record&&(record.type!==info.type||record.pendingTypeChange)){await this.reconcileBrowserRecordType(record,info,'reconcile');if(this.stopped)return;}
        }
        if(this.config.kind==='browser'&&!TARGET_TYPES.has(info.type)&&this.scope(info)){await this.failClosed('unsupported_executable_target');return;}
        if(!TARGET_TYPES.has(info.type)||this.byTarget.has(info.targetId))continue;
        if(this.config.kind==='browser'){
          // Root auto-attach owns browser sessions. A manual attachment here
          // can overtake the real paused event queued behind this reconcile.
          // Revoke and return to the event queue; never await that event here.
          const first=this.browserAutoattachPending.get(info.targetId);
          if(first===undefined){
            if(this.browserAutoattachPending.size>=64){await this.failClosed('autoattach_pending_limit');return;}
            this.browserAutoattachPending.set(info.targetId,performance.now());this.configurationGeneration++;
            this.topologyEvent('auto_attach_pending',{info,source:'none'});
          }else if(performance.now()-first>=5000){this.recordPendingDiagnostic('timeout',info,'none',performance.now()-first);await this.failClosed('autoattach_event_timeout');return;}
          this.recordPendingDiagnostic('pending',info,'none',first===undefined?0:performance.now()-first);
          this.pendingScope('unknown_inventory');
          continue;
        }
        this.topologyEvent('manual_attach_requested',{info,source:'manual_reconcile'});
        const {sessionId}=await this.transport.call('Target.attachToTarget',{targetId:info.targetId,flatten:true});
        if(typeof sessionId==='string'&&!this.records.has(sessionId))await this.attached(sessionId,info,false,'manual_reconcile');
      }
      if(this.config.kind==='browser'&&this.browserAutoattachPending.size){await this.publish();return;}
      await this.checkEnvironment();
      await this.publish();
    }catch(error){
      if(this.config.kind==='browser'&&error?.code==='root_inventory_temporarily_unavailable'){
        this.pendingScope('unknown_inventory');await this.publish();return;
      }
      throw error;
    }finally{this.reconciling=false;}
  }
  async event(msg){
    if(this.stopped)return;
    if(msg.method==='PrivatePipe.failed'){this.error('private_pipe_unavailable');return;}
    if(msg.method==='Target.attachedToTarget'){const p=msg.params??{};await this.attached(p.sessionId,p.targetInfo,p.waitingForDebugger===true,'auto_event');}
    else if(msg.method==='Target.detachedFromTarget'){
      const sessionId=msg.params?.sessionId,record=this.records.get(sessionId);
      const canonicalReady=record&&this.configurationReady(record)&&record.metadataConfirmed===true;
      this.browserAliasSessions.delete(sessionId);this.browserObservedAliases.delete(sessionId);this.browserWaitingSessions.delete(sessionId);
      if(record){
        if(this.byTarget.get(record.targetId)===record.sessionId)this.byTarget.delete(record.targetId);
        this.records.delete(record.sessionId);this.workerRuntimeChecks.delete(record.sessionId);this.verifiedSessions.delete(record.sessionId);
        if(this.config.kind==='browser'){
          if(TARGET_TYPES.has(record.type)&&!this.browserAutoattachPending.has(record.targetId))this.browserAutoattachPending.set(record.targetId,Number.isFinite(record.canonicalDetachedAt)?record.canonicalDetachedAt:performance.now());
          await this.recoverDetachedCanonical(record,canonicalReady);
        }
      }
    }
    else if(msg.method==='Target.targetInfoChanged'){
      const info=msg.params?.targetInfo;const sessionId=this.byTarget.get(info?.targetId);const record=this.records.get(sessionId);
      if(record){
        if(this.config.kind==='browser')await this.browserTargetInfoChanged(record,info);
        else {record.url=typeof info.url==='string'?info.url:'';const scope=this.scope(info);if(scope!==record.inScope){record.inScope=scope;this.status.counts.early_unpaused_targets++;this.errors.add('unpaused_navigation_scope_change');await this.configure(record,!scope);if(scope)await this.verifyMetadata(record,WORKER_TYPES.has(record.type));this.status.counts.navigation_scope_resets++;}}
      }
    }
    await this.publish();
  }
  async attached(sessionId,info,paused,source='direct'){
    this.topologyEvent('record_attach',{info,sessionId,paused,source});
    if(typeof sessionId!=='string'||!plain(info)||typeof info.targetId!=='string')return;
    if(this.records.has(sessionId)){
      const record=this.records.get(sessionId);
      if(this.config.kind==='browser'){
        if(record.targetId!==info.targetId||this.byTarget.get(info.targetId)!==sessionId||record.type!==info.type){await this.failClosed('attachment_session_identity_changed');return;}
        if(paused||record.waitingForResume||this.browserWaitingSessions.has(sessionId)){await this.resumeBrowserRecord(record);if(!this.stopped&&!record.retiredConfirmed&&record.inScope&&TARGET_TYPES.has(record.type))await this.verifyMetadata(record,WORKER_TYPES.has(record.type));}
      }
      this.topologyEvent('existing_session_checked',{info,sessionId,paused,source});return;
    }
    if(this.config.kind==='browser'&&this.byTarget.has(info.targetId)){
      await this.attachBrowserAlias(sessionId,info,paused);return;
    }
    if(await this.ignoreRetiredDuplicate(sessionId,info))return;
    if(this.processedAttachments.size>=4096){this.error('attachment_history_limit');return;}
    this.processedAttachments.set(sessionId,info.targetId);
    const record={sessionId,targetId:info.targetId,type:info.type,url:typeof info.url==='string'?info.url:'',inScope:this.scope(info),configured:false,configurationMode:'unconfigured',emulationApplied:false,workerOverrideUnavailable:false,workerInheritedVerifiedAt:null,metadataConfirmed:false,configurationGeneration:0,mainFrameId:null,waitingForResume:this.config.kind==='browser'&&(paused||this.browserWaitingSessions.has(sessionId))};this.records.set(sessionId,record);this.byTarget.set(info.targetId,sessionId);this.status.counts.attached++;
    if(!paused&&record.inScope){this.unpausedAttachments.set(sessionId,record.targetId);this.status.counts.early_unpaused_targets++;this.errors.add('early_unpaused_target');}
    let verify=false,retiredSetup=false,supersededSetup=false;
    try{
      if(PAGE_TYPES.has(record.type)){
        if(record.inScope){await this.configure(record,false);verify=true;}else this.status.counts.unprotected_targets++;
        try{await this.transport.call('Target.setAutoAttach',{autoAttach:true,waitForDebuggerOnStart:true,flatten:true},sessionId);}catch{this.error('recursive_autoattach_unavailable');}
      }else if(WORKER_TYPES.has(record.type)){
        if(record.inScope){try{await this.configure(record,false,true);}catch{record.workerOverrideUnavailable=true;this.errors.add('worker_override_unavailable');}verify=true;}else this.status.counts.unprotected_targets++;
        if(this.config.kind==='browser')await this.transport.call('Target.setAutoAttach',{autoAttach:true,waitForDebuggerOnStart:true,flatten:true},sessionId);
      }else if(this.config.kind==='browser'&&!record.inScope){this.status.counts.internal_targets_ignored=(this.status.counts.internal_targets_ignored??0)+1;}
      else{this.status.counts.unknown_target_types++;this.errors.add('unknown_target_type_unverified');if(this.config.kind==='browser')await this.failClosed('unsupported_executable_target');}
    }catch(error){
      if(this.config.kind==='browser'&&error?.code==='browser_target_type_changed'){
        supersededSetup=true;verify=false;this.recordTargetTypeDiagnostic('stale_result_discarded',record,record.type,'configuration');this.schedulePendingCheck();
      }else retiredSetup=await this.retireFailedSetupTarget(record);
      if(!retiredSetup&&!supersededSetup){
        const type=['page','iframe'].includes(record.type)?record.type:'other';
        const stage=['timezone','locale','headers','page_enable','frame_tree'].includes(record.setupStage)?record.setupStage:'other';
        const reasons=new Set(['cdp_timezone_override_in_effect','cdp_locale_override_in_effect','cdp_top_level_only','cdp_command_rejected','cdp_command_timeout','private_pipe_closed','private_pipe_write_failed']);
        const reason=reasons.has(error?.code)?error.code:'other';
        this.errors.add('setup_'+type+'_'+stage+'_'+reason);
        this.error('target_environment_setup_failed');
      }
    }
    finally{if((paused||(this.config.kind==='browser'&&this.browserWaitingSessions.has(sessionId)))&&!this.stopped&&!retiredSetup){try{if(this.config.kind==='browser'){await this.resumeBrowserRecord(record);retiredSetup=record.retiredConfirmed===true;}else await this.transport.call('Runtime.runIfWaitingForDebugger',{},sessionId);}catch{this.error('target_resume_failed');}}}
    if(retiredSetup){await this.publish();return;}
    // A newly paused target may not have a default execution context yet.
    // Apply overrides first, resume, then perform bounded metadata retries.
    if(verify&&!this.stopped)await this.verifyMetadata(record,WORKER_TYPES.has(record.type));
    if(this.config.kind==='browser'&&!this.stopped)this.browserAutoattachPending.delete(record.targetId);
    await this.publish();
  }
  async resumeBrowserRecord(record){
    const prior=this.browserResumedSessions.get(record.sessionId);
    if(prior!==undefined){if(prior!==record.targetId)await this.failClosed('attachment_session_identity_changed');return;}
    if(this.records.get(record.sessionId)!==record||this.byTarget.get(record.targetId)!==record.sessionId||record.pendingTypeChange){await this.failClosed('target_resume_identity_unavailable');return;}
    const waiting=this.browserWaitingSessions.get(record.sessionId);
    if(waiting!==undefined&&waiting!==record.targetId){await this.failClosed('attachment_session_identity_changed');return;}
    if(this.browserResumedSessions.size>=4096){await this.failClosed('attachment_history_limit');return;}
    const token=this.browserTypeContext(record);
    try{await this.transport.call('Runtime.runIfWaitingForDebugger',{},record.sessionId);}
    catch(error){
      this.recordLifecycleDiagnostic('operation_failed',record,'resume',this.lifecycleErrorReason(error));
      if(await this.retireAbsentBrowserRecord(record,'resume'))return false;
      throw error;
    }
    if(!this.browserTypeContextCurrent(token)){await this.failClosed('target_resume_identity_unavailable');return;}
    this.browserResumedSessions.set(record.sessionId,record.targetId);this.browserWaitingSessions.delete(record.sessionId);record.waitingForResume=false;
    if(record.inScope)this.configurationGeneration++;this.status.counts.autoattach_resumed_verified=(this.status.counts.autoattach_resumed_verified??0)+1;
    this.topologyEvent('auto_attach_resumed',{info:{targetId:record.targetId,type:record.type},sessionId:record.sessionId,paused:true,source:'auto_event'});
    this.recordLifecycleDiagnostic('resume_verified',record,'resume');
  }
  async recoverDetachedCanonical(previous,canonicalReady,retry=null){
    // A detached canonical may leave a previously verified recursive alias
    // attached to the same execution target. Never attach an unknown target or
    // treat the global inventory's `attached` flag as owned-session evidence.
    const refuse=reason=>{this.recordPendingDiagnostic('alias_refused',previous,reason);return false;};
    const aliases=[...this.browserAliasSessions.values()].filter(alias=>alias.targetId===previous.targetId);
    const ownedRunState=alias=>(alias.resumed===true&&this.browserResumedSessions.get(alias.sessionId)===previous.targetId)||
      (alias.resumed===false&&alias.observedRunning===true&&!this.browserResumedSessions.has(alias.sessionId));
    const eligible=alias=>alias.type===previous.type&&alias.canonicalSessionId===previous.sessionId&&alias.pending===false&&
      alias.bindingVerified===true&&alias.canonicalConfigurationGeneration===previous.configurationGeneration&&ownedRunState(alias)&&!this.records.has(alias.sessionId)&&!this.browserDetachedSessions.has(alias.sessionId)&&
      !this.browserWaitingSessions.has(alias.sessionId)&&!this.browserObservedAliases.has(alias.sessionId);
    if(!canonicalReady||!TARGET_TYPES.has(previous.type)||previous.pendingTypeChange||!aliases.length||aliases.some(alias=>!eligible(alias)))return refuse('no_eligible_alias');
    const alias=retry?.alias??aliases[0],initialGeneration=this.configurationGeneration;
    const origin=Number.isFinite(previous.canonicalDetachedAt)?previous.canonicalDetachedAt:performance.now();
    const deadline=retry?.deadline??origin+1500,attempt=retry?.attempt??1;
    if(!aliases.includes(alias)||!eligible(alias))return refuse('identity_changed');
    if(performance.now()>=deadline)return refuse('retry_budget_expired');
    const historyCompatible=()=>!this.retiredUnpaused.has(previous.sessionId)&&!this.retiredUnpaused.has(alias.sessionId)&&
      !this.unpausedAttachments.has(alias.sessionId)&&!this.browserCanonicalRebindings.has(previous.sessionId)&&this.browserCanonicalRebindings.size<4096&&
      (this.processedAttachments.get(alias.sessionId)===previous.targetId||(!this.processedAttachments.has(alias.sessionId)&&this.processedAttachments.size<4096))&&
      [...this.unpausedAttachments].every(([sid,target])=>target!==previous.targetId||sid===previous.sessionId)&&
      (!this.unpausedAttachments.has(previous.sessionId)||this.unpausedAttachments.get(previous.sessionId)===previous.targetId)&&
      [...this.browserCanonicalRebindings.values()].every(history=>
        history.previousSessionId!==alias.sessionId&&history.replacementSessionId!==alias.sessionId&&
        (history.replacementSessionId!==previous.sessionId||(history.targetId===previous.targetId&&history.type===previous.type)));
    if(!historyCompatible())return refuse('identity_changed');
    let promoted=null,committed=false,retryRequested=false;
    const oldUnchanged=()=>previous.type===alias.type&&previous.targetId===alias.targetId&&!previous.pendingTypeChange&&
      this.processedAttachments.get(previous.sessionId)===previous.targetId;
    const aliasAlive=()=>this.browserAliasSessions.get(alias.sessionId)===alias&&!this.browserDetachedSessions.has(alias.sessionId)&&
      alias.bindingVerified===true&&alias.canonicalConfigurationGeneration===previous.configurationGeneration&&ownedRunState(alias)&&!this.browserWaitingSessions.has(alias.sessionId)&&!this.browserObservedAliases.has(alias.sessionId);
    const before=()=>!this.stopped&&oldUnchanged()&&aliasAlive()&&historyCompatible()&&!this.records.has(previous.sessionId)&&!this.byTarget.has(previous.targetId)&&!this.records.has(alias.sessionId)&&this.configurationGeneration===initialGeneration;
    const budget=()=>{const remaining=deadline-performance.now();if(remaining<=0)reject('canonical_recovery_budget_expired');return Math.max(1,Math.min(350,Math.floor(remaining)));};
    const inventory=async()=>this.browserInventoryInfos(await this.rootInventory(budget()));
    const exactTarget=infos=>infos.some(info=>info.targetId===previous.targetId&&info.type===previous.type&&info.attached===true);
    try{
      const first=await inventory();
      if(!before())return refuse('identity_changed');
      if(!exactTarget(first))return refuse('inventory_not_exact');
      promoted={...previous,sessionId:alias.sessionId,configured:false,configurationMode:'unconfigured',metadataConfirmed:false,
        configurationGeneration:0,systemRuntimeVerifiedAt:null,workerInheritedVerifiedAt:null,waitingForResume:false,
        pendingTypeChange:null,retiredConfirmed:false,canonicalDetachedAt:null,canonicalRecoveryDeadline:deadline};
      this.records.set(alias.sessionId,promoted);this.byTarget.set(promoted.targetId,alias.sessionId);alias.pending=true;
      this.configurationGeneration++;this.invalidateNavigation();this.publishImmediate();
      const token=this.browserTypeContext(promoted);
      const same=()=>!this.stopped&&oldUnchanged()&&aliasAlive()&&historyCompatible()&&this.browserTypeContextCurrent(token);
      await this.configure(promoted,false,WORKER_TYPES.has(promoted.type));
      if(!same())return refuse('identity_changed');
      await this.transport.call('Target.setAutoAttach',{autoAttach:true,waitForDebuggerOnStart:true,flatten:true},alias.sessionId,budget());
      if(!same())return refuse('identity_changed');
      // Expected descendant events may arrive while recursion is installed.
      // Freeze only afterwards, then demand an unchanged final proof interval.
      const scopeGeneration=this.configurationGeneration;
      const metadata=await this.metadata(promoted,budget()).catch(()=>null);
      if(!same())return refuse('identity_changed');
      if(!this.matches(metadata)){
        if(metadata!==null){await this.failClosed('continuous_environment_mismatch');return refuse('runtime_mismatch');}
        return refuse('runtime_unavailable');
      }
      if(scopeGeneration!==this.configurationGeneration){retryRequested=attempt===1;return refuse('identity_changed');}
      const final=await inventory();
      if(!same())return refuse('identity_changed');
      if(!exactTarget(final))return refuse('inventory_not_exact');
      if(scopeGeneration!==this.configurationGeneration){retryRequested=attempt===1;return refuse('identity_changed');}
      budget();
      promoted.metadataConfirmed=true;promoted.configurationMode='system_runtime_verified';promoted.configured=true;
      promoted.emulationApplied=false;promoted.systemRuntimeVerifiedAt=Date.now();promoted.configurationGeneration=++this.configurationGeneration;
      delete promoted.canonicalRecoveryDeadline;
      delete promoted.canonicalDetachedAt;
      const unpausedCount=this.unpausedAttachments.size,retiredCount=this.retiredUnpaused.size;
      const history=Object.freeze({previousSessionId:previous.sessionId,replacementSessionId:promoted.sessionId,targetId:promoted.targetId,type:promoted.type,
        configurationGeneration:promoted.configurationGeneration,unpausedHistoryMoved:this.unpausedAttachments.has(previous.sessionId),
        unpausedHistoryCount:unpausedCount,retiredHistoryCount:retiredCount});
      if(history.unpausedHistoryMoved){this.unpausedAttachments.delete(previous.sessionId);this.unpausedAttachments.set(promoted.sessionId,promoted.targetId);}
      this.browserCanonicalRebindings.set(previous.sessionId,history);
      this.processedAttachments.set(promoted.sessionId,promoted.targetId);
      if(WORKER_TYPES.has(promoted.type))this.status.counts.workers_inherited_verified++;else this.status.counts.metadata_matches++;
      for(const oldAlias of aliases){
        if(this.browserAliasSessions.get(oldAlias.sessionId)!==oldAlias)continue;
        if(oldAlias===alias||!eligible(oldAlias)){this.browserAliasSessions.delete(oldAlias.sessionId);continue;}
        // These are already-owned sessions of this exact execution target,
        // not new targets. Preserve them for a later canonical turnover only
        // after the replacement canonical's fresh proof completed.
        oldAlias.canonicalSessionId=promoted.sessionId;oldAlias.canonicalConfigurationGeneration=promoted.configurationGeneration;
      }
      this.browserAutoattachPending.delete(promoted.targetId);
      this.recordPendingDiagnostic('alias_promoted',promoted,'none',0,history);committed=true;
      if(this.navigationWindow?.invalidated){this.navigationWindow=null;this.status.navigation_guard=null;}
      // Preserve all original unpaused/resume history. Only a later complete
      // scope sweep may publish a fresh environment permission.
      this.schedulePendingCheck();return true;
    }catch{return refuse('setup_failed');}
    finally{
      if(!committed&&promoted){
        if(this.records.get(promoted.sessionId)===promoted)this.records.delete(promoted.sessionId);
        if(this.byTarget.get(promoted.targetId)===promoted.sessionId)this.byTarget.delete(promoted.targetId);
        this.workerRuntimeChecks.delete(promoted.sessionId);
        if(this.browserAliasSessions.get(alias.sessionId)===alias)alias.pending=false;
        if(retryRequested&&!this.stopped&&performance.now()<deadline&&this.browserCanonicalRecoveryPending.size<64&&
            !this.byTarget.has(previous.targetId)&&oldUnchanged()&&aliasAlive()&&historyCompatible()){
          this.browserCanonicalRecoveryPending.set(previous.targetId,{previous,canonicalReady,alias,deadline,attempt:2});
          this.recordPendingDiagnostic('alias_refused',previous,'scope_transition_retry_pending');
        }
        this.schedulePendingCheck();
      }
    }
  }
  async attachBrowserAlias(sessionId,info,paused){
    // Recursive auto-attach may give one execution target another session.
    // The alias never becomes a second executable record or replaces byTarget.
    paused=paused||this.browserWaitingSessions.has(sessionId);
    const prior=this.browserAliasSessions.get(sessionId),canonical=this.records.get(this.byTarget.get(info.targetId));
    if(prior){
      if(prior.targetId!==info.targetId||prior.type!==info.type||prior.canonicalSessionId!==canonical?.sessionId){await this.failClosed('attachment_session_identity_changed');return;}
      if(prior.resumed||!paused){this.browserObservedAliases.delete(sessionId);return;}
    }
    if(!canonical||canonical.type!==info.type||!this.configurationReady(canonical)||canonical.metadataConfirmed!==true||canonical.pendingTypeChange){await this.failClosed('alias_canonical_not_verified');return;}
    if(!prior&&this.browserAliasSessions.size>=64){await this.failClosed('attachment_alias_limit');return;}
    const token=this.browserTypeContext(canonical),generation=canonical.configurationGeneration;
    const alias=prior??{sessionId,targetId:info.targetId,type:info.type,canonicalSessionId:canonical.sessionId,resumed:false,pending:true};
    this.browserAliasSessions.set(sessionId,alias);alias.pending=true;
    this.configurationGeneration++;const scopeGeneration=this.configurationGeneration;this.invalidateNavigation();this.publishImmediate();
    const valid=()=>!this.stopped&&this.browserTypeContextCurrent(token)&&this.configurationReady(canonical)&&canonical.metadataConfirmed===true&&canonical.configurationGeneration===generation&&this.configurationGeneration===scopeGeneration&&this.browserAliasSessions.get(sessionId)===alias;
    const metadata=await this.metadata(canonical,1000).catch(()=>null);
    if(!valid()||!this.matches(metadata)){await this.failClosed('alias_canonical_not_verified');return;}
    const inventory=this.browserInventoryInfos(await this.rootInventory(1000));
    const current=inventory.find(item=>item.targetId===info.targetId);
    if(!valid()||!current||current.type!==canonical.type||current.attached!==true){await this.failClosed('alias_root_binding_not_verified');return;}
    if(paused){
      const waiting=this.browserWaitingSessions.get(sessionId),resumed=this.browserResumedSessions.get(sessionId);
      if((waiting!==undefined&&waiting!==info.targetId)||(resumed!==undefined&&resumed!==info.targetId)){await this.failClosed('attachment_session_identity_changed');return;}
      if(resumed===undefined){
        if(this.browserResumedSessions.size>=4096){await this.failClosed('attachment_history_limit');return;}
        try{await this.transport.call('Runtime.runIfWaitingForDebugger',{},sessionId);}
        catch(error){
          this.recordLifecycleDiagnostic('operation_failed',alias,'alias',this.lifecycleErrorReason(error));
          if(valid()&&await this.retireAbsentBrowserRecord(canonical,'alias'))return;
          throw error;
        }
        if(!valid()){await this.failClosed('alias_root_binding_not_verified');return;}
        this.browserResumedSessions.set(sessionId,info.targetId);
        this.status.counts.autoattach_resumed_verified=(this.status.counts.autoattach_resumed_verified??0)+1;
        this.topologyEvent('auto_attach_resumed',{info,sessionId,paused:true,source:'auto_event'});
      }
      this.browserWaitingSessions.delete(sessionId);
    }
    alias.resumed=paused;alias.observedRunning=!paused;alias.bindingVerified=true;alias.canonicalConfigurationGeneration=canonical.configurationGeneration;
    alias.pending=false;this.browserObservedAliases.delete(sessionId);this.configurationGeneration++;
    this.topologyEvent('alias_binding_verified',{info,sessionId,paused,source:'auto_event'});
    this.schedulePendingCheck();await this.publish();
  }
  async retireFailedSetupTarget(record){
    if(this.config.kind!=='browser')return false;
    return this.retireAbsentBrowserRecord(record,'setup');
  }
  async retireAbsentBrowserRecord(record,source){
    if(this.config.kind!=='browser')return false;
    const token=this.browserTypeContext(record);
    if(!this.browserTypeContextCurrent(token)||(!TARGET_TYPES.has(record.type)&&record.inScope)){this.recordLifecycleDiagnostic('retirement_refused',record,source,'identity_changed');return false;}
    let inventory;
    try{inventory=await this.rootInventory(1000);}
    catch{this.recordLifecycleDiagnostic('retirement_refused',record,source,'inventory_unavailable');return false;}
    let infos;try{infos=this.browserInventoryInfos(inventory);}catch{this.recordLifecycleDiagnostic('retirement_refused',record,source,'inventory_invalid');return false;}
    if(!this.browserTypeContextCurrent(token)){this.recordLifecycleDiagnostic('retirement_refused',record,source,'identity_changed');return false;}
    if(infos.some(info=>info.targetId===record.targetId)){this.recordLifecycleDiagnostic('retirement_refused',record,source,'target_present');return false;}
    // A command rejection alone is never retirement evidence. Only this fresh
    // complete root absence, with the same canonical identity before/after the
    // read, allows removal of this owned target. No resume success is invented.
    this.records.delete(record.sessionId);this.byTarget.delete(record.targetId);this.workerRuntimeChecks.delete(record.sessionId);this.verifiedSessions.delete(record.sessionId);
    this.browserWaitingSessions.delete(record.sessionId);this.browserAutoattachPending.delete(record.targetId);
    for(const [sid,alias] of this.browserAliasSessions)if(alias.targetId===record.targetId&&alias.canonicalSessionId===record.sessionId){this.browserAliasSessions.delete(sid);this.browserWaitingSessions.delete(sid);this.browserObservedAliases.delete(sid);}
    for(const [sid,targetId] of this.browserObservedAliases)if(targetId===record.targetId)this.browserObservedAliases.delete(sid);
    for(const [sid,targetId] of this.browserWaitingSessions)if(targetId===record.targetId)this.browserWaitingSessions.delete(sid);
    record.retiredConfirmed=true;this.status.counts.retired_before_metadata++;this.configurationGeneration++;
    this.invalidateNavigation('scope_changed');
    if(!this.confirmUnpausedRetirements(inventory)){await this.failClosed('retired_attachment_inventory_invalid');return false;}
    this.recordLifecycleDiagnostic('retirement_verified',record,source);
    if(source==='setup')this.topologyEvent('retired_setup_target',{info:{targetId:record.targetId,type:record.type},sessionId:record.sessionId,detail:'setup_target_absent'});
    this.schedulePendingCheck();return true;
  }
  async configure(record,clear=false,worker=false){
    this.topologyEvent('configuration_started',{info:{targetId:record.targetId,type:record.type},sessionId:record.sessionId,detail:worker?'worker':'page'});
    if(this.navigationWindow)this.invalidateNavigation('configuration_changed');
    const setupToken=this.config.kind==='browser'?this.browserTypeContext(record):null;
    const call=(method,params)=>{
      record.setupStage=({'Emulation.setTimezoneOverride':'timezone','Emulation.setLocaleOverride':'locale','Network.setExtraHTTPHeaders':'headers','Page.enable':'page_enable','Page.getFrameTree':'frame_tree'})[method]??'other';
      if(!setupToken)return this.transport.call(method,params,record.sessionId);
      return (async()=>{
        if(!this.browserTypeContextCurrent(setupToken))reject('browser_target_type_changed');
        const remaining=Number.isFinite(record.canonicalRecoveryDeadline)?record.canonicalRecoveryDeadline-performance.now():8000;
        if(remaining<=0)reject('canonical_recovery_budget_expired');
        const result=await this.transport.call(method,params,record.sessionId,Math.max(1,Math.min(8000,Math.floor(remaining),Number.isFinite(record.canonicalRecoveryDeadline)?350:8000)));
        if(!this.browserTypeContextCurrent(setupToken))reject('browser_target_type_changed');
        return result;
      })();
    };
    if(this.config.kind==='browser'){
      // This isolated browser inherits Windows' timezone and its English
      // startup/profile locale. Headers alone never establish runtime coverage.
      // Do not call Emulation setters: every target needs fresh actual metadata.
      // --accept-lang supplies request headers and navigator.language. The
      // validated English startup flags replace this redundant per-target setter.
      record.configured=false;record.metadataConfirmed=false;
      record.configurationMode=clear?'unconfigured':'system_runtime_pending';
      record.emulationApplied=false;record.systemRuntimeVerifiedAt=null;
      record.configurationGeneration=0;
      if(!worker&&PAGE_TYPES.has(record.type)){
        await call('Page.enable',{});const tree=await call('Page.getFrameTree',{});const id=tree.frameTree?.frame?.id;
        if(typeof id!=='string'||!id.length||id.length>256)reject('main_frame_identity_unavailable');record.mainFrameId=id;
      }
      if(!clear&&!worker){if(record.type==='page')this.status.counts.covered_pages++;else this.status.counts.covered_iframes++;}
      return;
    }
    await call('Emulation.setTimezoneOverride',{timezoneId:clear?'':this.config.timezone});
    await call('Emulation.setLocaleOverride',{locale:clear?'':this.config.locale});
    await call('Network.setExtraHTTPHeaders',{headers:clear?{}:{'Accept-Language':'en-US,en;q=0.9'}});
    record.configured=!clear;
    record.configurationMode=clear?'unconfigured':'emulated';record.emulationApplied=!clear;
    record.configurationGeneration=++this.configurationGeneration;
    this.topologyEvent('configuration_applied',{info:{targetId:record.targetId,type:record.type},sessionId:record.sessionId,detail:worker?'worker':'page'});
    if(!worker&&PAGE_TYPES.has(record.type)&&this.config.kind==='browser'){
      await call('Page.enable',{});const tree=await call('Page.getFrameTree',{});const id=tree.frameTree?.frame?.id;
      if(typeof id!=='string'||!id.length||id.length>256)reject('main_frame_identity_unavailable');record.mainFrameId=id;
    }
    if(clear)record.metadataConfirmed=false;
    if(!clear&&!worker){if(record.type==='page')this.status.counts.covered_pages++;else this.status.counts.covered_iframes++;}
  }
  async verifyMetadata(record,worker=false){
    if(this.config.kind==='browser'&&record.retiredConfirmed)return true;
    const verifyToken=this.config.kind==='browser'?this.browserTypeContext(record):null;
    let metadata=null;for(let attempt=0;attempt<6&&!this.stopped;attempt++){
      if(this.config.kind==='browser'&&this.browserWaitingSessions.has(record.sessionId)){await this.resumeBrowserRecord(record);if(this.stopped)return false;if(record.retiredConfirmed)return true;}
      metadata=await this.metadata(record,1000).catch(()=>null);
      if(this.config.kind==='browser'&&this.browserWaitingSessions.has(record.sessionId)){await this.resumeBrowserRecord(record);if(this.stopped)return false;if(record.retiredConfirmed)return true;metadata=null;}
      if(verifyToken&&!this.browserTypeContextCurrent(verifyToken)){this.recordTargetTypeDiagnostic('stale_result_discarded',record,record.type,'metadata',verifyToken.type);this.schedulePendingCheck();return false;}
      if(this.matches(metadata))break;
      if(this.config.kind==='browser'){
        if(await this.retireAbsentBrowserRecord(record,'metadata'))return true;
      }else{
        const current=await this.rootInventory().catch(()=>null);
        if(current&&!(current.targetInfos??[]).some(info=>info.targetId===record.targetId)){
          this.records.delete(record.sessionId);if(this.byTarget.get(record.targetId)===record.sessionId)this.byTarget.delete(record.targetId);this.workerRuntimeChecks.delete(record.sessionId);this.status.counts.retired_before_metadata++;if(!this.confirmUnpausedRetirements(current)){this.error('retired_attachment_inventory_invalid');return false;}return true;
        }
      }
      if(attempt<5)await sleep(150);
    }
    if(verifyToken&&!this.browserTypeContextCurrent(verifyToken)){this.recordTargetTypeDiagnostic('stale_result_discarded',record,record.type,'metadata',verifyToken.type);this.schedulePendingCheck();return false;}
    record.metadataConfirmed=this.matches(metadata);
    if(this.config.kind==='browser'&&record.metadataConfirmed&&record.configurationMode==='system_runtime_pending'&&!record.configured&&
        this.records.get(record.sessionId)===record&&this.byTarget.get(record.targetId)===record.sessionId){
      if(this.navigationWindow)this.invalidateNavigation('configuration_changed');
      record.configurationMode='system_runtime_verified';record.emulationApplied=false;
      record.systemRuntimeVerifiedAt=Date.now();record.configurationGeneration=++this.configurationGeneration;
      record.configured=true;
      this.topologyEvent('configuration_applied',{info:{targetId:record.targetId,type:record.type},sessionId:record.sessionId,detail:worker?'worker':'page'});
    }
    if(worker&&WORKER_TYPES.has(record.type)&&record.metadataConfirmed&&record.workerOverrideUnavailable&&!record.configured&&
        this.records.get(record.sessionId)===record&&this.byTarget.get(record.targetId)===record.sessionId){
      // Worker targets may not implement Emulation. A fresh exact runtime result
      // can establish verified inherited settings, never pretend an override ran.
      // This creates a new binding generation; old navigation proof cannot reuse it.
      if(this.navigationWindow)this.invalidateNavigation('configuration_changed');
      record.configurationMode='runtime_verified_inheritance';record.emulationApplied=false;
      record.workerInheritedVerifiedAt=Date.now();record.configurationGeneration=++this.configurationGeneration;
      record.configured=true;
    }
    if(worker){if(record.metadataConfirmed)this.status.counts.workers_inherited_verified++;else{this.status.counts.workers_unverified++;this.errors.add('worker_environment_unverified');}}
    else if(this.matches(metadata))this.status.counts.metadata_matches++;else{this.status.counts.metadata_mismatches++;this.errors.add('target_metadata_not_confirmed');}
    if(!record.metadataConfirmed&&this.config.kind==='browser')await this.failClosed('target_metadata_not_confirmed');
    return record.metadataConfirmed;
  }
  schedulePendingCheck(){
    if(this.stopped||this.pendingRecheckTimer)return;
    this.pendingRecheckTimer=setTimeout(()=>{this.pendingRecheckTimer=null;if(this.config.kind==='browser')this.queueReconcile('pending_reconcile');else if(!this.stopped)this.queue(()=>this.reconcile(),'pending_reconcile');},75);
    this.pendingRecheckTimer.unref?.();
  }
  configurationReady(record){
    if(this.config.kind==='browser'&&record.waitingForResume)return false;
    if(this.config.kind==='browser'&&record.pendingTypeChange)return false;
    if(record.configured!==true)return false;
    if(record.configurationMode==='emulated')return record.emulationApplied===true;
    if(record.configurationMode==='system_runtime_verified')return this.config.kind==='browser'&&TARGET_TYPES.has(record.type)&&
      record.emulationApplied===false&&record.metadataConfirmed===true&&Number.isFinite(record.systemRuntimeVerifiedAt)&&
      record.systemRuntimeVerifiedAt>0&&record.systemRuntimeVerifiedAt<=Date.now()&&
      this.records.get(record.sessionId)===record&&this.byTarget.get(record.targetId)===record.sessionId;
    return WORKER_TYPES.has(record.type)&&record.configurationMode==='runtime_verified_inheritance'&&
      record.emulationApplied===false&&record.workerOverrideUnavailable===true&&record.metadataConfirmed===true&&
      Number.isFinite(record.workerInheritedVerifiedAt);
  }
  sameVerifiedSessions(live){
    return live.length>0&&live.length===this.verifiedSessions.size&&live.every(record=>{
      const previous=this.verifiedSessions.get(record.sessionId);
      return this.configurationReady(record)&&record.metadataConfirmed&&previous?.targetId===record.targetId&&previous.type===record.type&&previous.generation===record.configurationGeneration;
    });
  }
  pendingScope(detail='other'){
    this.topologyEvent('sweep_scope_pending',{detail});
    this.invalidateNavigation('scope_changed');this.schedulePendingCheck();return false;
  }
  async checkEnvironment(){
    if(this.stopped)return false;if(this.environmentCheck)return this.environmentCheck;
    this.environmentCheck=(async()=>{
      const sweepStartedAt=Date.now(),sweepSequence=++this.observationSequence,sweepGeneration=this.configurationGeneration;
      if(this.config.kind==='browser'&&(this.browserWaitingSessions.size||this.browserObservedAliases.size||[...this.browserAliasSessions.values()].some(alias=>alias.pending)))return this.pendingScope('not_checked_or_configured');
      const records=[...this.records.values()].filter(r=>r.inScope&&TARGET_TYPES.has(r.type));
      if(!records.length&&this.config.kind!=='browser'){this.status.environment_check_ok=false;this.status.environment_check_pending=false;return false;}
      // A status-file heartbeat alone cannot renew network permission. Each
      // sweep performs the fixed account-free Runtime evaluation anew.
      const results=await Promise.all(records.map(async record=>{
        const typeToken=this.config.kind==='browser'?this.browserTypeContext(record):null,generation=record.configurationGeneration;
        let value=null,diagnostic='metadata_unavailable';const deadline=Date.now()+2000;
        while(!this.stopped&&Date.now()<deadline){
          value=await this.metadata(record,Math.max(1,Math.min(350,deadline-Date.now()))).catch(()=>null);
          if(typeToken&&!this.browserTypeContextCurrent(typeToken)){diagnostic='target_type_changed';break;}
          diagnostic=this.diagnostic(value);
          if(diagnostic===null||!this.records.has(record.sessionId))break;
          if(diagnostic!=='metadata_unavailable'){
            // A genuine returned field mismatch is not a navigation grace.
            if(!this.failing){this.status.counts.environment_check_failures++;this.status.last_environment_diagnostic=diagnostic;}
            this.status.environment_check_ok=false;
            if(this.config.kind==='browser')await this.failClosed('continuous_environment_mismatch');
            else this.errors.add('continuous_environment_mismatch');
            break;
          }
          if(Date.now()<deadline)await sleep(Math.min(75,deadline-Date.now()));
        }
        return {record,valid:diagnostic===null,diagnostic,typeToken,generation};
      }));
      if(this.stopped)return false;
      // A worker may end while its detached event waits behind this serialized
      // sweep. Consult a fresh browser-owned target list before classifying a
      // failed evaluation; a normally retired worker is not an environment
      // mismatch. Newly created, still-unconfigured targets do not renew a
      // lease until a later completed sweep has checked them too.
      let current;
      try{current=await this.rootInventory();}
      catch(error){if(this.config.kind==='browser'&&error?.code==='root_inventory_temporarily_unavailable')return this.pendingScope('unknown_inventory');throw error;}
      const inventory=this.config.kind==='browser'?this.browserInventoryInfos(current):(current.targetInfos??[]);
      if(this.config.kind==='browser'){
        for(const info of inventory){
          const record=this.records.get(this.byTarget.get(info.targetId));
          if((!TARGET_TYPES.has(info.type)&&this.scope(info))||(record&&TARGET_TYPES.has(record.type)&&!TARGET_TYPES.has(info.type))){
            this.recordTargetTypeDiagnostic('type_refused',record,info.type,'sweep');await this.failClosed('unsupported_executable_target');return false;
          }
          if(record&&(record.type!==info.type||record.pendingTypeChange)){
            if(!record.pendingTypeChange)this.beginBrowserTypeChange(record,info,'sweep');
            this.recordTargetTypeDiagnostic('inventory_mismatch',record,info.type,'sweep');
            return this.pendingScope('not_checked_or_configured');
          }
        }
        if(!this.confirmUnpausedRetirements(current)){await this.failClosed('target_type_retirement_not_verified');return false;}
      }
      const infos=inventory.filter(info=>this.scope(info));
      if(this.config.kind==='browser'&&infos.some(info=>!TARGET_TYPES.has(info.type))){await this.failClosed('unsupported_executable_target');return false;}
      const targetIds=new Set(infos.filter(info=>TARGET_TYPES.has(info.type)).map(info=>info.targetId));
      const live=[...this.records.values()].filter(r=>r.inScope&&TARGET_TYPES.has(r.type)&&targetIds.has(r.targetId));
      const checked=new Map(results.map(r=>[r.record.sessionId,r]));
      if(infos.some(info=>TARGET_TYPES.has(info.type)&&!this.byTarget.has(info.targetId)))return this.pendingScope('unknown_inventory');
      if(live.some(r=>!checked.has(r.sessionId)||!this.configurationReady(r)||!r.metadataConfirmed))return this.pendingScope('not_checked_or_configured');
      if(this.config.kind==='browser'&&(
        sweepGeneration!==this.configurationGeneration||live.length!==infos.length||new Set(live.map(r=>r.targetId)).size!==live.length||
        infos.some(info=>{
          const session=this.byTarget.get(info.targetId),r=this.records.get(session),check=checked.get(session);
          return !r||r.targetId!==info.targetId||r.sessionId!==session||r.type!==info.type||info.attached!==true||r.inScope!==true||r.pendingTypeChange||
            !this.configurationReady(r)||r.metadataConfirmed!==true||check?.record!==r||!check?.typeToken||
            !this.browserTypeContextCurrent(check.typeToken)||check.generation!==r.configurationGeneration;
        })))
        return this.pendingScope('not_checked_or_configured');
      if(live.some(r=>!checked.get(r.sessionId)?.valid)){
        // Execution contexts briefly disappear during ordinary navigation.
        // The last completed sweep retains only its original four-second
        // grant, and only for the identical verified session/target set. A
        // pending sweep never renews that timestamp or grants a new target.
        const checkedAt=Date.parse(this.status.environment_check_at),age=Date.now()-checkedAt;
        const retainsPriorGrant=this.config.kind==='browser'&&this.status.environment_check_ok===true&&this.sameVerifiedSessions(live)&&Number.isFinite(checkedAt)&&age>=0&&age<4000;
        this.status.environment_check_ok=retainsPriorGrant;this.status.environment_check_pending=true;this.status.counts.environment_pending_checks++;
        const missing=live.filter(record=>!checked.get(record.sessionId)?.valid);
        const navigationEligible=this.navigationWindow&&missing.every(record=>PAGE_TYPES.has(record.type)&&this.navigationWindow.participants.has(record.sessionId));
        if(this.navigationWindow&&!navigationEligible)this.invalidateNavigation('navigation_binding_unavailable');
        const navigation=navigationEligible&&this.navigationProof(current);
        this.status.last_environment_diagnostic=navigation?'navigation_configuration_pending':'metadata_unavailable';
        this.schedulePendingCheck();
        return false;
      }
      if(!live.length){this.status.environment_check_ok=false;this.status.environment_check_pending=false;return false;}
      if(this.pendingRecheckTimer){clearTimeout(this.pendingRecheckTimer);this.pendingRecheckTimer=null;}
      this.verifiedSessions=new Map(live.map(record=>[record.sessionId,{targetId:record.targetId,type:record.type,generation:record.configurationGeneration}]));
      this.status.environment_check_ok=true;this.status.environment_check_pending=false;this.status.environment_check_at=new Date().toISOString();this.clearScopeSuspension();
      if(this.navigationWindow&&!this.navigationWindow.loading.size&&this.navigationWindow.stoppedAt!==null&&sweepStartedAt>=this.navigationWindow.stoppedAt&&sweepSequence>this.navigationWindow.stoppedSequence){
        const window=this.navigationWindow;
        this.status.navigation_completions=[...this.status.navigation_completions,{schema:1,mode:'navigation_completed_runtime',started_at:new Date(window.startedAt).toISOString(),deadline_at:new Date(window.deadlineAt).toISOString(),first_runtime_checked_at:window.firstRuntimeCheckedAt,stopped_at:new Date(window.stoppedAt).toISOString(),runtime_checked_at:this.status.environment_check_at}].slice(-16);
        this.navigationWindow=null;this.status.navigation_guard=null;
      }
      this.status.last_environment_diagnostic='verified';this.status.counts.environment_checks++;return true;
    })();
    try{return await this.environmentCheck;}finally{this.environmentCheck=null;}
  }
  async failClosed(code){
    if(this.failing)return this.failing;if(this.stopped)return;
    this.errors.add(code);this.status.environment_check_ok=false;this.status.environment_check_pending=false;this.status.navigation_guard=null;if(this.navigationWindow)this.navigationWindow.invalidated=true;this.status.status='environment_failed';this.stopped=true;if(this.suspensionTimer)clearInterval(this.suspensionTimer);if(this.timer)clearInterval(this.timer);if(this.navigationTimer)clearInterval(this.navigationTimer);if(this.pendingRecheckTimer)clearTimeout(this.pendingRecheckTimer);this.stopEvents?.();
    this.failing=(async()=>{
      // Publish revocation before touching the owned child. The independent
      // gate watcher also refuses stale or missing metadata after a crash.
      try{await this.publish();}catch{this.errors.add('revocation_status_write_failed');}
      try{await this.transport.call('Browser.close',{},undefined,3000);}catch{this.errors.add('graceful_child_close_not_confirmed');}
      this.transport.close?.();try{await this.publish();}catch{this.errors.add('revocation_status_write_failed');}
    })();
    return this.failing;
  }
  recordWorkerRuntime(record,sequence,generation,ok){
    if(!WORKER_TYPES.has(record.type)||this.records.get(record.sessionId)!==record||this.byTarget.get(record.targetId)!==record.sessionId)return;
    const previous=this.workerRuntimeChecks.get(record.sessionId);
    // A delayed older response cannot replace a newer failed/successful check.
    if(previous&&previous.sequence>sequence)return;
    this.workerRuntimeChecks.set(record.sessionId,{targetId:record.targetId,type:record.type,sequence,generation,ok,at:Date.now()});
    if(!ok)this.publishImmediate();
  }
  workerEvidenceForNavigation(){
    const window=this.navigationWindow,nav=this.status.navigation_guard,now=Date.now();
    if(this.stopped||!window||window.invalidated||!nav||window.generation!==this.configurationGeneration||
        !Number.isSafeInteger(this.configurationGeneration)||this.configurationGeneration<=0||now>=window.deadlineAt||
        nav.started_at!==new Date(window.startedAt).toISOString()||nav.deadline_at!==new Date(window.deadlineAt).toISOString()||
        nav.first_runtime_checked_at!==window.firstRuntimeCheckedAt||nav.bindings_verified!==true)return null;
    const checked=Date.parse(nav.checked_at);
    if(!Number.isFinite(checked)||checked>now||now-checked>=4000)return null;
    const workers=[...this.records.values()].filter(r=>r.inScope&&WORKER_TYPES.has(r.type));
    const inherited=workers.filter(r=>r.configurationMode==='runtime_verified_inheritance');
    if(!workers.length||workers.length>64||!inherited.length)return null;
    let min=Infinity;
    for(const record of workers){
      const binding=window.bindings.get(record.sessionId),runtime=this.workerRuntimeChecks.get(record.sessionId);
      if(!this.configurationReady(record)||!record.metadataConfirmed||!binding||binding.targetId!==record.targetId||binding.type!==record.type||
          binding.generation!==record.configurationGeneration||this.byTarget.get(record.targetId)!==record.sessionId||
          !runtime||runtime.ok!==true||runtime.targetId!==record.targetId||runtime.type!==record.type||runtime.generation!==record.configurationGeneration||
          !Number.isFinite(runtime.at)||runtime.at>now||now-runtime.at>=4000)return null;
      min=Math.min(min,runtime.at);
    }
    return {schema:1,mode:'fresh_worker_runtime_same_navigation',navigation_started_at:nav.started_at,navigation_checked_at:nav.checked_at,
      navigation_deadline_at:nav.deadline_at,first_runtime_checked_at:nav.first_runtime_checked_at,configuration_generation:this.configurationGeneration,
      worker_count:workers.length,inherited_worker_count:inherited.length,min_runtime_checked_at:new Date(min).toISOString(),bindings_verified:true};
  }
  async metadata(record,timeout=1000){
    const worker=WORKER_TYPES.has(record.type),sequence=worker?++this.workerRuntimeSequence:0,generation=record.configurationGeneration;
    try{
      const result=await this.transport.call('Runtime.evaluate',{expression:METADATA_EXPRESSION,returnByValue:true,silent:true,includeCommandLineAPI:false},record.sessionId,timeout);
      if(result.exceptionDetails||typeof result.result?.value!=='string'||result.result.value.length>4096)reject('invalid_metadata_result');let metadata;try{metadata=JSON.parse(result.result.value);}catch{reject('invalid_metadata_result');}
      // Never persist supplied strings. Only compare approved fields and counts.
      if(worker)this.recordWorkerRuntime(record,sequence,generation,this.matches(metadata));
      return metadata;
    }catch(error){
      if(worker)this.recordWorkerRuntime(record,sequence,generation,false);
      throw error;
    }
  }
  diagnostic(data){
    if(!plain(data)||['timeZone','locale','language','languages','januaryOffset','julyOffset'].some(key=>!Object.hasOwn(data,key))||!Array.isArray(data.languages))return 'metadata_unavailable';
    if(data.timeZone!=='America/New_York')return 'timezone_mismatch';
    if(!['en-US','en_US'].includes(data.locale))return 'locale_mismatch';
    if(data.language!=='en-US'||data.languages[0]!=='en-US')return 'language_mismatch';
    if(data.januaryOffset!==300||data.julyOffset!==240)return 'daylight_offset_mismatch';
    return null;
  }
  matches(data){return this.diagnostic(data)===null;}
  async frameObservation(record){
    try{
      const tree=await this.transport.call('Page.getFrameTree',{},record.sessionId,1000);
      const frame=tree.frameTree?.frame;
      return{...documentHealthFromFrameTree(tree,this.config.domains),loaderId:typeof frame?.loaderId==='string'&&frame.loaderId.length<=256?frame.loaderId:null};
    }catch{return{isErrorDocument:null,securityOriginMatchesProtected:null,protectedHttpsDocument:null,unreachableDocument:null,loaderId:null};}
  }
  async fixedQaValue(record){
    const result=await this.transport.call('Runtime.evaluate',{expression:QA_EXPRESSION,returnByValue:true,silent:true,includeCommandLineAPI:false,awaitPromise:true},record.sessionId,5000);
    if(result.exceptionDetails||typeof result.result?.value!=='string'||result.result.value.length>8192)reject('invalid_qa_result');
    let value;try{value=JSON.parse(result.result.value);}catch{reject('invalid_qa_result');}
    if(!exact(value,['mainDocumentLoaded','environment','rtc'])||typeof value.mainDocumentLoaded!=='boolean')reject('invalid_qa_result');
    const rtc=rtcSummary(value.rtc),noRawAddress=['events','sdp','stats'].every(source=>RAW_RTC_KEYS.every(k=>rtc[source][k]===0));
    const unavailable=rtc.status==='api_unavailable'&&!rtc.gatheringComplete&&!rtc.statsAvailable&&['events','sdp','stats'].every(source=>RTC_COUNT_KEYS.every(k=>rtc[source][k]===0));
    const rtcAccepted=unavailable||(rtc.status==='complete'&&rtc.gatheringComplete&&rtc.statsAvailable&&noRawAddress);
    return{mainDocumentLoaded:value.mainDocumentLoaded,environmentMatches:this.matches(value.environment),rtc,rtcNoRawAddressObserved:noRawAddress,rtcAccepted};
  }
  // A document failure is an availability result, never a locale mismatch.
  // It must not close a user window, revoke or renew the caller's network lease.
  async inspectQa(){
    if(this.stopped)return;
    const records=[...this.records.values()].filter(record=>record.type==='page'&&record.inScope&&record.configured);
    let complete=records.length>0&&records.length<=16;
    const pages=await Promise.all(records.slice(0,16).map(async record=>{
      const before=await this.frameObservation(record);
      let value=null;
      // Error documents are not used to produce successful RTC/locale proof.
      if(before.isErrorDocument===false&&before.securityOriginMatchesProtected===true&&before.protectedHttpsDocument===true)value=await this.fixedQaValue(record).catch(()=>null);
      const after=await this.frameObservation(record);
      const bound=this.records.get(record.sessionId)===record&&before.loaderId!==null&&before.loaderId===after.loaderId;
      if(!bound)complete=false;
      const health={isErrorDocument:after.isErrorDocument,securityOriginMatchesProtected:after.securityOriginMatchesProtected,protectedHttpsDocument:after.protectedHttpsDocument,unreachableDocument:after.unreachableDocument,mainDocumentLoaded:bound&&value?.mainDocumentLoaded===true};
      const accepted=health.mainDocumentLoaded&&health.isErrorDocument===false&&health.securityOriginMatchesProtected===true&&health.protectedHttpsDocument===true&&health.unreachableDocument===false&&value?.environmentMatches===true&&value?.rtcAccepted===true;
      return{...health,environmentMatches:value?.environmentMatches===true,rtc:value?.rtc??null,rtcNoRawAddressObserved:value?.rtcNoRawAddressObserved===true,rtcAccepted:value?.rtcAccepted===true,accepted};
    }));
    const current=await this.rootInventory().catch(()=>null);
    const pageIds=(current?.targetInfos??[]).filter(info=>info.type==='page'&&this.scope(info)).map(info=>info.targetId);
    complete=!this.stopped&&complete&&current!==null&&pageIds.length===records.length&&records.every(record=>pageIds.includes(record.targetId));
    this.status.qa_diagnostic={schema:1,scope:'fixed-top-level-document-and-no-stun-rtc-v1',checked_at:new Date().toISOString(),complete_target_inventory:complete,accepted:complete&&pages.length>0&&pages.every(page=>page.accepted),pages};
    await this.publish();
  }

  async fixedLoadingValue(record){
    const result=await this.transport.call('Runtime.evaluate',{expression:LOADING_EXPRESSION,returnByValue:true,silent:true,includeCommandLineAPI:false},record.sessionId,1000);
    if(result.exceptionDetails||typeof result.result?.value!=='string'||result.result.value.length>4096)reject('invalid_loading_result');
    let value;try{value=JSON.parse(result.result.value);}catch{reject('invalid_loading_result');}
    return loadingSummary(value);
  }
  async inspectLoading(){
    if(this.stopped)return;
    const records=[...this.records.values()].filter(record=>record.type==='page'&&record.inScope&&record.configured);
    let complete=records.length>0&&records.length<=16;
    const pages=await Promise.all(records.slice(0,16).map(async record=>{
      const before=await this.frameObservation(record);
      let value=null;
      if(before.isErrorDocument===false&&before.securityOriginMatchesProtected===true&&before.protectedHttpsDocument===true)value=await this.fixedLoadingValue(record).catch(()=>null);
      const after=await this.frameObservation(record);
      const bound=this.records.get(record.sessionId)===record&&before.loaderId!==null&&before.loaderId===after.loaderId;
      if(!bound||value===null)complete=false;
      const empty={readyState:'unavailable',performanceAvailable:false,documentAgeMs:null,domInteractiveMs:null,domContentLoadedMs:null,loadEventEndMs:null,resourceCounts:Object.fromEntries(LOADING_RESOURCE_TYPES.map(k=>[k,0])),responseStatusCounts:Object.fromEntries(LOADING_STATUS_TYPES.map(k=>[k,0]))};
      return {isErrorDocument:after.isErrorDocument,securityOriginMatchesProtected:after.securityOriginMatchesProtected,protectedHttpsDocument:after.protectedHttpsDocument,unreachableDocument:after.unreachableDocument,...(bound&&value!==null?value:empty)};
    }));
    const current=await this.rootInventory().catch(()=>null);
    const pageIds=(current?.targetInfos??[]).filter(info=>info.type==='page'&&this.scope(info)).map(info=>info.targetId);
    complete=!this.stopped&&complete&&current!==null&&pageIds.length===records.length&&records.every(record=>pageIds.includes(record.targetId));
    this.status.loading_diagnostic={schema:1,scope:'fixed-top-level-loading-state-v1',checked_at:new Date().toISOString(),complete_target_inventory:complete,pages};
    await this.publish();
  }

  recordStartupNavigation(operation,result,attempt=1){
    if(!['navigate','reload'].includes(operation)||!Number.isInteger(attempt)||![1,2].includes(attempt))reject('invalid_startup_navigation_diagnostic');
    const code=startupNavigationCode(result);
    const previous=this.status.activation_navigation_diagnostic?.results??[];
    this.status.activation_navigation_diagnostic={schema:1,scope:'fixed-startup-navigation-results-v1',checked_at:new Date().toISOString(),results:[...previous,{operation,attempt,code}].slice(-32)};
    return code;
  }

  async waitForActivatedDocument(record,previousLoaderId){
    const deadline=Date.now()+this.documentHealthDeadlineMs;
    let observation=null;
    do{
      observation=await this.frameObservation(record);
      const fresh=previousLoaderId!==null&&observation.loaderId!==null&&previousLoaderId!==observation.loaderId;
      if(observation.isErrorDocument===true)return{...observation,freshDocument:fresh};
      if(fresh&&observation.securityOriginMatchesProtected===true&&observation.protectedHttpsDocument===true&&observation.isErrorDocument===false)return{...observation,freshDocument:true};
      if(Date.now()<deadline)await sleep(100);
    }while(!this.stopped&&Date.now()<deadline);
    return{...observation,freshDocument:false};
  }
  recordActivationDiagnostic(stage,code,urlClass='unavailable'){
    if(!ACTIVATION_STAGES.includes(stage)||!ACTIVATION_CODES.includes(code)||!ACTIVATION_URL_CLASSES.includes(urlClass))reject('invalid_activation_diagnostic');
    const events=this.status.activation_diagnostic?.events??[];
    this.status.activation_diagnostic={schema:1,scope:'fixed-activation-steps-v1',checked_at:new Date().toISOString(),events:[...events,{stage,code,url_class:urlClass}].slice(-32)};
  }
  activationBindingCurrent(record,binding){
    return !this.stopped&&this.records.get(binding.sessionId)===record&&this.byTarget.get(binding.targetId)===binding.sessionId&&record.sessionId===binding.sessionId&&record.targetId===binding.targetId&&record.mainFrameId===binding.mainFrameId&&record.configurationGeneration===binding.generation&&this.configurationReady(record)&&record.metadataConfirmed===true;
  }
  async activationWithinBudget(operation,deadline){
    const remaining=deadline-Date.now();if(remaining<=0)reject('activation_budget_expired');
    let timer;
    try{return await Promise.race([Promise.resolve().then(operation),new Promise((_,rejectPromise)=>{timer=setTimeout(()=>rejectPromise(new SafeError('activation_budget_expired')),remaining);})]);}
    finally{clearTimeout(timer);}
  }
  async assertActivationBinding(record,binding,deadline,{inventory=false}={}){
    if(Date.now()>=deadline)reject('activation_budget_expired');
    if(!this.activationBindingCurrent(record,binding))reject('activation_identity_changed');
    if(inventory){
      const current=await this.transport.call('Target.getTargets',{},undefined,Math.max(1,Math.min(1000,deadline-Date.now())));
      if(!plain(current)||!Array.isArray(current.targetInfos)||current.targetInfos.filter(info=>info?.targetId===binding.targetId&&info.type==='page'&&info.attached===true).length!==1)reject('activation_identity_changed');
    }
    if(Date.now()>=deadline)reject('activation_budget_expired');
    if(!this.activationBindingCurrent(record,binding))reject('activation_identity_changed');
  }
  async activationFrameObservation(record,binding,deadline){
    await this.assertActivationBinding(record,binding,deadline,{inventory:true});
    const tree=await this.transport.call('Page.getFrameTree',{},binding.sessionId,Math.max(1,Math.min(1000,deadline-Date.now())));
    const frame=tree?.frameTree?.frame;
    if(frame?.id!==binding.mainFrameId)reject('activation_identity_changed');
    await this.assertActivationBinding(record,binding,deadline);
    return {...documentHealthFromFrameTree(tree,this.config.domains),loaderId:typeof frame.loaderId==='string'&&frame.loaderId.length<=256?frame.loaderId:null};
  }
  async waitForBoundActivatedDocument(record,binding,previousLoaderId,totalDeadline,urlClass='unavailable'){
    const deadline=Math.min(totalDeadline,Date.now()+this.documentHealthDeadlineMs);let observation,readTimeouts=0;
    // A zero test deadline still permits one actual immediate observation. The
    // production overall deadline always remains authoritative.
    do{
      try{
        const readDeadline=this.documentHealthDeadlineMs===0?totalDeadline:deadline;
        observation=await this.activationFrameObservation(record,binding,readDeadline);
      }
      catch(error){
        // Only these account-free frame/inventory reads may be retried. A
        // timed-out navigation is never reissued; neither deadline is reset.
        if(error?.code!=='cdp_command_timeout')throw error;
        this.recordActivationDiagnostic('document_observation','cdp_command_timeout',urlClass);
        await this.assertActivationBinding(record,binding,totalDeadline);
        readTimeouts++;
        const remaining=Math.min(deadline,totalDeadline)-Date.now();
        if(remaining<=0)reject('activation_budget_expired');
        if(readTimeouts>=8)throw error;
        await sleep(Math.min(75,remaining));
        continue;
      }
      const fresh=previousLoaderId!==null&&observation.loaderId!==null&&previousLoaderId!==observation.loaderId;
      if(observation.isErrorDocument===true)return {...observation,freshDocument:fresh};
      if(fresh&&observation.securityOriginMatchesProtected===true&&observation.protectedHttpsDocument===true&&observation.isErrorDocument===false&&observation.unreachableDocument===false)return {...observation,freshDocument:true};
      if(Date.now()<deadline)await sleep(Math.min(100,deadline-Date.now()));
    }while(!this.stopped&&Date.now()<deadline);
    if(!observation)reject('activation_budget_expired');
    return {...observation,freshDocument:false};
  }
  async activateBrowser(){
    const deadline=Date.now()+this.activationBudgetMs,pages=[],bindings=[];let activated=0,stage='candidates',urlClass='unavailable';
    const candidates=[...this.records.values()].filter(record=>record.type==='page'&&record.inScope&&record.configured&&record.metadataConfirmed);
    this.recordActivationDiagnostic(stage,'started');
    if(!candidates.length||candidates.length>16){
      this.recordActivationDiagnostic(stage,'no_candidates');
      this.status.document_health={schema:1,scope:'activation-top-level-committed-documents-v1',checked_at:new Date().toISOString(),accepted:false,pages};
      await this.publish();return;
    }
    try{
      for(const record of candidates){
        stage='classify_url';urlClass=activationUrlClass(record.url,this.config.domains);
        if(!['blank','protected_https'].includes(urlClass)){this.recordActivationDiagnostic(stage,'skipped_url',urlClass);continue;}
        this.recordActivationDiagnostic(stage,'ok',urlClass);
        const binding={sessionId:record.sessionId,targetId:record.targetId,mainFrameId:record.mainFrameId,generation:record.configurationGeneration};bindings.push({record,binding});
        stage='before_document';this.recordActivationDiagnostic(stage,'started',urlClass);
        const before=await this.activationFrameObservation(record,binding,deadline);
        this.recordActivationDiagnostic(stage,'ok',urlClass);
        stage='navigation_command';this.recordActivationDiagnostic(stage,'started',urlClass);
        const operation=urlClass==='blank'?'navigate':'reload';
        try{
          const result=await this.transport.call(operation==='navigate'?'Page.navigate':'Page.reload',operation==='navigate'?{url:'https://claude.ai/'}:{ignoreCache:false},binding.sessionId,Math.max(1,Math.min(8000,deadline-Date.now())));
          await this.assertActivationBinding(record,binding,deadline);
          this.recordStartupNavigation(operation,result);this.recordActivationDiagnostic(stage,'ok',urlClass);
        }catch(error){
          // A command timeout does not cancel Chromium's in-flight navigation.
          // Observe its real committed document; never retry or infer success.
          if(error?.code!=='cdp_command_timeout')throw error;
          this.recordActivationDiagnostic(stage,'cdp_command_timeout',urlClass);
          await this.assertActivationBinding(record,binding,deadline,{inventory:true});
        }
        await this.publish();
        stage='document_observation';this.recordActivationDiagnostic(stage,'started',urlClass);
        const doc=await this.waitForBoundActivatedDocument(record,binding,before.loaderId,deadline,urlClass);
        const documentAccepted=doc.isErrorDocument===false&&doc.securityOriginMatchesProtected===true&&doc.protectedHttpsDocument===true&&doc.unreachableDocument===false&&doc.freshDocument===true;
        pages.push({isErrorDocument:doc.isErrorDocument,securityOriginMatchesProtected:doc.securityOriginMatchesProtected,protectedHttpsDocument:doc.protectedHttpsDocument,unreachableDocument:doc.unreachableDocument,freshDocument:doc.freshDocument});
        this.recordActivationDiagnostic(stage,documentAccepted?'ok':'document_not_accepted',urlClass);
        stage='metadata_check';this.recordActivationDiagnostic(stage,'started',urlClass);
        if(!await this.activationWithinBudget(()=>this.verifyMetadata(record),deadline))throw new SafeError('activation_metadata_not_confirmed');
        await this.assertActivationBinding(record,binding,deadline,{inventory:true});
        this.recordActivationDiagnostic(stage,'ok',urlClass);activated++;
      }
      stage='environment_check';this.recordActivationDiagnostic(stage,'started');
      const environmentReady=activated>0&&await this.activationWithinBudget(()=>this.checkEnvironment(),deadline);
      if(!environmentReady)throw new SafeError('activation_environment_not_confirmed');
      for(const {record,binding} of bindings)await this.assertActivationBinding(record,binding,deadline,{inventory:true});
      this.recordActivationDiagnostic(stage,'ok');
      const documentReady=pages.length>0&&pages.every(page=>page.isErrorDocument===false&&page.securityOriginMatchesProtected===true&&page.protectedHttpsDocument===true&&page.unreachableDocument===false&&page.freshDocument===true);
      this.status.activation_complete=environmentReady&&documentReady;
      this.recordActivationDiagnostic('complete',this.status.activation_complete?'ok':'document_not_accepted');
    }catch(error){
      this.status.activation_complete=false;
      const code=activationErrorCode(error),last=this.status.activation_diagnostic?.events.at(-1);
      if(code!=='cdp_command_timeout'||last?.stage!==stage||last?.code!==code||last?.url_class!==urlClass)this.recordActivationDiagnostic(stage,code,urlClass);
    }
    this.status.document_health={schema:1,scope:'activation-top-level-committed-documents-v1',checked_at:new Date().toISOString(),accepted:this.status.activation_complete,pages};
    await this.publish();
  }
  async activate(){
    if(this.stopped||this.status.activation_attempted)return;
    if(this.config.kind==='browser'){this.status.activation_attempted=true;await this.activateBrowser();return;}
    this.status.activation_attempted=true;
    const candidates=[...this.records.values()].filter(record=>record.type==='page'&&record.inScope&&record.configured&&record.metadataConfirmed);
    if(!candidates.length||candidates.length>16){this.status.document_health={schema:1,scope:'activation-top-level-committed-documents-v1',checked_at:new Date().toISOString(),accepted:false,pages:[]};await this.publish();return;}
    const pages=[];let activated=0;
    try{
      for(const record of candidates){
        if(!(this.config.kind==='browser'&&record.url==='about:blank')&&!(record.url.startsWith('https:')&&protectedUrl(record.url,this.config.domains)))continue;
        const before=await this.frameObservation(record);
        if(this.config.kind==='browser'&&record.url==='about:blank'){
          const result=await this.transport.call('Page.navigate',{url:'https://claude.ai/'},record.sessionId);
          this.recordStartupNavigation('navigate',result);await this.publish();
        }else{
          const result=await this.transport.call('Page.reload',{ignoreCache:false},record.sessionId);
          this.recordStartupNavigation('reload',result);await this.publish();
        }
        const doc=await this.waitForActivatedDocument(record,before.loaderId);
        pages.push({isErrorDocument:doc.isErrorDocument,securityOriginMatchesProtected:doc.securityOriginMatchesProtected,protectedHttpsDocument:doc.protectedHttpsDocument,unreachableDocument:doc.unreachableDocument,freshDocument:doc.freshDocument});
        if(!await this.verifyMetadata(record))throw new SafeError('activation_metadata_not_confirmed');
        activated++;
      }
      // Runtime readiness and actual document availability are separate facts.
      const environmentReady=activated>0&&await this.checkEnvironment();
      const documentReady=pages.length>0&&pages.every(page=>page.isErrorDocument===false&&page.securityOriginMatchesProtected===true&&page.protectedHttpsDocument===true&&page.unreachableDocument===false&&page.freshDocument===true);
      this.status.activation_complete=environmentReady&&documentReady;
    }catch{this.status.activation_complete=false;}
    this.status.document_health={schema:1,scope:'activation-top-level-committed-documents-v1',checked_at:new Date().toISOString(),accepted:this.status.activation_complete,pages};
    await this.publish();
  }
  async stop(){this.stopped=true;if(this.suspensionTimer)clearInterval(this.suspensionTimer);if(this.timer)clearInterval(this.timer);if(this.navigationTimer)clearInterval(this.navigationTimer);if(this.pendingRecheckTimer)clearTimeout(this.pendingRecheckTimer);if(this.navigationWindow)this.navigationWindow.invalidated=true;this.status.navigation_guard=null;this.stopEvents?.();this.status.status='stopping';this.status.environment_check_ok=false;this.status.environment_check_pending=false;try{await this.publish();}catch{this.errors.add('shutdown_status_write_failed');}try{await this.transport.call('Browser.close',{},undefined,3000);}catch{this.errors.add('graceful_child_close_not_confirmed');}this.transport.close?.();}
}

export const NATIVE_VERIFICATION_MODE='native_process_policy_v1';
export const NATIVE_ENVIRONMENT_SCOPE='native-browser-process-policy-v1';
const NATIVE_OBSERVATION_REASONS=new Set(['none','cdp_command_timeout','cdp_command_rejected','target_unavailable','inventory_unavailable','invalid_result','timezone_mismatch','locale_mismatch','language_mismatch','daylight_offset_mismatch','rtc_raw_address_observed','rtc_not_completed','private_pipe_unavailable']);

function nativeMetadataDiagnostic(value){
  if(!exact(value,['timeZone','locale','language','languages','januaryOffset','julyOffset'])||
      typeof value.timeZone!=='string'||typeof value.locale!=='string'||typeof value.language!=='string'||
      !Array.isArray(value.languages)||value.languages.length<1||value.languages.length>8||
      value.languages.some(x=>typeof x!=='string'||x.length>32)||
      !Number.isInteger(value.januaryOffset)||!Number.isInteger(value.julyOffset))return 'invalid_result';
  if(value.timeZone!=='America/New_York')return 'timezone_mismatch';
  if(!['en-US','en_US'].includes(value.locale))return 'locale_mismatch';
  if(value.language!=='en-US'||value.languages.length!==2||value.languages[0]!=='en-US'||value.languages[1]!=='en')return 'language_mismatch';
  if(value.januaryOffset!==300||value.julyOffset!==240)return 'daylight_offset_mismatch';
  return null;
}

function nativeRtcAccepted(rtc){
  const noRaw=['events','sdp','stats'].every(source=>RAW_RTC_KEYS.every(key=>rtc[source][key]===0));
  const unavailable=rtc.status==='api_unavailable'&&!rtc.gatheringComplete&&!rtc.statsAvailable&&['events','sdp','stats'].every(source=>RTC_COUNT_KEYS.every(key=>rtc[source][key]===0));
  return unavailable||(rtc.status==='complete'&&rtc.gatheringComplete&&rtc.statsAvailable&&noRaw);
}

/** Native process policy is a different permission contract, not fullscope CDP.
 * Python independently checks Windows timezone, owned process identity and exact
 * startup/proxy/WebRTC arguments. This class never pauses child targets, changes
 * runtime settings, or makes renderer responsiveness a continuous network lease.
 */
export class NativePolicyBrowserController {
  constructor(config,transport,writeStatus=async()=>{}){
    if(config?.kind!=='browser'||config.verification_mode!==NATIVE_VERIFICATION_MODE)reject('unsupported_verification_mode');
    this.config=config;this.transport=transport;this.writeStatus=writeStatus;this.stopped=false;this.timer=null;this.stopEvents=null;
    this.errors=new Set();this.records=new Map();this.byTarget=new Map();this.heartbeatBusy=false;this.passiveBusy=false;this.lastPassiveAt=0;this.activationTask=null;this.passiveCursor=0;
    this.status={schema_version:1,kind:'browser',verification_mode:NATIVE_VERIFICATION_MODE,environment_scope:NATIVE_ENVIRONMENT_SCOPE,
      process_pid:null,version:null,status:'starting',activation_attempted:false,activation_complete:false,protected_environment_verified:false,
      network_hold_managed_by_caller:true,environment_check_at:null,environment_check_ok:false,environment_check_pending:false,
      startup_runtime_checked_at:null,startup_runtime:null,controller_heartbeat_checked_at:null,
      last_environment_diagnostic:'not_checked',counts:{attached:0,metadata_matches:0,metadata_mismatches:0,command_errors:0,startup_checks:0,passive_checks:0,passive_unobserved:0},
      profile_scope:typeof config.profile==='string'&&norm(config.profile)===norm(path.join(ROOT,'browser-profiles','edge-claude'))?'claude-persistent':'qa-isolated',
      native_activation:{schema:1,scope:'fixed-protected-navigation-v1',command_state:'not_requested',checked_at:null},
      limits:['Native process policy is independently checked by the owning Python monitor; no continuous per-target runtime proof is claimed.',
        'The unchanged startup runtime timestamp records one about:blank metadata and no-STUN ICE observation.',
        'A passive renderer timeout is unobserved, not a new successful check or an IP change.',
        'Network admission also requires the independent four-second allowed-exit lease.']};
  }
  snapshot(){
    const now=new Date().toISOString();
    return {...this.status,at:now,controller_heartbeat_checked_at:now,counts:{...this.status.counts},error_codes:[...this.errors].sort()};
  }
  async publish(){await this.writeStatus(this.snapshot());}
  error(code){
    const fixed=new Set(['controller_start_failed','lifecycle_marker_failed','private_pipe_unavailable','publisher_unavailable','startup_runtime_not_verified','runtime_mismatch']);
    this.errors.add(fixed.has(code)?code:'controller_failed');this.status.environment_check_ok=false;this.status.status='environment_failed';
    this.status.last_environment_diagnostic=code==='runtime_mismatch'?'runtime_mismatch':'private_pipe_unavailable';
  }
  async heartbeat(){
    if(this.stopped||this.heartbeatBusy)return;this.heartbeatBusy=true;
    try{
      if(this.transport.closed===true)this.error('private_pipe_unavailable');
      await this.publish();
    }catch{this.error('publisher_unavailable');}
    finally{this.heartbeatBusy=false;}
  }
  observation(state,reason='none',type='page'){
    this.status.native_runtime_observation={schema:1,scope:'bounded-native-runtime-observation-v1',checked_at:new Date().toISOString(),state,
      reason:NATIVE_OBSERVATION_REASONS.has(reason)?reason:'invalid_result',target_type:TARGET_TYPES.has(type)?type:'other'};
    if(state==='unobserved')this.status.counts.passive_unobserved++;
  }
  async inventory(timeout=1000){
    const result=await this.transport.call('Target.getTargets',{},undefined,timeout);
    if(!plain(result)||!Array.isArray(result.targetInfos)||result.targetInfos.length>4096)reject('native_inventory_invalid');
    const ids=new Set();
    for(const info of result.targetInfos){
      if(!plain(info)||typeof info.targetId!=='string'||!info.targetId||info.targetId.length>256||ids.has(info.targetId)||typeof info.type!=='string'||!info.type||info.type.length>64||typeof info.url!=='string'||info.url.length>65536)reject('native_inventory_invalid');
      ids.add(info.targetId);
    }
    for(const [sid,record] of this.records)if(!ids.has(record.targetId)){this.records.delete(sid);if(this.byTarget.get(record.targetId)===sid)this.byTarget.delete(record.targetId);}
    return result.targetInfos;
  }
  async releasePassiveRecords(){
    const pinned=this.bootstrapRecord?.sessionId;
    for(const [sid,record] of [...this.records]){
      if(sid===pinned)continue;
      try{await this.transport.call('Target.detachFromTarget',{sessionId:sid},undefined,500);}
      catch(error){if(['private_pipe_closed','private_pipe_write_failed','private_pipe_failed','child_exited'].includes(error?.code))this.error('private_pipe_unavailable');}
      this.records.delete(sid);if(this.byTarget.get(record.targetId)===sid)this.byTarget.delete(record.targetId);
    }
  }
  async attach(info){
    if(this.byTarget.has(info.targetId))return this.records.get(this.byTarget.get(info.targetId));
    if(this.records.size>=64)reject('native_observation_limit');
    const response=await this.transport.call('Target.attachToTarget',{targetId:info.targetId,flatten:true},undefined,1000);
    if(typeof response.sessionId!=='string'||!response.sessionId||response.sessionId.length>256)reject('native_attachment_invalid');
    const record={sessionId:response.sessionId,targetId:info.targetId,type:info.type};
    this.records.set(record.sessionId,record);this.byTarget.set(record.targetId,record.sessionId);this.status.counts.attached++;return record;
  }
  async evaluate(record,expression,qa=false,timeout=1000){
    const params={expression,returnByValue:true,silent:true,includeCommandLineAPI:false,...(qa?{awaitPromise:true}:{})};
    const result=await this.transport.call('Runtime.evaluate',params,record.sessionId,timeout);
    if(result.exceptionDetails||typeof result.result?.value!=='string'||result.result.value.length>(qa?8192:4096))reject('invalid_native_result');
    let value;try{value=JSON.parse(result.result.value);}catch{reject('invalid_native_result');}return value;
  }
  async bootstrap(){
    const wall=Date.now(),mono=performance.now();
    const initial=await this.inventory(),pages=initial.filter(info=>info.type==='page');
    if(pages.length!==1||pages[0].url!=='about:blank'||initial.some(info=>TARGET_TYPES.has(info.type)&&info.targetId!==pages[0].targetId))reject('native_policy_requires_blank_start');
    const record=await this.attach(pages[0]);this.bootstrapRecord=record;
    const before=Date.now(),beforeMono=performance.now();
    const value=await this.evaluate(record,QA_EXPRESSION,true,3500);
    const checkedAt=Date.now();
    if(checkedAt<before||checkedAt-before>=4000||performance.now()-beforeMono>=4000||checkedAt<wall||performance.now()-mono<0)reject('native_startup_observation_stale');
    if(!exact(value,['mainDocumentLoaded','environment','rtc'])||typeof value.mainDocumentLoaded!=='boolean')reject('invalid_native_result');
    const diagnostic=nativeMetadataDiagnostic(value.environment),rtc=rtcSummary(value.rtc);
    if(diagnostic||!nativeRtcAccepted(rtc)){
      this.status.counts.metadata_mismatches++;this.status.last_environment_diagnostic=diagnostic??'rtc_not_completed';reject('native_startup_mismatch');
    }
    const after=await this.inventory();
    if(!after.some(info=>info.targetId===record.targetId&&info.type==='page'&&info.url==='about:blank')||after.some(info=>TARGET_TYPES.has(info.type)&&info.targetId!==record.targetId)||Date.now()<checkedAt||Date.now()-checkedAt>=4000||performance.now()-beforeMono>=4000)reject('native_startup_binding_changed');
    const stamp=new Date(checkedAt).toISOString();
    // These facts are written exactly once. Ordinary publication, navigation,
    // new targets and passive probes never refresh or mutate this payload.
    this.status.startup_runtime={schema:1,scope:'initial-about-blank-no-stun-v1',checked_at:stamp,
      environment:JSON.parse(JSON.stringify(value.environment)),rtc,accepted:true};
    this.status.startup_runtime_checked_at=stamp;this.status.environment_check_at=stamp;this.status.environment_check_ok=true;
    this.status.last_environment_diagnostic='native_startup_verified';this.status.counts.startup_checks++;this.status.counts.metadata_matches++;
  }
  async start({monitor=true}={}){
    this.stopEvents=this.transport.on(msg=>{
      if(msg.method==='PrivatePipe.failed'){this.error('private_pipe_unavailable');void this.publish().catch(()=>{});}
      if(msg.method==='Target.detachedFromTarget'){
        const sid=msg.params?.sessionId,record=this.records.get(sid);
        if(record){this.records.delete(sid);if(this.byTarget.get(record.targetId)===sid)this.byTarget.delete(record.targetId);}
      }
    });
    if(monitor)this.timer=setInterval(()=>{void this.heartbeat();if(!this.passiveBusy&&this.status.startup_runtime&&Date.now()-this.lastPassiveAt>=2000)void this.observeRuntime();},200);
    const version=await this.transport.call('Browser.getVersion',{},undefined,2000);
    if(typeof version.product==='string'&&/^[A-Za-z][A-Za-z ]*\/[0-9.]+$/.test(version.product))this.status.version=version.product;
    await this.bootstrap();this.status.status='monitoring';await this.publish();
  }
  async observeRuntime({qa=false}={}){
    if(this.stopped||this.passiveBusy||!this.status.startup_runtime||this.errors.size)return;
    this.passiveBusy=true;this.lastPassiveAt=Date.now();let count=0,matched=0,unobserved=0,rtcAccepted=null,loaded=null;
    try{
      const infos=await this.inventory();
      // Manual page attachment only. No autoattach/renderer pause, worker keep-
      // alive sessions or speculative-target configuration is introduced here.
      const all=infos.filter(info=>info.type==='page'&&(info.url==='about:blank'||protectedUrl(info.url,this.config.domains)));
      const offset=all.length?this.passiveCursor%all.length:0;
      const candidates=[...all.slice(offset),...all.slice(0,offset)].slice(0,8);this.passiveCursor=offset+candidates.length;
      if(!candidates.length){this.observation('unobserved','target_unavailable');unobserved++;}
      for(const info of candidates){
        count++;this.status.counts.passive_checks++;
        try{
          const record=await this.attach(info),raw=await this.evaluate(record,qa?QA_EXPRESSION:METADATA_EXPRESSION,qa,qa?3500:750);
          if(this.stopped)return;
          const data=qa?raw?.environment:raw,reason=nativeMetadataDiagnostic(data);
          if(reason==='invalid_result'){this.observation('unobserved','invalid_result');unobserved++;continue;}
          if(reason){this.status.counts.metadata_mismatches++;this.observation('mismatch',reason);this.error('runtime_mismatch');break;}
          if(qa){
            if(!exact(raw,['mainDocumentLoaded','environment','rtc'])||typeof raw.mainDocumentLoaded!=='boolean')reject('invalid_native_result');
            const rtc=rtcSummary(raw.rtc);rtcAccepted=nativeRtcAccepted(rtc);loaded=raw.mainDocumentLoaded;
            const rawAddress=['events','sdp','stats'].some(source=>RAW_RTC_KEYS.some(key=>rtc[source][key]>0));
            if(rawAddress){this.status.counts.metadata_mismatches++;this.observation('mismatch','rtc_raw_address_observed');this.error('runtime_mismatch');break;}
            if(!rtcAccepted){this.observation('unobserved','rtc_not_completed');unobserved++;continue;}
          }
          matched++;this.status.counts.metadata_matches++;this.observation('matched');
        }catch(error){
          if(['private_pipe_closed','private_pipe_write_failed','private_pipe_failed','child_exited'].includes(error?.code)){this.error('private_pipe_unavailable');break;}
          this.observation('unobserved',['cdp_command_timeout','cdp_command_rejected'].includes(error?.code)?error.code:'invalid_result');unobserved++;
        }
      }
    }catch(error){
      if(['private_pipe_closed','private_pipe_write_failed','private_pipe_failed','child_exited'].includes(error?.code))this.error('private_pipe_unavailable');
      else{this.observation('unobserved','inventory_unavailable');unobserved++;}
    }finally{
      if(qa)this.status.native_qa_diagnostic={schema:1,scope:'passive-fixed-native-metadata-no-stun-v1',checked_at:new Date().toISOString(),observed_targets:count,matched_targets:matched,unobserved_targets:unobserved,rtc_accepted:rtcAccepted,main_document_loaded:loaded};
      if(!this.stopped)await this.releasePassiveRecords();
      this.passiveBusy=false;if(!this.stopped)await this.publish().catch(()=>this.error('publisher_unavailable'));
    }
  }
  async activate(){
    if(this.stopped||this.status.activation_attempted||!this.status.startup_runtime||this.errors.size)return;
    this.status.activation_attempted=true;
    let record=this.bootstrapRecord;
    try{
      const infos=await this.inventory(),info=infos.find(item=>item.targetId===record?.targetId);
      if(!info||info.type!=='page'||!['blank','protected_https'].includes(activationUrlClass(info.url,this.config.domains)))reject('native_activation_target_unavailable');
      record=await this.attach(info);
      // Native policy readiness and document availability are intentionally
      // distinct. The sole fixed navigation can remain in flight without
      // invalidating the independent process-policy or four-second IP lease.
      this.status.activation_complete=true;
      this.status.native_activation={schema:1,scope:'fixed-protected-navigation-v1',command_state:'in_flight',checked_at:new Date().toISOString()};
      const command=this.transport.call('Page.navigate',{url:'https://claude.ai/'},record.sessionId,8000);
      this.activationTask=command.then(async result=>{
        const code=startupNavigationCode(result);
        this.status.native_activation={schema:1,scope:'fixed-protected-navigation-v1',command_state:code==='ok'?'accepted':'failed',checked_at:new Date().toISOString()};
        this.status.activation_navigation_diagnostic={schema:1,scope:'fixed-startup-navigation-results-v1',checked_at:new Date().toISOString(),results:[{operation:'navigate',attempt:1,code}]};
        await this.publish();
      }).catch(async error=>{
        if(['private_pipe_closed','private_pipe_write_failed','private_pipe_failed','child_exited'].includes(error?.code))this.error('private_pipe_unavailable');
        this.status.native_activation={schema:1,scope:'fixed-protected-navigation-v1',command_state:'unobserved',checked_at:new Date().toISOString()};
        await this.publish().catch(()=>this.error('publisher_unavailable'));
      });
      await this.publish();
    }catch(error){
      if(['private_pipe_closed','private_pipe_write_failed','private_pipe_failed','child_exited'].includes(error?.code))this.error('private_pipe_unavailable');
      this.status.native_activation={schema:1,scope:'fixed-protected-navigation-v1',command_state:'failed',checked_at:new Date().toISOString()};await this.publish();
    }
  }
  async inspectQa(){return this.observeRuntime({qa:true});}
  async inspectLoading(){
    if(this.stopped||this.passiveBusy)return;this.passiveBusy=true;const pages=[];
    try{
      const infos=await this.inventory(),candidates=infos.filter(info=>info.type==='page'&&protectedUrl(info.url,this.config.domains)).slice(0,8);
      for(const info of candidates){
        try{
          const record=await this.attach(info),raw=await this.evaluate(record,NATIVE_LOADING_EXPRESSION,false,750);
          const healthKeys=['isErrorDocument','securityOriginMatchesProtected','protectedHttpsDocument'];
          if(!exact(raw,[...healthKeys,'readyState','performanceAvailable','documentAgeMs','domInteractiveMs','domContentLoadedMs','loadEventEndMs','resourceCounts','responseStatusCounts'])||healthKeys.some(key=>raw[key]!==null&&typeof raw[key]!=='boolean'))reject('invalid_native_result');
          const loading=loadingSummary(Object.fromEntries(Object.entries(raw).filter(([key])=>!healthKeys.includes(key))));
          pages.push({state:'observed',...Object.fromEntries(healthKeys.map(key=>[key,raw[key]])),...loading});
        }catch(error){
          if(['private_pipe_closed','private_pipe_write_failed','private_pipe_failed','child_exited'].includes(error?.code))this.error('private_pipe_unavailable');
          pages.push({state:'unobserved'});
        }
      }
    }catch(error){if(['private_pipe_closed','private_pipe_write_failed','private_pipe_failed','child_exited'].includes(error?.code))this.error('private_pipe_unavailable');}
    finally{
      this.status.native_loading_diagnostic={schema:1,scope:'passive-native-loading-v1',checked_at:new Date().toISOString(),pages};
      if(!this.stopped)await this.releasePassiveRecords();this.passiveBusy=false;if(!this.stopped)await this.publish().catch(()=>this.error('publisher_unavailable'));
    }
  }
  enableTopologyDiagnostics(){}
  async flush(){await this.publish();}
  async stop(){
    if(this.stopped)return;this.stopped=true;if(this.timer)clearInterval(this.timer);this.stopEvents?.();this.status.status='stopping';this.status.environment_check_ok=false;
    await this.publish().catch(()=>{});try{await this.transport.call('Browser.close',{},undefined,3000);}catch{this.errors.add('graceful_child_close_not_confirmed');}this.transport.close?.();
  }
}

/** Consume only this controller's exact empty marker. Never follow a link. */
export async function consumeLifecycleMarker(statusPath,suffix){
  if(!['.activate','.stop','.qa','.topology','.loading'].includes(suffix))reject('invalid_lifecycle_suffix');
  const marker=statusPath+suffix;
  const parent=path.dirname(marker);
  if(norm(await fs.realpath(parent))!==norm(path.resolve(parent)))reject('redirected_lifecycle_directory');
  let stat;try{stat=await fs.lstat(marker);}catch(error){if(error.code==='ENOENT')return false;throw new SafeError('lifecycle_marker_unreadable');}
  if(!stat.isFile()||stat.isSymbolicLink()||stat.size!==0)reject('invalid_lifecycle_marker');
  const claimed=marker+'.consumed-'+randomUUID();
  await fs.rename(marker,claimed);
  // Recheck after claiming, so a raced-in link is retained, never followed/deleted.
  const claimedStat=await fs.lstat(claimed);
  if(!claimedStat.isFile()||claimedStat.isSymbolicLink()||claimedStat.size!==0||norm(await fs.realpath(claimed))!==norm(path.resolve(claimed)))reject('invalid_lifecycle_marker');
  await fs.unlink(claimed);
  return true;
}

async function discoverAuthorizedExecutables(candidate){
  if(process.platform!=='win32')reject('windows_required');
  const script=`$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$candidate=$env:CLAUDE_ENV_CANDIDATE_EXE;$valid=@();$pkg=@(Get-AppxPackage -Name Claude | Where-Object {$_.PackageFamilyName -eq 'Claude_pzs8sxrjxfjjc'});foreach($p in $pkg){$valid+=@{kind='electron';exe=(Join-Path $p.InstallLocation 'app/Claude.exe');publisher='Anthropic, PBC'}};$chrome=Join-Path $env:ProgramFiles 'Google/Chrome/Application/chrome.exe';$edge=Join-Path \${env:ProgramFiles(x86)} 'Microsoft/Edge/Application/msedge.exe';$valid+=@{kind='browser';exe=$chrome;publisher='Google LLC'};$valid+=@{kind='browser';exe=$edge;publisher='Microsoft Corporation'};$found=@($valid | Where-Object {[StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($_.exe),[IO.Path]::GetFullPath($candidate))});if($found.Count -ne 1){throw 'unapproved'};$sig=Get-AuthenticodeSignature -LiteralPath $candidate;if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -ne $found[0].publisher){throw 'signature'};$found | ForEach-Object {[pscustomobject]@{kind=$_.kind;exe=$_.exe}} | ConvertTo-Json -Compress`;
  const queryEnv={...process.env,CLAUDE_ENV_CANDIDATE_EXE:candidate};for(const key of Object.keys(queryEnv)){if(key.toLowerCase()==='psmodulepath')delete queryEnv[key];}queryEnv.PSModulePath=path.join(process.env.SystemRoot,'System32','WindowsPowerShell','v1.0','Modules');
  const result=await new Promise((resolve,rejectPromise)=>{const proc=spawn('powershell.exe',['-NoProfile','-NonInteractive','-Command',script],{env:queryEnv,stdio:['ignore','pipe','ignore'],windowsHide:true});let stdout='';const timer=setTimeout(()=>{proc.kill();rejectPromise(new SafeError('executable_validation_timeout'));},20000);proc.stdout.on('data',chunk=>{stdout+=chunk;if(stdout.length>32768){proc.kill();rejectPromise(new SafeError('executable_validation_failed'));}});proc.once('error',()=>{clearTimeout(timer);rejectPromise(new SafeError('executable_validation_failed'));});proc.once('exit',code=>{clearTimeout(timer);if(code!==0)rejectPromise(new SafeError('executable_validation_failed'));else resolve(stdout);});});
  let value;try{value=JSON.parse(result.replace(/^\uFEFF/,''));}catch{reject('executable_validation_failed');}return Array.isArray(value)?value:[value];
}

async function ensurePhysicalDirectory(directory){
  await fs.mkdir(directory,{recursive:true});const real=await fs.realpath(directory);if(norm(real)!==norm(path.resolve(directory)))reject('redirected_runtime_directory');return real;
}

async function main(){
  if(path.basename(path.dirname(BASE))==='candidates')reject('candidate_not_deployed');
  const argv=process.argv.slice(2);if(argv.length===1&&argv[0]==='--help'){console.log('Usage: node claude_environment_controller.mjs --config <strict JSON file>\nCaller must hold network gate before launch. No application is started when this module is imported.');return;}
  if(argv.length!==2||argv[0]!=='--config')reject('invalid_cli_arguments');
  const configPath=path.resolve(argv[1]);const stat=await fs.stat(configPath);if(stat.size>32768)reject('configuration_too_large');const input=parseJsonStrict(await fs.readFile(configPath,'utf8'));
  if(typeof input?.exe!=='string')reject('invalid_executable');const authorized=await discoverAuthorizedExecutables(input.exe);const config=validateConfig(input,authorized);
  const realExe=await fs.realpath(config.exe);if(norm(realExe)!==norm(config.exe))reject('redirected_executable');
  if(config.profile)await ensurePhysicalDirectory(config.profile);
  const statusRoot=await ensurePhysicalDirectory(path.join(BASE,'runs'));const statusPath=path.join(statusRoot,`environment-${config.kind}-${process.pid}.json`);
  const publisher=new StatusPublisher();
  const writeStatus=report=>publisher.publish(report);
  // No TCP/HTTP server exists here. Only this child inherits protocol handles.
  const childEnv={...process.env};const proxy=config.args.find(arg=>arg.startsWith('--proxy-server=')).slice('--proxy-server='.length);
  for(const key of ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy'])childEnv[key]=proxy;
  childEnv.NO_PROXY=childEnv.no_proxy='';delete childEnv.ELECTRON_RUN_AS_NODE;delete childEnv.NODE_OPTIONS;
  const child=spawn(config.exe,[...config.args,'--remote-debugging-pipe'],{env:childEnv,stdio:['ignore','ignore','ignore','pipe','pipe'],windowsHide:config.args.includes('--headless=new')});
  const transport=new PrivatePipeTransport(child);const controller=config.kind==='browser'&&config.verification_mode===NATIVE_VERIFICATION_MODE?new NativePolicyBrowserController(config,transport,writeStatus):new EnvironmentController(config,transport,writeStatus);controller.status.process_pid=child.pid??null;
  let stopping=false,lifecycleTimer=null,lifecycleBusy=false;
  const shutdown=async()=>{if(stopping)return;stopping=true;if(lifecycleTimer)clearInterval(lifecycleTimer);await controller.stop();for(let n=0;n<80&&child.exitCode===null;n++)await sleep(100);controller.status.status=child.exitCode===null?'child_shutdown_not_confirmed':'stopped';await controller.publish().catch(()=>{});await publisher.close();if(child.exitCode===null){process.exitCode=2;child.unref();}};
  process.once('SIGINT',()=>void shutdown());process.once('SIGTERM',()=>void shutdown());
  child.once('exit',()=>{if(!stopping){stopping=true;if(lifecycleTimer)clearInterval(lifecycleTimer);controller.stopped=true;if(controller.timer)clearInterval(controller.timer);controller.status.status='child_exited';controller.status.environment_check_ok=false;void controller.publish().catch(()=>{}).finally(()=>publisher.close());}});
  try{
    await controller.start();
    lifecycleTimer=setInterval(async()=>{
      if(stopping||lifecycleBusy)return;lifecycleBusy=true;
      try{
        if(await consumeLifecycleMarker(statusPath,'.stop')){await shutdown();return;}
        if(await consumeLifecycleMarker(statusPath,'.activate'))await controller.activate();
        if(await consumeLifecycleMarker(statusPath,'.qa'))await controller.inspectQa();
        if(await consumeLifecycleMarker(statusPath,'.loading'))await controller.inspectLoading();
        if(await consumeLifecycleMarker(statusPath,'.topology')){controller.enableTopologyDiagnostics();await controller.publish();}
      }catch{controller.error('lifecycle_marker_failed');await controller.publish();}
      finally{lifecycleBusy=false;}
    },200);
  }catch{controller.error('controller_start_failed');await shutdown();process.exitCode=2;}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){main().catch(error=>{console.error('Claude environment controller stopped: '+(error instanceof SafeError?error.code:'unexpected_startup_failure'));process.exitCode=2;});}
