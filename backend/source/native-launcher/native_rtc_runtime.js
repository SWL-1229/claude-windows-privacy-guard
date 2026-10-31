// Installed only through Claude's official local main-process debugger.
// Uses Electron's native policy API; never replaces page WebRTC APIs.
(function installNativeRtc(config) {
  'use strict';
  const E=process.mainModule.require('electron');
  const fs=process.getBuiltinModule('fs');
  const key=Symbol.for('claude.network.guard.native.rtc.v1');
  const policy='disable_non_proxied_udp';
  if (!config || config.pid!==process.pid || !/^[0-9a-f]{16}$/.test(config.creation) ||
      !/^[0-9a-f]{32}$/.test(config.nonce) || !/^[0-9a-f]{64}$/.test(config.sourceSha256) ||
      config.output!=='C:\\Users\\lenovo\\.claude-network-guard\\native-launcher\\native-rtc-runtime.json') {
    throw Error('rtc_configuration_invalid');
  }
  const prior=globalThis[key];
  if (prior && prior.nonce!==config.nonce) throw Error('rtc_existing_generation');
  if (prior) return prior.summary();
  let writes=0,failures=0,writeFailures=0;
  const apply=w=>{if(!w.isDestroyed())w.setWebRTCIPHandlingPolicy(policy);};
  // Event is synchronous; new Electron web contents receive the policy before
  // this listener returns. External applications and non-Electron workers are
  // not claimed as covered.
  const listener=(_event,w)=>{try{apply(w);}catch{failures++;}};
  E.app.on('web-contents-created',listener);
  try{for(const w of E.webContents.getAllWebContents())apply(w);}
  catch(e){E.app.removeListener('web-contents-created',listener);throw e;}
  const summary=()=>{
    const contents=E.webContents.getAllWebContents().filter(w=>!w.isDestroyed());
    const rows=contents.map(w=>({id:w.id,policy:w.getWebRTCIPHandlingPolicy()}));
    return {schema:1,kind:'native-electron-rtc-policy-v1',pid:process.pid,
      creation:config.creation,nonce:config.nonce,sourceSha256:config.sourceSha256,
      listenerAttached:E.app.listeners('web-contents-created').includes(listener),
      ok:failures===0&&E.app.listeners('web-contents-created').includes(listener)&&rows.length>0&&rows.every(r=>r.policy===policy),
      policy,webContents:rows,failures,writes,writeFailures,epoch:Date.now()};
  };
  const tick=()=>{
    let temp;
    try{
      const value=summary();
      temp=config.output+'.'+config.nonce+'.tmp';
      fs.writeFileSync(temp,JSON.stringify(value),{encoding:'utf8',flag:'w'});
      fs.renameSync(temp,config.output);writes++;
    }catch{writeFailures++;if(temp){try{fs.unlinkSync(temp);}catch{}}}
  };
  const interval=setInterval(tick,250);interval.unref();
  const value={nonce:config.nonce,summary,listener,interval};
  Object.defineProperty(globalThis,key,{value,configurable:false,writable:false});
  tick();
  return summary();
})
