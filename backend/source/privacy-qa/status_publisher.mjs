/** Owning controller's private child publisher. No listening socket or file API. */
import {spawn} from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const QA=path.dirname(fileURLToPath(import.meta.url)),ROOT=path.dirname(QA),MAX_FRAME=32768;
export class StatusPublisher{
  constructor({spawnChild=spawn,readRuntime=()=>fs.readFile(path.join(ROOT,'environment-runtime.json'),'utf8'),setTimer=setTimeout,clearTimer=clearTimeout}={}){
    this.spawnChild=spawnChild;this.readRuntime=readRuntime;this.child=null;this.sequence=0;this.pending=new Map();this.buffer='';this.failed=null;this.ending=false;this.serial=Promise.resolve();
    this.setTimer=setTimer;this.clearTimer=clearTimer;this.publicationEpoch=0;
    this.ready=this.start();this.ready.catch(()=>{});
  }
  async start(){
    let runtime;try{runtime=JSON.parse(await this.readRuntime());}catch{throw this.fail('publisher_runtime_unavailable');}
    if(this.ending)throw this.fail('publisher_closed');
    if(typeof runtime.python_executable!=='string'||!path.win32.isAbsolute(runtime.python_executable))throw this.fail('publisher_runtime_invalid');
    this.child=this.spawnChild(runtime.python_executable,['-B',path.join(QA,'status_publisher.py'),'--controller-pid',String(process.pid)],{cwd:ROOT,stdio:['pipe','pipe','ignore'],windowsHide:true});
    return new Promise((resolve,reject)=>{
      this.readyResolve=resolve;this.readyReject=reject;this.readyTimer=this.setTimer(()=>this.fail('publisher_start_timeout'),8000);
      this.child.stdout.setEncoding('utf8');this.child.stdout.on('data',s=>this.receive(s));
      this.child.stdin.on('error',()=>this.fail('publisher_pipe_failed'));
      this.child.once('error',()=>this.fail('publisher_start_failed'));
      this.child.once('exit',()=>{if(!this.ending||this.pending.size)this.fail('publisher_exited');});
    });
  }
  fail(code){
    if(this.failed)return this.failed;this.failed=Error(code);this.clearTimer(this.readyTimer);this.readyReject?.(this.failed);
    for(const item of this.pending.values()){this.clearTimer(item.timer);item.reject(this.failed);}this.pending.clear();
    if(this.child&&!this.ending&&this.child.exitCode===null){try{this.child.kill();}catch{}}
    return this.failed;
  }
  receive(chunk){
    this.buffer+=chunk;if(Buffer.byteLength(this.buffer)>MAX_FRAME){this.fail('publisher_response_limit');return;}
    let end;while((end=this.buffer.indexOf('\n'))>=0){const line=this.buffer.slice(0,end);this.buffer=this.buffer.slice(end+1);let message;try{message=JSON.parse(line);}catch{this.fail('publisher_response_invalid');return;}
      if(message.ready===true){if(!this.readyResolve||Object.keys(message).sort().join(',')!=='controller_creation,pid,ready'||message.pid!==this.child.pid||typeof message.controller_creation!=='string'||!/^[0-9a-f]{16}$/.test(message.controller_creation)){this.fail('publisher_identity_invalid');return;}this.clearTimer(this.readyTimer);this.readyResolve(message);this.readyResolve=null;continue;}
      if(message.ok===false&&message.retryable===true&&message.code==='publisher_atomic_retry_budget_expired'&&Object.keys(message).sort().join(',')==='code,id,ok,retryable'){
        const item=this.pending.get(message.id);if(!item){this.fail('publisher_ack_invalid');return;}
        this.clearTimer(item.timer);this.pending.delete(message.id);
        if(!item.timedOut){this.publicationEpoch++;item.resolve({published:false,code:'publisher_atomic_retry_budget_expired'});}
        continue;
      }
      if(message.ok!==true){this.fail('publisher_write_failed');return;}
      if(Object.keys(message).sort().join(',')!=='id,ok'){this.fail('publisher_ack_invalid');return;}
      const item=this.pending.get(message.id);if(!item){this.fail('publisher_ack_invalid');return;}
      this.clearTimer(item.timer);this.pending.delete(message.id);
      // A late ACK consumes only its original sequence slot. It never converts
      // the already timed-out observation to success or renews its timestamp.
      if(!item.timedOut)item.resolve({published:true});
    }
  }
  publish(status){
    if(this.failed||this.ending)return Promise.reject(this.failed??Error('publisher_closed'));
    // Keep one owned child and one unacknowledged frame. While that original
    // write is unresolved, do not queue/replay newer or older observations.
    if([...this.pending.values()].some(item=>item.timedOut))return Promise.resolve({published:false,code:'publisher_waiting_for_original_ack'});
    const requestedEpoch=this.publicationEpoch;
    const task=this.serial.then(async()=>{
      await this.ready;if(this.failed||this.ending)throw this.failed??Error('publisher_closed');
      if(requestedEpoch!==this.publicationEpoch)return {published:false,code:'publisher_queued_observation_discarded'};
      const id=++this.sequence,line=JSON.stringify({id,status})+'\n';
      if(Buffer.byteLength(line)>MAX_FRAME)throw this.fail('publisher_frame_limit');
      return new Promise((resolve,reject)=>{
        const item={resolve,reject,timer:null,timedOut:false};
        item.timer=this.setTimer(()=>{
          if(this.failed||this.ending||this.pending.get(id)!==item)return;
          item.timedOut=true;this.publicationEpoch++;
          item.resolve({published:false,code:'publisher_ack_timeout'});
        },3000);this.pending.set(id,item);
        this.child.stdin.write(line,e=>{if(e)this.fail('publisher_pipe_failed');});
      });
    });
    this.serial=task;task.catch(()=>{});return task;
  }
  async close(){
    if(this.ending)return;try{await this.serial;}catch{}this.ending=true;this.clearTimer(this.readyTimer);
    if(!this.child)return;this.child.stdin.end();
    for(let n=0;n<40&&this.child.exitCode===null;n++)await new Promise(r=>setTimeout(r,50));
    if(this.child.exitCode===null)this.child.kill();
  }
}
