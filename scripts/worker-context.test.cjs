'use strict'
const test = require('node:test')
const assert = require('node:assert/strict')
const {spawn} = require('node:child_process')
const {once} = require('node:events')
const path = require('node:path')

test('framed context has frozen intrinsics and exchanges only capability messages', async t => {
  const child = spawn(process.execPath,[path.join(__dirname,'../crates/keygate/src/bin/context.cjs')], {
    env:{BROKER_CANARY:'host-only-cookie'},stdio:['pipe','pipe','inherit']
  })
  t.after(() => child.kill())
  const reader=child.stdout[Symbol.asyncIterator]()
  let bytes=Buffer.alloc(0)
  async function read() {
    while (bytes.length<4 || bytes.length<4+bytes.readUInt32BE()) {
      const part=await reader.next()
      assert.equal(part.done,false)
      bytes=Buffer.concat([bytes,part.value])
    }
    const end=4+bytes.readUInt32BE()
    const text=bytes.toString('utf8',4,end)
    assert(!text.includes('host-only-cookie'))
    bytes=bytes.subarray(end)
    return JSON.parse(text)
  }
  function write(value) {
    const data=Buffer.from(JSON.stringify(value)), size=Buffer.alloc(4)
    size.writeUInt32BE(data.length)
    child.stdin.write(Buffer.concat([size,data]))
  }
  assert.deepEqual(await read(),{ready:true})
  for(const source of ["return process.env","return globalThis.fetch('/')",
      "return Object.getPrototypeOf(function(){}).constructor('return 1')()","return new Function('return 1')()"]) {
    write({source,input:null})
    assert.deepEqual(await read(),{failed:true})
  }
  write({source:'return [Object.isFrozen(Array.prototype),Object.isFrozen(globalThis),typeof eval,typeof process]',input:null})
  assert.deepEqual(await read(),{done:true,value:[true,true,'undefined','undefined']})
  write({source:'return yield caps.pod.claim(input)',input:{task:'compile'}})
  assert.deepEqual(await read(),{effect:{op:'pod.claim',body:{task:'compile'}}})
  write({ok:true,fencing_token:'8'})
  assert.deepEqual(await read(),{done:true,value:{ok:true,fencing_token:'8'}})
  const ended=once(child,'exit')
  child.stdin.end()
  assert.equal((await ended)[0],0)
})
