// The Rust supervisor owns the deadline, macaroon and broker connection.
// Only JSON primitives cross the realm boundary. Capability requests suspend
// the generator while Rust checks and executes the operation.
'use strict'
const vm = require('node:vm')
const fs = require('node:fs')
const LIMIT = 65536
function read(size) {
  const data = Buffer.alloc(size)
  let n = 0
  while (n < size) {
    const count = fs.readSync(0, data, n, size - n)
    if (!count) process.exit(0)
    n += count
  }
  return data
}
function receive() {
  const size = read(4).readUInt32BE()
  if (size > LIMIT) process.exit(1)
  return JSON.parse(read(size))
}
function send(value) {
  const body = Buffer.from(JSON.stringify(value))
  if (body.length > LIMIT) throw Error()
  const frame = Buffer.allocUnsafe(body.length + 4)
  frame.writeUInt32BE(body.length)
  body.copy(frame, 4)
  let n = 0
  while (n < frame.length) n += fs.writeSync(1, frame, n, frame.length - n)
}
const lockdown = new vm.Script(`
  "use strict";
  const caps = (() => {
    const op = name => body => ({op:name,body})
    return Object.freeze({
      pod:Object.freeze({claim:op('pod.claim'),done:op('pod.done')}),
      git:Object.freeze({land:op('git.land'),reconcile:op('git.reconcile')})
    })
  })()
  ;(() => {
    for (const name of ['console','eval','Function','WebAssembly','SharedArrayBuffer','Atomics']) delete globalThis[name]
    const seen = new Set([globalThis])
    function freeze(value) {
      if (value === null || !['object','function'].includes(typeof value) || seen.has(value)) return
      seen.add(value)
      for (const key of Reflect.ownKeys(value)) {
        const desc = Object.getOwnPropertyDescriptor(value,key)
        freeze(desc.value); freeze(desc.get); freeze(desc.set)
      }
      freeze(Object.getPrototypeOf(value))
      Object.freeze(value)
    }
    for (const key of Reflect.ownKeys(globalThis)) {
      const desc=Object.getOwnPropertyDescriptor(globalThis,key)
      freeze(desc.value); freeze(desc.get); freeze(desc.set)
    }
    for(const f of [function*(){}, async function(){}, async function*(){}]) freeze(f)
    freeze(caps)
    Object.freeze(globalThis)
  })()
`)
const next = new vm.Script('JSON.stringify(task.next(reply))')
const handlers = new Map()
// One Rust watchdog spans compilation, every VM step, IPC and broker time.
const options = { displayErrors:false }
function invoke({source,input}) {
  // Realms are scoped to the pool's single seat and exact handler source.
  let ctx = handlers.get(source)
  if (!ctx) {
    if (handlers.size >= 4) handlers.delete(handlers.keys().next().value)
    ctx = vm.createContext(vm.constants.DONT_CONTEXTIFY, {
      codeGeneration:{strings:false,wasm:false}, microtaskMode:'afterEvaluate'
    })
    lockdown.runInContext(ctx,options)
    vm.runInContext('let task,reply; const handler=function*(caps,input){"use strict";\n'+source+'\n}',ctx,options)
    handlers.set(source,ctx)
  }
  vm.runInContext('reply=undefined;task=handler(caps,JSON.parse('+JSON.stringify(JSON.stringify(input))+'))',ctx,options)
  for (;;) {
    const encoded = next.runInContext(ctx,options)
    if (typeof encoded !== 'string' || encoded.length > LIMIT) throw Error()
    const step = JSON.parse(encoded)
    if (step.done) {send({done:true,value:step.value ?? null}); return}
    send({effect:step.value})
    const answer=receive()
    vm.runInContext('reply=JSON.parse('+JSON.stringify(JSON.stringify(answer))+')',ctx,options)
  }
}
send({ready:true})
for (;;) {
  const job=receive()
  try { invoke(job) } catch { handlers.delete(job.source); send({failed:true}) }
}
