const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const assert = require('node:assert/strict')
const test = require('node:test')
const { getEventListeners } = require('node:events')
const ts = require('../node_modules/typescript')
const source = ts.transpileModule(fs.readFileSync(path.join(__dirname, '../src/api.ts'), 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText
function fixture() {
  const sources = []
  class EventSource {
    constructor() { this.listeners = {}; this.closed = false; sources.push(this) }
    addEventListener(name, callback) { this.listeners[name] = callback }
    close() { this.closed = true }
  }
  const context = { exports: {}, EventSource, DOMException, crypto: require('node:crypto').webcrypto }
  vm.runInNewContext(source, context)
  return { stream: context.exports.streamRun, sources }
}

test('explicit end completes historical traces without adding a synthetic event', async () => {
  const { stream, sources } = fixture()
  const controller = new AbortController()
  const events = []
  const result = stream('run', event => events.push(event), controller.signal)
  sources[0].onmessage({ data: JSON.stringify({ actor: 'mapper', type: 'tool', payload: {} }), lastEventId: 'event-1' })
  sources[0].listeners.end()
  await result
  assert.equal(events.length, 1)
  assert.equal(events[0].event_id, 'event-1')
  assert.equal(sources[0].closed, true)
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0)
})

test('timeouts and interrupted streams reject instead of claiming a completed trace', async () => {
  const { stream, sources } = fixture()
  const result = stream('run', () => {}, new AbortController().signal)
  sources[0].listeners.trace_error()
  await assert.rejects(result, /timed out/)
  assert.equal(sources[0].closed, true)
})

test('abort and malformed messages clean up their connection', async () => {
  const { stream, sources } = fixture()
  const controller = new AbortController()
  const result = stream('run', () => {}, controller.signal)
  controller.abort()
  await assert.rejects(result, { name: 'AbortError' })
  assert.equal(sources[0].closed, true)
  const invalid = stream('run', () => {}, new AbortController().signal)
  sources[1].onmessage({ data: '{broken' })
  await assert.rejects(invalid)
  assert.equal(sources[1].closed, true)
})
