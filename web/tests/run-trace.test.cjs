const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const assert = require('node:assert/strict')
const test = require('node:test')
const ts = require('../node_modules/typescript')
const source = ts.transpileModule(fs.readFileSync(path.join(__dirname, '../src/lib/run-trace.ts'), 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText
const context = { exports: {} }
vm.runInNewContext(source, context)
const { filterTrace, tracePage, traceCategory, traceSummary } = context.exports
const events = [
  { event_id: 'a', actor: 'mapper', type: 'tool', payload: { sql: 'SELECT secret_case FROM evidence', rows: 2, ms: 18 } },
  { event_id: 'b', actor: 'matcher', type: 'llm_call', payload: { routed_model: 'verification-model', request: 'secret_case', tokens: 20 } },
  { event_id: 'c', actor: 'critic', type: 'decision', payload: { action: 'recheck', reason: 'Conflicting evidence' } },
  { event_id: 'd', actor: 'orchestrator', type: 'state', payload: { from: 'COLLECTING', to: 'MAPPING' } },
  { event_id: 'e', actor: 'prioritiser', type: 'reuse', payload: { case_id: 'case-1', verdict: 'affected' } },
]

test('filters cover every request including nested payload search and actor combinations', () => {
  assert.equal(filterTrace(events, 'all', '', '').length, 5)
  assert.equal(filterTrace(events, 'queries', 'mapper', 'SECRET_CASE')[0].event_id, 'a')
  assert.equal(filterTrace(events, 'models', '', 'secret_case')[0].event_id, 'b')
  assert.equal(filterTrace(events, 'queries', 'critic', '').length, 0)
  assert.equal(traceCategory(events[2]), 'rechecks')
  assert.equal(traceCategory(events[3]), 'stages')
  assert.equal(traceCategory(events[4]), 'decisions')
  assert.match(traceSummary(events[0]), /2 rows.*18 ms/)
})

test('ten thousand events remain fully reachable with only twenty rows in a page', () => {
  const large = Array.from({ length: 10007 }, (_, index) => ({ ...events[index % events.length], event_id: String(index) }))
  const reached = new Set()
  const { pages } = tracePage(large, 0)
  for (let page = 0; page < pages; page++) {
    const slice = tracePage(large, page)
    assert.ok(slice.events.length <= 20)
    slice.events.forEach(event => reached.add(event.event_id))
  }
  assert.equal(reached.size, large.length)
  assert.equal(tracePage(large, 100000).current, pages - 1)
  assert.equal(tracePage([], 99).current, 0)
  assert.equal(tracePage(large, -1).current, 0)
})
