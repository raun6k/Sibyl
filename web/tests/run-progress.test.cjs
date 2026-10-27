const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const assert = require('node:assert/strict')
const test = require('node:test')
const ts = require('../node_modules/typescript')
const { createRequire } = require('node:module')
const webRequire = createRequire(path.join(__dirname, '../package.json'))
const { renderToStaticMarkup } = webRequire('react-dom/server')
const { createElement } = webRequire('react')
function compile(file, require = webRequire) {
  const source = ts.transpileModule(fs.readFileSync(path.join(__dirname, file), 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX } }).outputText
  const context = { exports: {}, require }
  vm.runInNewContext(source, context)
  return context.exports
}
const format = compile('../src/lib/format.ts')
const { RunProgress } = compile('../src/components/run-progress.tsx', name => name === '@/lib/format' ? format : webRequire(name))
const render = props => renderToStaticMarkup(createElement(RunProgress, props))

test('completed and queued runs do not display misleading in-progress stages', () => {
  const done = render({ stage: 'DONE', status: 'DONE' })
  assert.equal((done.match(/<span class="sr-only">Completed<\/span>/g) || []).length, 7)
  assert.ok(!done.includes('aria-current="step"'))
  const queued = render({ stage: 'QUEUED', status: 'QUEUED' })
  assert.match(queued, /Waiting to start/)
  assert.ok(!queued.includes('aria-current="step"'))
})

test('running and failed stages are distinguished from completed stages', () => {
  const running = render({ stage: 'MAPPING', status: 'RUNNING' })
  assert.equal((running.match(/aria-current="step"/g) || []).length, 1)
  assert.match(running, /In progress/)
  const failed = render({ stage: 'MATCHING', status: 'FAILED' })
  assert.match(failed, /Run stopped/)
  assert.match(failed, /<span class="sr-only">Failed/)
  assert.ok(!failed.includes('All stages finished'))
})
