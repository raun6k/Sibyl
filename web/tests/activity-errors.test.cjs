const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const assert = require('node:assert/strict')
const test = require('node:test')
const ts = require('../node_modules/typescript')
const source = ts.transpileModule(fs.readFileSync(path.join(__dirname, '../src/lib/activity-errors.ts'), 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText
const context = { exports: {} }
vm.runInNewContext(source, context)
const { activityFailure } = context.exports

test('bad GitHub folder/file links explain the URL correction without printing process output', () => {
  for (const segment of ['tree/main/SCA', 'blob/main/package.json']) {
    const error = `git clone failed: Cloning into '/private/local/repos/sca'... fatal: repository 'https://github.com/example/project/${segment}/' not found`
    const message = activityFailure(error, true)
    assert.match(message, /root URL/)
    assert.ok(!message.includes('/private/local') && !message.includes('git clone'))
  }
})

test('does not label authentication, missing repositories or network failures as bad folder links', () => {
  assert.match(activityFailure('fatal: Authentication failed for repository', true), /credentials and permissions/)
  assert.match(activityFailure("fatal: repository 'https://github.com/example/private/' not found", true), /not found or inaccessible/)
  assert.match(activityFailure('fatal: Could not resolve host: github.com', true), /connection/)
  assert.match(activityFailure('request timed out', false), /timed out/)
  assert.match(activityFailure('unexpected internal exception', false), /Review the details/)
})
