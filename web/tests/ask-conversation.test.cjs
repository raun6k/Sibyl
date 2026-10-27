const fs = require('node:fs')
const vm = require('node:vm')
const assert = require('node:assert/strict')
const path = require('node:path')
const test = require('node:test')
const crypto = require('node:crypto').webcrypto
const ts = require('../node_modules/typescript')
const source = ts.transpileModule(fs.readFileSync(path.join(__dirname, '../src/lib/ask-conversation.ts'), 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText

function fixture() {
  const data = new Map()
  const storage = { getItem: k => data.get(k) ?? null, setItem: (k, v) => data.set(k, v) }
  function load(localStorage = storage) {
    const context = { exports: {}, localStorage, crypto, require: () => ({}) }
    vm.runInNewContext(source, context)
    return context.exports
  }
  return { data, load }
}
const pending = { id: 'one', question: 'Are we affected by CVE-2023-4863?', status: 'checking' }

test('messages, drafts, selected chat and history survive reload and stay workspace-scoped', () => {
  const { load } = fixture()
  let store = load()
  store.updateConversation('personal', () => ({ draft: 'unsent draft', turns: [{ ...pending, status: 'answered', answer: null }] }))
  const first = store.getConversation('personal').id
  store.newConversation('personal')
  const second = store.getConversation('personal').id
  assert.notEqual(first, second)
  assert.equal(store.getChatHistory('personal').chats.length, 2)
  assert.equal(store.getChatHistory('demo').chats.length, 1)
  assert.equal(store.getConversation('demo').turns.length, 0)
  // Repeated New chat on an empty chat must not create empty duplicates.
  store.newConversation('personal')
  assert.equal(store.getChatHistory('personal').chats.length, 2)
  store.selectConversation('personal', first)
  store = load()
  assert.equal(store.getConversation('personal').id, first)
  assert.equal(store.getConversation('personal').draft, 'unsent draft')
  assert.equal(store.getConversation('personal').turns[0].status, 'answered')
  store.newConversation('personal')
  assert.equal(store.getConversation('personal').id, second)
  assert.equal(store.getChatHistory('personal').chats.length, 2)
  assert.equal(store.getConversation('personal').draft, '')
})

test('responses finish in their original chat after switching or starting another', () => {
  const { load } = fixture()
  const store = load()
  store.updateConversation('personal', () => ({ draft: '', turns: [pending] }))
  const original = store.getConversation('personal').id
  store.newConversation('personal')
  store.updateConversation('personal', () => ({ draft: 'another topic', turns: [] }))
  store.updateConversation('personal', current => ({ ...current, turns: current.turns.map(turn => ({ ...turn, status: 'answered', answer: null })) }), original)
  assert.equal(store.getConversation('personal').draft, 'another topic')
  assert.equal(store.getConversation('personal').turns.length, 0)
  store.selectConversation('personal', original)
  assert.equal(store.getConversation('personal').turns[0].status, 'answered')
})

test('legacy saved current chat migrates into history; interrupted requests offer retry', () => {
  const { load, data } = fixture()
  data.set('sibyl-chat:v1:personal', JSON.stringify({ version: 1, draft: 'legacy draft', turns: [pending] }))
  const store = load()
  const migrated = store.getConversation('personal')
  assert.equal(migrated.draft, 'legacy draft')
  assert.equal(migrated.turns[0].question, pending.question)
  assert.equal(migrated.turns[0].status, 'error')
  assert.match(migrated.turns[0].error, /interrupted/)
  assert.ok(data.has('sibyl-chat:v2:personal'))
  assert.equal(load().getConversation('personal').id, migrated.id)
})

test('blocked/full storage and invalid stored data do not crash or discard in-memory chats', () => {
  const { load, data } = fixture()
  const blocked = load({ getItem: () => { throw Error('blocked') }, setItem: () => { throw Error('full') } })
  blocked.updateConversation('personal', () => ({ draft: 'still here', turns: [pending] }))
  blocked.newConversation('personal')
  assert.equal(blocked.getChatHistory('personal').chats.length, 2)
  assert.equal(blocked.getChatHistory('personal').chats[1].draft, 'still here')
  assert.equal(blocked.getConversation('personal').saved, false)
  data.set('sibyl-chat:v2:corrupt', '{bad')
  assert.equal(load().getConversation('corrupt').turns.length, 0)
  data.set('sibyl-chat:v2:invalid', JSON.stringify({ version: 2, activeId: 'bad', chats: [{ id: 'bad' }] }))
  assert.equal(load().getConversation('invalid').turns.length, 0)
})
