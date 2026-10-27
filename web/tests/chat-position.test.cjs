const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const assert = require('node:assert/strict')
const test = require('node:test')
const ts = require('../node_modules/typescript')
const source = ts.transpileModule(fs.readFileSync(path.join(__dirname, '../src/lib/chat-position.ts'), 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText
const context = { exports: {} }
vm.runInNewContext(source, context)
const { clampChat } = context.exports

test('initial, dragged and resized chat windows remain inside the viewport', () => {
  for (const [viewportWidth, viewportHeight] of [[1280, 720], [897, 984], [390, 844], [320, 568], [844, 390]]) {
    for (const panelWidth of [420, 628]) {
    const width = Math.min(panelWidth, viewportWidth - 24)
    const height = Math.min(620, viewportHeight - 112)
    for (const position of [null, { x: -2000, y: -2000 }, { x: 4000, y: 4000 }, { x: 400, y: 100 }]) {
      const result = clampChat(position, width, height, viewportWidth, viewportHeight)
      assert.ok(result.x >= 12 && result.y >= 12)
      assert.ok(result.x + width <= viewportWidth - 12)
      assert.ok(result.y + height <= viewportHeight - 12)
    }
    }
  }
})
