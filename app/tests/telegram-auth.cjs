const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '../src-tauri');
for (const name of fs.readdirSync(path.join(root, 'capabilities'))) {
  if (!name.endsWith('.json')) continue;
  const capability = JSON.parse(fs.readFileSync(path.join(root, 'capabilities', name), 'utf8'));
  assert.deepEqual(capability.windows, ['main'], `${name}: only the app window can invoke commands`);
  assert.equal(capability.remote, undefined, `${name}: remote login pages cannot invoke commands`);
  assert.equal(capability.webviews, undefined, `${name}: cannot grant the login webview app permissions`);
}
console.log('PASS: Telegram webview has no app command permissions; callback/state tests run in Rust');
