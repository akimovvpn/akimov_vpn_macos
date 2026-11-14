const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../src-tauri/src/main.rs'), 'utf8');
const bridge = source.match(/const TELEGRAM_BRIDGE: &str = r#"([\s\S]*?)"#;/)[1]
  .replace('__AKIMOV_CALLBACK__', 'https://akimov-login.invalid/challenge-nonce')
  .replace('__AKIMOV_ORIGIN__', 'https://akimov.bid');
function page(origin = 'https://oauth.telegram.org', frame = false) {
  const location = { origin, hostname: new URL(origin).hostname, href: '' };
  const window = {};
  window.top = frame ? {} : window;
  vm.runInNewContext(bridge, { window, location });
  return { window, location };
}
for (const origin of ['http://oauth.telegram.org', 'https://oauth.telegram.org:444', 'https://telegram.org']) {
  const p = page(origin);
  assert.equal(p.window.opener, undefined, `must not install bridge on ${origin}`);
}
assert.equal(page(undefined, true).window.opener, undefined, 'subframes cannot answer login');
const p = page();
p.window.opener.postMessage({ event: 'auth_result', result: 'wrong-target' }, 'https://evil.example');
assert.equal(p.location.href, '', 'wrong target origin cannot complete login');
p.window.opener.postMessage({ event: 'auth_result', result: { id_token: 'signed-token' } }, 'https://akimov.bid');
const callback = new URL(p.location.href);
assert.equal(callback.origin, 'https://akimov-login.invalid');
assert.equal(callback.pathname, '/challenge-nonce');
assert.deepEqual(JSON.parse(callback.searchParams.get('d')), { event: 'auth_result', result: { id_token: 'signed-token' } });
p.window.close();
assert.equal(p.location.href, callback.href, 'close cannot overwrite the first answer');
const cancelled = page();
cancelled.window.close();
assert.equal(new URL(cancelled.location.href).search, '?closed');
console.log('PASS: Telegram popup origin, frame, challenge binding and cancellation');
