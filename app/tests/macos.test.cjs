const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const conf = JSON.parse(fs.readFileSync(path.join(root, 'src-tauri/tauri.conf.json')));
assert.deepEqual(conf.bundle.targets, ['app']);
assert(!conf.plugins?.updater?.endpoints?.some(url => url.includes('akimov_vpn_windows')));
assert(conf.bundle.resources['core/mihomo']);
const source = fs.readFileSync(path.join(root, 'ui/app.js'), 'utf8');
assert(source.includes('mihomo · macOS'));
assert(!source.includes('Restart Windows'));
assert(!source.includes('Allow Windows administrator'));
console.log('PASS: macOS packaging and interface');
{
  // The cabinet's callback page hands browser sign-ins back through akimovvpn://; the bundle must register it.
  const plist = require('node:fs').readFileSync(require('node:path').join(__dirname, '../src-tauri/Info.plist'), 'utf8');
  require('node:assert/strict').match(plist, /<key>CFBundleURLSchemes<\/key>\s*<array>\s*<string>akimovvpn<\/string>/);
}
