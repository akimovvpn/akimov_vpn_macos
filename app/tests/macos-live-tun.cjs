// Explicit acceptance check: briefly changes system routing/DNS through the installed helper.
// Uses this user's saved profile without printing server credentials or account data.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const dgram = require('node:dgram');
const crypto = require('node:crypto');
const {execFileSync, execFile} = require('node:child_process');
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
async function freePort() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
function ownedInterface() {
  let name;
  for (const line of execFileSync('/sbin/ifconfig', {encoding:'utf8'}).split('\n')) {
    if (/^\S+:/.test(line)) name = line.split(':')[0];
    if (line.includes('inet 198.19.0.1 ') && /^utun\d+$/.test(name || '')) return name;
  }
  return null;
}
function vpnRoutes() {
  return execFileSync('/usr/sbin/netstat', ['-rn', '-f', 'inet'], {encoding:'utf8'})
    .split('\n').filter(line => /\butun\d+\b/.test(line))
    .filter(line => !line.trim().split(/\s+/)[2]?.includes('W'))
    .map(line => line.trim().split(/\s+/).slice(0, 4).join(' ')).sort();
}
function routeInterface() {
  return execFileSync('/sbin/route', ['-n', 'get', '1.1.1.1'], {encoding:'utf8'})
    .match(/interface:\s*(\S+)/)?.[1];
}
function https() {
  return new Promise((resolve, reject) => {
    execFile('/usr/bin/curl', ['--silent', '--show-error', '--noproxy', '*',
      '--connect-timeout', '5', '--max-time', '12', '-o', '/dev/null', '-w', '%{http_code}',
      'https://www.gstatic.com/generate_204'], {timeout:15000}, (error, output) => {
      if (error) reject(Error('HTTPS through the system TUN route failed.'));
      else resolve(output);
    });
  });
}
function dns() {
  const socket = dgram.createSocket('udp4');
  const id = crypto.randomBytes(2);
  // example.com A query, recursion desired.
  const query = Buffer.concat([id, Buffer.from('01000001000000000000076578616d706c6503636f6d0000010001', 'hex')]);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(Error('UDP DNS through TUN timed out.')), 5000);
    const finish = error => { clearTimeout(timer); socket.close(); error ? reject(error) : resolve(); };
    socket.once('error', finish);
    socket.once('message', packet => {
      if (packet.length < 12 || !packet.subarray(0, 2).equals(id) || !(packet[2] & 0x80) || (packet[3] & 15) !== 0 || packet.readUInt16BE(6) === 0) {
        finish(Error('TUN returned an invalid or empty DNS answer.'));
      } else finish();
    });
    socket.send(query, 53, '1.1.1.1');
  });
}
async function main() {
  if (!process.argv.includes('--live')) throw Error('Run with --live; this check temporarily changes system routing and DNS.');
  assert.equal(process.platform, 'darwin');
  assert.equal(ownedInterface(), null, 'Disconnect akimov before running this check.');
  const previousRoute = routeInterface();
  const previousVpnRoutes = vpnRoutes();
  const base = path.join(os.homedir(), 'Library/Application Support/akimov-vpn');
  const settings = JSON.parse(fs.readFileSync(path.join(base, 'settings.json')));
  const profile = execFileSync('/usr/bin/ruby', ['-ryaml', '-rjson', '-e',
    'print JSON.generate(YAML.safe_load(File.read(ARGV[0]), [], [], true))', path.join(base, 'core/config.yaml')], {encoding:'utf8'});
  const config = JSON.parse(profile);
  const group = config.rules.filter(rule => rule.startsWith('MATCH,')).at(-1)?.split(',')[1];
  assert(group && settings.node, 'Connect once in the app to save a selected profile first.');
  config['mixed-port'] = await freePort();
  config['proxy-groups'].find(item => item.name === group)['default-selected'] = settings.node;
  for (const kind of ['rule-providers', 'proxy-providers']) {
    for (const provider of Object.values(config[kind] || {})) {
      if (provider.type === 'http' && !provider.proxy) provider.proxy = group;
    }
  }
  const socket = net.connect('/Library/Application Support/vpn.akimov.macos/control.sock');
  await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
  socket.setTimeout(35000, () => socket.destroy(Error('Helper response timed out.')));
  const pending = [];
  let buffered = '';
  socket.setEncoding('utf8');
  socket.on('data', chunk => {
    buffered += chunk;
    let index;
    while ((index = buffered.indexOf('\n')) >= 0) {
      const result = JSON.parse(buffered.slice(0, index)); buffered = buffered.slice(index + 1);
      const request = pending.shift();
      if (result.error) request.reject(Error(result.error)); else request.resolve(result.value);
    }
  });
  socket.on('error', error => { for (const request of pending.splice(0)) request.reject(error); });
  const ask = value => new Promise((resolve, reject) => { pending.push({resolve,reject}); socket.write(JSON.stringify(value)+'\n'); });
  const api = (method, route, body) => ask({op:'api',method,path:route,body,wait:2});
  try {
    await ask({op:'start',yaml:JSON.stringify(config)});
    let ready = false;
    const started = Date.now();
    while (Date.now() - started < 25000) {
      let status;
      try { status = await api('GET', '/version'); } catch { await wait(100); continue; }
      if (status.tun_error) throw Error(status.tun_error);
      if (status.ready && ownedInterface()) { ready = true; break; }
      await wait(100);
    }
    assert(ready, 'Mihomo did not create a ready, owned TUN interface.');
    const owned = ownedInterface();
    assert.equal(routeInterface(), owned, 'The system route must use akimov’s adapter, not another VPN.');
    const remainingRoutes = vpnRoutes();
    for (const route of previousVpnRoutes) assert(remainingRoutes.includes(route), 'Existing VPN route was changed: '+route);
    await api('PUT', '/proxies/'+encodeURIComponent(group), {name:settings.node});
    assert.equal(await https(), '204');
    await dns();
    console.log('PASS: owned TUN interface, matching system route, HTTPS and UDP DNS');
  } finally {
    try { await ask({op:'stop'}); } finally { socket.destroy(); }
    assert.equal(ownedInterface(), null, 'akimov TUN must be removed after disconnect.');
    assert.equal(routeInterface(), previousRoute, 'The previous system route must be restored.');
    assert.deepEqual(vpnRoutes(), previousVpnRoutes, 'Existing VPN routes must remain unchanged after disconnect.');
    console.log('PASS: TUN removal and previous route restored');
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
