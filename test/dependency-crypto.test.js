import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createApiServer, provisionTenant } from '../src/api/server.js';
import { setManualPlan } from '../src/billing/entitlements.js';
import { scanDependencies } from '../src/dependencyCrypto.js';

// AD-070 (knock-out Phase 5): which declared libraries bring in RSA/ECC and which are post-quantum capable, from
// manifests only; node_modules is skipped; unparsable manifests are listed; the result rides inside the signed
// inventory snapshot (so changing it breaks the signature).
async function workspace(files) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-deps-'));
  for (const [rel, content] of Object.entries(files)) { await fs.mkdir(path.dirname(path.join(dir, rel)), { recursive: true }); await fs.writeFile(path.join(dir, rel), content); }
  return dir;
}

test('manifests across ecosystems: classical, post-quantum capable, both, symmetric; node_modules skipped; bad manifest listed', async () => {
  const dir = await workspace({
    'package.json': JSON.stringify({ dependencies: { jsonwebtoken: '^9.0.0', '@noble/post-quantum': '0.7.1', express: '^4' }, devDependencies: { 'crypto-js': '4.2.0' } }),
    'svc/requirements.txt': 'cryptography>=42\nrequests==2.31\n# comment\npyjwt[crypto]==2.8\n',
    'go/go.mod': 'module x\n\nrequire (\n\tgithub.com/cloudflare/circl v1.3.7\n\tgolang.org/x/crypto v0.21.0\n)\n',
    'rs/Cargo.toml': '[package]\nname="x"\n\n[dependencies]\nring = "0.17"\nml-kem = { version = "0.2" }\nserde = "1"\n',
    'java/pom.xml': '<project><dependencies><dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId><version>1.78</version></dependency></dependencies></project>',
    'net/App.csproj': '<Project><ItemGroup><PackageReference Include="BouncyCastle.Cryptography" Version="2.4.0" /></ItemGroup></Project>',
    'node_modules/x/package.json': JSON.stringify({ dependencies: { 'node-rsa': '1' } }),
    'broken/package.json': '{ not json',
  });
  const r = await scanDependencies(dir);
  const names = r.libraries.map((l) => l.name).sort();
  assert.deepEqual(names, ['@noble/post-quantum', 'BouncyCastle.Cryptography', 'crypto-js', 'cryptography', 'github.com/cloudflare/circl', 'golang.org/x/crypto', 'jsonwebtoken', 'ml-kem', 'org.bouncycastle:bcprov-jdk18on', 'pyjwt', 'ring'].sort());
  assert.ok(!names.includes('node-rsa'), 'node_modules skipped');
  assert.ok(!names.includes('express') && !names.includes('requests') && !names.includes('serde'), 'non-crypto libraries not listed');
  assert.deepEqual(r.unreadableManifests, ['broken/package.json']);
  const cls = Object.fromEntries(r.libraries.map((l) => [l.name, l.class]));
  assert.match(cls.jsonwebtoken, /^classical public-key/);
  assert.equal(cls['@noble/post-quantum'], 'post-quantum capable');
  assert.match(cls['github.com/cloudflare/circl'], /post-quantum capable/);
  assert.equal(cls['crypto-js'], 'symmetric / hashing only');
  assert.equal(r.summary.libraries, 11);
  assert.match(r.method, /Declared dependencies/);
  assert.doesNotMatch(JSON.stringify(r), /quantum-safe|quantum-proof/i);
});

test('hosted: the signed inventory snapshot carries the dependency list; changing it breaks the signature', async () => {
  const apiHome = await fs.mkdtemp(path.join(os.tmpdir(), 'pqc-forge-deps-'));
  const { server } = createApiServer({ apiHome });
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const pro = await provisionTenant(apiHome, 'Pro Co');
    await setManualPlan(apiHome, pro.tenantId, { plan: 'pro' });
    const ph = { authorization: `Bearer ${pro.apiKey}`, 'content-type': 'application/json' };
    const { workspaceId } = await (await fetch(`${base}/v1/workspaces`, { method: 'POST', headers: ph, body: JSON.stringify({ files: [
      { path: 'package.json', content: JSON.stringify({ dependencies: { 'node-forge': '1.3.1' } }) },
      { path: 'src/a.js', content: "const forge = require('node-forge');\n" },
    ] }) })).json();
    const job = await (await fetch(`${base}/v1/jobs`, { method: 'POST', headers: ph, body: JSON.stringify({ type: 'inventory-snapshot', params: { workspaceId, label: 'Deps' } }) })).json();
    let done; for (let i = 0; i < 600; i++) { done = await (await fetch(`${base}/v1/jobs/${job.jobId}`, { headers: ph })).json(); if (['succeeded', 'failed'].includes(done.status)) break; await new Promise((r) => setTimeout(r, 50)); }
    assert.equal(done.status, 'succeeded', JSON.stringify(done));
    const doc = await (await fetch(`${base}/v1/jobs/${job.jobId}/files/inventory-snapshot.json`, { headers: ph })).json();
    assert.equal(doc.dependencies.libraries[0].name, 'node-forge');
    assert.match(doc.dependencies.libraries[0].class, /classical public-key/);
    const pv = async (d) => (await fetch(`${base}/v1/public/verify-report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(d) })).json();
    assert.equal((await pv(doc)).valid, true);
    const edited = JSON.parse(JSON.stringify(doc)); edited.dependencies.libraries = [];
    assert.equal((await pv(edited)).valid, false, 'removing a library from the signed snapshot breaks the signature');
  } finally { server.close(); }
});
