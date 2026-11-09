import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// Task G 2026-11-08: the web app footer shows the RootSystems X and Instagram profiles as icon links, from one list.
test('the web app footer links both profiles from one list, opening in a new tab', () => {
  const src = readFileSync(new URL('../web/src/socialLinks.tsx', import.meta.url), 'utf8');
  const list = src.slice(src.indexOf('SOCIAL_LINKS'), src.indexOf('];'));
  assert.deepEqual([...list.matchAll(/url: '([^']+)'/g)].map((m) => m[1]), ['https://x.com/TheROOTsystems', 'https://www.instagram.com/therootsystemms/']);
  assert.match(src, /SOCIAL_LINKS\.map\(\(l\) => \(\s*<a key=\{l\.url\} href=\{l\.url\} target="_blank" rel="noopener"/);
  const app = readFileSync(new URL('../web/src/App.tsx', import.meta.url), 'utf8');
  assert.equal((app.match(/<AppFooter \/>/g) || []).length, 2, 'shown signed in and signed out');
});
