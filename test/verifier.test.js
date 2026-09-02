import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseTarget } from '../src/verifier.js';

test('TLS targets accept hostname, port, and URL forms', () => {
  assert.deepEqual(parseTarget('example.com'), { host: 'example.com', port: 443 });
  assert.deepEqual(parseTarget('example.com:8443'), { host: 'example.com', port: 8443 });
  assert.deepEqual(parseTarget('https://example.com'), { host: 'example.com', port: 443 });
});
