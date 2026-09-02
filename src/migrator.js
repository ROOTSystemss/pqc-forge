import { promises as fs } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';

const digest = (content) => `sha256:${createHash('sha256').update(content).digest('hex')}`;
const HAPROXY_GROUPS = 'X25519MLKEM768:SecP256r1MLKEM768:X25519:P-384:P-256';
const APACHE_GROUPS = 'X25519MLKEM768:X25519:prime256v1:secp384r1';

function editableLines(content) {
  return { lines: content.split(/\r?\n/), eol: content.includes('\r\n') ? '\r\n' : '\n' };
}

function replaceLine(lines, index, replacement, ruleId, file) {
  if (lines[index] === replacement) return null;
  const before = lines[index];
  lines[index] = replacement;
  return { ruleId, file, line: index + 1, before, after: replacement };
}

function nginxEdits(relativeFile, content) {
  const { lines, eol } = editableLines(content);
  const edits = [];
  let sawCurve = false;

  for (let index = 0; index < lines.length; index += 1) {
    const curve = lines[index].match(/^(\s*)ssl_ecdh_curve\s+([^;]+);/i);
    if (curve) {
      sawCurve = true;
      if (!/MLKEM|KYBER/i.test(curve[2])) {
        const edit = replaceLine(
          lines,
          index,
          `${curve[1]}ssl_ecdh_curve X25519MLKEM768:X25519;`,
          'QF-TLS-CLASSICAL-GROUPS',
          relativeFile
        );
        if (edit) edits.push(edit);
      }
    }

    const protocols = lines[index].match(/^(\s*)ssl_protocols\s+([^;]+);/i);
    if (protocols && /(?:\bTLSv1(?:\.0)?(?!\.\d)|\bTLSv1\.1\b)/i.test(protocols[2])) {
      const edit = replaceLine(
        lines,
        index,
        `${protocols[1]}ssl_protocols TLSv1.2 TLSv1.3;`,
        'QF-TLS-LEGACY',
        relativeFile
      );
      if (edit) edits.push(edit);
    }
  }

  if (!sawCurve && /ssl_protocols\s+[^;]*TLSv1\.3/i.test(lines.join('\n'))) {
    const protocolIndex = lines.findIndex((line) => /ssl_protocols\s+/i.test(line));
    const indent = lines[protocolIndex]?.match(/^(\s*)/)?.[1] ?? '';
    const inserted = `${indent}ssl_ecdh_curve X25519MLKEM768:X25519;`;
    lines.splice(protocolIndex + 1, 0, inserted);
    edits.push({
      ruleId: 'QF-TLS-ADD-HYBRID-GROUP',
      file: relativeFile,
      line: protocolIndex + 2,
      before: null,
      after: inserted
    });
  }

  return { content: lines.join(eol), edits };
}

function haproxyEdits(relativeFile, content) {
  const { lines, eol } = editableLines(content);
  const edits = [];
  let sawBindCurves = false;

  for (let index = 0; index < lines.length; index += 1) {
    const curves = lines[index].match(/^(\s*)(ssl-default-(bind|server)-curves)\s+([^\s#]+)(\s*(?:#.*)?)$/i);
    if (curves) {
      if (curves[3].toLowerCase() === 'bind') sawBindCurves = true;
      if (!/MLKEM|KYBER/i.test(curves[4])) {
        const edit = replaceLine(lines, index, `${curves[1]}${curves[2]} ${HAPROXY_GROUPS}${curves[5]}`, 'QF-HAPROXY-CLASSICAL-GROUPS', relativeFile);
        if (edit) edits.push(edit);
      }
    }

    if (/(?:ssl-default-(?:bind|server)-options|\bbind\b.*\bssl\b).*\bssl-min-ver\s+(?:TLSv1(?:\.0)?(?!\.\d)|TLSv1\.1)\b/i.test(lines[index])) {
      const replacement = lines[index].replace(/(\bssl-min-ver\s+)(?:TLSv1(?:\.0)?(?!\.\d)|TLSv1\.1)\b/ig, '$1TLSv1.2');
      const edit = replaceLine(lines, index, replacement, 'QF-HAPROXY-LEGACY-TLS', relativeFile);
      if (edit) edits.push(edit);
    }
  }

  const hasTlsBind = lines.some((line) => /^\s*bind\s+[^#]*\bssl\b/i.test(line));
  if (!sawBindCurves && hasTlsBind) {
    const globalIndex = lines.findIndex((line) => /^\s*global\s*(?:#.*)?$/i.test(line));
    if (globalIndex >= 0) {
      const firstSetting = lines.slice(globalIndex + 1).find((line) => /^\s+\S/.test(line));
      const indent = firstSetting?.match(/^(\s+)/)?.[1] ?? '  ';
      const inserted = `${indent}ssl-default-bind-curves ${HAPROXY_GROUPS}`;
      lines.splice(globalIndex + 1, 0, inserted);
      edits.push({ ruleId: 'QF-HAPROXY-ADD-HYBRID-GROUP', file: relativeFile, line: globalIndex + 2, before: null, after: inserted });
    }
  }

  return { content: lines.join(eol), edits };
}

function isHaproxy(relativeFile, content) {
  return path.basename(relativeFile).toLowerCase() === 'haproxy.cfg'
    || (/^\s*global\s*$/im.test(content) && /^\s*(?:frontend|listen)\s+\S+/im.test(content));
}

function apacheMissingPolicyLines(lines) {
  let depth = 0;
  let globalPolicy = false;
  for (const line of lines) {
    if (/^\s*<VirtualHost\b/i.test(line)) depth += 1;
    if (depth === 0 && /^\s*SSLOpenSSLConfCmd\s+(?:Groups|Curves)\s+/i.test(line)) globalPolicy = true;
    if (/^\s*<\/VirtualHost\s*>/i.test(line)) depth = Math.max(0, depth - 1);
  }
  if (globalPolicy) return [];
  const missing = [];
  const seenContexts = new Set();
  for (let index = 0; index < lines.length; index += 1) {
    if (!/^\s*SSLEngine\s+on\b/i.test(lines[index])) continue;
    let open = -1;
    for (let cursor = 0; cursor <= index; cursor += 1) {
      if (/^\s*<VirtualHost\b/i.test(lines[cursor])) open = cursor;
      if (/^\s*<\/VirtualHost\s*>/i.test(lines[cursor])) open = -1;
    }
    const start = open >= 0 ? open : 0;
    let end = lines.length;
    if (open >= 0) {
      const closeOffset = lines.slice(index + 1).findIndex((line) => /^\s*<\/VirtualHost\s*>/i.test(line));
      if (closeOffset >= 0) end = index + 1 + closeOffset + 1;
    }
    const context = `${start}:${end}`;
    if (!seenContexts.has(context) && !lines.slice(start, end).some((line) => /^\s*SSLOpenSSLConfCmd\s+(?:Groups|Curves)\s+/i.test(line))) {
      missing.push(index);
      seenContexts.add(context);
    }
  }
  return missing;
}

function apacheEdits(relativeFile, content) {
  const { lines, eol } = editableLines(content);
  const edits = [];
  for (let index = 0; index < lines.length; index += 1) {
    const groups = lines[index].match(/^(\s*)SSLOpenSSLConfCmd\s+(Groups|Curves)\s+([^\s#]+)(\s*(?:#.*)?)$/i);
    if (groups && !/MLKEM|KYBER/i.test(groups[3])) {
      const edit = replaceLine(lines, index, `${groups[1]}SSLOpenSSLConfCmd Groups ${APACHE_GROUPS}${groups[4]}`, 'QF-APACHE-CLASSICAL-GROUPS', relativeFile);
      if (edit) edits.push(edit);
    }
  }
  const insertions = apacheMissingPolicyLines(lines).sort((a, b) => b - a);
  for (const engineIndex of insertions) {
    const indent = lines[engineIndex].match(/^(\s*)/)?.[1] ?? '';
    const inserted = `${indent}SSLOpenSSLConfCmd Groups ${APACHE_GROUPS}`;
    lines.splice(engineIndex + 1, 0, inserted);
    edits.push({ ruleId: 'QF-APACHE-ADD-HYBRID-GROUP', file: relativeFile, line: engineIndex + 2, before: null, after: inserted });
  }
  edits.sort((a, b) => a.line - b.line);
  return { content: lines.join(eol), edits };
}

async function collectConfigFiles(root, current = root, output = []) {
  const entries = await fs.readdir(current, { withFileTypes: true });
  for (const entry of entries) {
    if (['.git', 'node_modules', 'dist', 'build'].includes(entry.name)) continue;
    const absolute = path.join(current, entry.name);
    if (entry.isDirectory()) await collectConfigFiles(root, absolute, output);
    else if (entry.isFile() && (entry.name === 'nginx.conf' || entry.name === 'haproxy.cfg' || entry.name.endsWith('.conf') || entry.name.endsWith('.cfg'))) output.push(absolute);
  }
  return output;
}

export async function migrateRepository(rootPath, { write = false, acknowledgeRuntime = false, includeContent = false } = {}) {
  if (write && !acknowledgeRuntime) {
    throw new Error('Refusing to write: confirm the target uses a TLS runtime supporting X25519MLKEM768 with --accept-runtime-requirement.');
  }
  const root = path.resolve(rootPath);
  const files = await collectConfigFiles(root);
  const proposed = [];
  const artifacts = [];
  const pendingWrites = [];

  for (const file of files) {
    const before = await fs.readFile(file, 'utf8');
    const relativeFile = path.relative(root, file);
    let result = { content: before, edits: [] };
    if (/ssl_protocols|ssl_ecdh_curve/i.test(before) || path.basename(file).toLowerCase() === 'nginx.conf') {
      result = nginxEdits(relativeFile, result.content);
    }
    if (isHaproxy(relativeFile, before)) {
      const haproxy = haproxyEdits(relativeFile, result.content);
      result = { content: haproxy.content, edits: [...result.edits, ...haproxy.edits] };
    }
    if (/^\s*SSLEngine\s+on\b|^\s*SSLOpenSSLConfCmd\s+/im.test(before)) {
      const apache = apacheEdits(relativeFile, result.content);
      result = { content: apache.content, edits: [...result.edits, ...apache.edits] };
    }
    if (result.edits.length === 0) continue;
    proposed.push(...result.edits);
    artifacts.push({
      file: relativeFile,
      beforeDigest: digest(before),
      afterDigest: digest(result.content),
      backup: write ? `${relativeFile}.pqc-forge.bak` : null,
      ...(includeContent ? { beforeContent: before, afterContent: result.content } : {})
    });
    if (write) pendingWrites.push({ file, before, after: result.content, beforeDigest: digest(before), backup: `${file}.pqc-forge.bak` });
  }

  if (write) {
    // Complete all destructive preflight checks before writing the first file.
    for (const pending of pendingWrites) {
      try {
        await fs.lstat(pending.backup);
        throw new Error(`Refusing to overwrite existing migration backup: ${pending.backup}`);
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      const current = await fs.readFile(pending.file, 'utf8');
      if (digest(current) !== pending.beforeDigest) throw new Error(`Refusing to write changed file: ${pending.file}`);
    }
    for (const pending of pendingWrites) {
      await fs.writeFile(pending.backup, pending.before, { encoding: 'utf8', flag: 'wx' });
    }
    for (const pending of pendingWrites) await fs.writeFile(pending.file, pending.after, 'utf8');
  }

  return {
    schema: 'pqc-forge.migration/v1',
    generatedAt: new Date().toISOString(),
    root,
    mode: write ? 'applied' : 'dry-run',
    runtimeRequirement: 'OpenSSL 3.5+ (including HAProxy or Apache mod_ssl linked against it) or another TLS runtime supporting X25519MLKEM768',
    changeCount: proposed.length,
    changes: proposed,
    artifacts
  };
}
