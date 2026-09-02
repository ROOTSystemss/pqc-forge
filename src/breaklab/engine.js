const PQ_PATTERN = /MLKEM|KYBER/i;
const PQ_SIGNATURE_PATTERN = /ML-?DSA|SLH-?DSA|DILITHIUM|SPHINCS/i;

export function createRng(seed = 42) {
  let state = Number(seed) >>> 0;
  return () => {
    state = (state + 0x6D2B79F5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

export function validateScenario(scenario) {
  if (scenario?.schema !== 'pqc-forge.breaklab-scenario/v1') throw new Error('Unsupported or missing BreakLab scenario schema.');
  for (const key of ['client', 'server', 'certificate', 'network', 'allowClassicalFallback']) {
    if (!Array.isArray(scenario.dimensions?.[key]) || scenario.dimensions[key].length === 0) throw new Error(`Scenario dimension ${key} must be a non-empty array.`);
  }
  for (const [dimension, profileGroup] of [['client', 'clients'], ['server', 'servers'], ['certificate', 'certificates'], ['network', 'networks']]) {
    for (const value of scenario.dimensions[dimension]) {
      if (!scenario.profiles?.[profileGroup]?.[value]) throw new Error(`Missing ${profileGroup} profile: ${value}`);
    }
  }
  return scenario;
}

export function enumerateCandidates(dimensions, limit = 100000) {
  const entries = Object.entries(dimensions);
  const total = entries.reduce((count, [, values]) => count * values.length, 1);
  if (total > limit) throw new Error(`Scenario has ${total} states; enumeration limit is ${limit}.`);
  let candidates = [{}];
  for (const [name, values] of entries) candidates = candidates.flatMap((candidate) => values.map((value) => ({ ...candidate, [name]: value })));
  return candidates;
}

function sizeFor(map, name, fallback = 0) {
  return Number(map?.[name] ?? fallback);
}

export function evaluateCandidate(scenarioInput, candidate) {
  const scenario = validateScenario(scenarioInput);
  const client = scenario.profiles.clients[candidate.client];
  const server = scenario.profiles.servers[candidate.server];
  const certificate = scenario.profiles.certificates[candidate.certificate];
  const network = scenario.profiles.networks[candidate.network];
  const allowFallback = candidate.allowClassicalFallback === true || candidate.allowClassicalFallback === 'true';
  const serverGroups = allowFallback ? server.groups : server.groups.filter((group) => PQ_PATTERN.test(group));
  const group = serverGroups.find((item) => client.groups.includes(item)) ?? null;
  const findings = [];

  if (!group) findings.push({ code: 'HANDSHAKE_NO_COMMON_GROUP', severity: 100, message: 'Client and server have no permitted key-exchange group in common.' });
  else if (scenario.policy.requirePqKeyExchange && !PQ_PATTERN.test(group)) findings.push({ code: 'CLASSICAL_DOWNGRADE', severity: 95, message: `Negotiation silently fell back to ${group}.` });

  const signatureSupported = client.signatures.includes(certificate.signature);
  if (!signatureSupported) findings.push({ code: 'AUTH_SIGNATURE_UNSUPPORTED', severity: 98, message: `Client does not support ${certificate.signature}.` });
  else if (scenario.policy.requirePqAuthentication && !PQ_SIGNATURE_PATTERN.test(certificate.signature)) findings.push({ code: 'CLASSICAL_AUTHENTICATION', severity: 90, message: `Authentication remains classical with ${certificate.signature}.` });

  const keyExchangeBytes = group ? sizeFor(scenario.algorithmSizes?.keyExchangeBytes, group, 256) : 0;
  const signatureBytes = sizeFor(scenario.algorithmSizes?.signatureBytes, certificate.signature, certificate.bytes ?? 512);
  const handshakeBytes = Number(scenario.baseHandshakeBytes ?? 700) + keyExchangeBytes + signatureBytes;
  const fragments = Math.ceil(handshakeBytes / network.mtu);
  if (fragments > Number(network.maxFragments ?? 8)) findings.push({ code: 'FRAGMENT_LIMIT_EXCEEDED', severity: 85, message: `${handshakeBytes} handshake bytes require ${fragments} fragments; limit is ${network.maxFragments}.` });

  const latencyMs = Number(network.baseLatencyMs ?? 0) + fragments * Number(network.fragmentCostMs ?? 0)
    + sizeFor(scenario.algorithmSizes?.keyExchangeCostMs, group, 0)
    + sizeFor(scenario.algorithmSizes?.signatureVerifyCostMs, certificate.signature, 0);
  if (latencyMs > Number(scenario.policy.maxHandshakeLatencyMs ?? Infinity)) findings.push({ code: 'LATENCY_BUDGET_EXCEEDED', severity: 65, message: `${latencyMs.toFixed(1)}ms exceeds the ${scenario.policy.maxHandshakeLatencyMs}ms budget.` });

  return {
    candidate: { ...candidate }, negotiatedGroup: group, signatureAlgorithm: certificate.signature,
    handshakeBytes, fragments, latencyMs: Number(latencyMs.toFixed(3)), findings,
    severity: Math.max(0, ...findings.map((finding) => finding.severity)),
    score: findings.reduce((sum, finding) => sum + finding.severity, 0)
  };
}

const candidateKey = (candidate) => JSON.stringify(candidate);

function pairTokens(candidate) {
  const entries = Object.entries(candidate);
  const output = [];
  for (let left = 0; left < entries.length; left += 1) {
    for (let right = left + 1; right < entries.length; right += 1) output.push(`${entries[left][0]}=${entries[left][1]}|${entries[right][0]}=${entries[right][1]}`);
  }
  return output;
}

function summarizeStrategy(name, evaluated, totalStates, started, metadata = {}) {
  const failures = evaluated.filter((result) => result.findings.length > 0);
  const modes = [...new Set(failures.flatMap((result) => result.findings.map((finding) => finding.code)))].sort();
  const maximum = failures.reduce((best, result) => !best || result.score > best.score ? result : best, null);
  const bestFailuresByMode = {};
  for (const result of failures) {
    for (const finding of result.findings) {
      if (!bestFailuresByMode[finding.code] || result.score > bestFailuresByMode[finding.code].score) bestFailuresByMode[finding.code] = result;
    }
  }
  return {
    strategy: name,
    terminology: name === 'adaptive_distribution' ? 'classical quantum-inspired probability-distribution search' : 'classical search',
    evaluations: evaluated.length,
    stateCoverage: Number((evaluated.length / totalStates).toFixed(4)),
    failingConfigurations: failures.length,
    uniqueFailureModes: modes,
    maxSeverity: failures.length ? Math.max(...failures.map((result) => result.severity)) : 0,
    bestFailure: maximum,
    bestFailuresByMode,
    runtimeMs: Number((performance.now() - started).toFixed(3)),
    ...metadata
  };
}

function randomCandidate(scenario, rng) {
  return Object.fromEntries(Object.entries(scenario.dimensions).map(([name, values]) => [name, values[Math.floor(rng() * values.length)]]));
}

function uniqueEvaluate(scenario, candidates, budget) {
  const seen = new Set();
  const results = [];
  for (const candidate of candidates) {
    const key = candidateKey(candidate);
    if (seen.has(key)) continue;
    seen.add(key);
    results.push(evaluateCandidate(scenario, candidate));
    if (results.length >= budget) break;
  }
  return results;
}

function runRandom(scenario, budget, seed, totalStates) {
  const started = performance.now();
  const rng = createRng(seed);
  const candidates = [];
  for (let index = 0; index < Math.max(budget * 40, 100); index += 1) candidates.push(randomCandidate(scenario, rng));
  return summarizeStrategy('random', uniqueEvaluate(scenario, candidates, budget), totalStates, started, { seed });
}

function runPairwise(scenario, budget, seed, allCandidates) {
  const started = performance.now();
  const rng = createRng(seed);
  const remaining = allCandidates.map((candidate) => ({ candidate, tie: rng() }));
  const covered = new Set();
  const selected = [];
  while (remaining.length && selected.length < budget) {
    remaining.sort((a, b) => {
      const gainA = pairTokens(a.candidate).filter((token) => !covered.has(token)).length;
      const gainB = pairTokens(b.candidate).filter((token) => !covered.has(token)).length;
      return gainB - gainA || a.tie - b.tie;
    });
    const next = remaining.shift().candidate;
    selected.push(next);
    pairTokens(next).forEach((token) => covered.add(token));
  }
  return summarizeStrategy('pairwise', uniqueEvaluate(scenario, selected, budget), allCandidates.length, started, { seed, pairsCovered: covered.size });
}

function neighbor(scenario, candidate, rng) {
  const names = Object.keys(scenario.dimensions);
  const dimension = names[Math.floor(rng() * names.length)];
  const alternatives = scenario.dimensions[dimension].filter((value) => value !== candidate[dimension]);
  return { ...candidate, [dimension]: alternatives[Math.floor(rng() * alternatives.length)] };
}

function runAnnealing(scenario, budget, seed, totalStates) {
  const started = performance.now();
  const rng = createRng(seed);
  let current = randomCandidate(scenario, rng);
  let currentResult = evaluateCandidate(scenario, current);
  const results = new Map([[candidateKey(current), currentResult]]);
  for (let step = 1; step < budget && results.size < totalStates; step += 1) {
    const candidate = neighbor(scenario, current, rng);
    const result = evaluateCandidate(scenario, candidate);
    results.set(candidateKey(candidate), result);
    const temperature = Math.max(0.02, 1 - step / budget);
    if (result.score >= currentResult.score || rng() < Math.exp((result.score - currentResult.score) / (100 * temperature))) {
      current = candidate;
      currentResult = result;
    }
  }
  return summarizeStrategy('simulated_annealing', [...results.values()], totalStates, started, { seed });
}

function weightedChoice(values, weights, rng) {
  let pick = rng() * weights.reduce((sum, value) => sum + value, 0);
  for (let index = 0; index < values.length; index += 1) {
    pick -= weights[index];
    if (pick <= 0) return values[index];
  }
  return values.at(-1);
}

function runAdaptive(scenario, budget, seed, totalStates) {
  const started = performance.now();
  const rng = createRng(seed);
  const weights = Object.fromEntries(Object.entries(scenario.dimensions).map(([name, values]) => [name, values.map(() => 1)]));
  const evaluated = new Map();
  let batches = 0;
  while (evaluated.size < Math.min(budget, totalStates)) {
    const batch = [];
    const target = Math.min(12, budget - evaluated.size);
    let attempts = 0;
    while (batch.length < target && attempts < target * 40) {
      attempts += 1;
      const candidate = Object.fromEntries(Object.entries(scenario.dimensions).map(([name, values]) => [name, weightedChoice(values, weights[name], rng)]));
      const key = candidateKey(candidate);
      if (!evaluated.has(key) && !batch.some((item) => candidateKey(item) === key)) batch.push(candidate);
    }
    if (!batch.length) {
      const unseen = enumerateCandidates(scenario.dimensions).find((candidate) => !evaluated.has(candidateKey(candidate)));
      if (!unseen) break;
      batch.push(unseen);
    }
    const scored = batch.map((candidate) => evaluateCandidate(scenario, candidate));
    scored.forEach((result) => evaluated.set(candidateKey(result.candidate), result));
    const elite = [...scored].sort((a, b) => b.score - a.score).slice(0, Math.max(2, Math.ceil(scored.length / 4)));
    for (const [name, values] of Object.entries(scenario.dimensions)) {
      const counts = values.map((value) => elite.filter((result) => result.candidate[name] === value).length / elite.length);
      weights[name] = weights[name].map((weight, index) => Math.max(0.15, weight * Math.exp(0.55 * (counts[index] - 1 / values.length))));
      const total = weights[name].reduce((sum, value) => sum + value, 0);
      const probabilities = weights[name].map((value) => value / total);
      const entropy = -probabilities.reduce((sum, probability) => sum + probability * Math.log(Math.max(probability, 1e-12)), 0) / Math.log(values.length);
      if (entropy < 0.55) weights[name] = weights[name].map((weight) => weight * 0.75 + 0.25);
    }
    batches += 1;
  }
  return summarizeStrategy('adaptive_distribution', [...evaluated.values()], totalStates, started, { seed, batches });
}

export function minimizeFailure(scenario, result) {
  const requiredCodes = new Set(result.findings.map((finding) => finding.code));
  const baseline = Object.fromEntries(Object.entries(scenario.dimensions).map(([name, values]) => [name, values[0]]));
  let candidate = { ...result.candidate };
  for (const name of Object.keys(candidate).filter((key) => candidate[key] !== baseline[key])) {
    const attempt = { ...candidate, [name]: baseline[name] };
    const evaluated = evaluateCandidate(scenario, attempt);
    if ([...requiredCodes].every((code) => evaluated.findings.some((finding) => finding.code === code))) candidate = attempt;
  }
  const minimized = evaluateCandidate(scenario, candidate);
  return { ...minimized, changedDimensions: Object.keys(candidate).filter((name) => candidate[name] !== baseline[name]) };
}

export function runBreakLab(scenarioInput, { budget = 64, seed = 42 } = {}) {
  const scenario = validateScenario(structuredClone(scenarioInput));
  const allCandidates = enumerateCandidates(scenario.dimensions);
  const effectiveBudget = Math.max(1, Math.min(Number(budget), allCandidates.length));
  const strategies = [runRandom(scenario, effectiveBudget, seed, allCandidates.length), runPairwise(scenario, effectiveBudget, seed, allCandidates), runAnnealing(scenario, effectiveBudget, seed, allCandidates.length), runAdaptive(scenario, effectiveBudget, seed, allCandidates.length)];
  const ranked = [...strategies].sort((a, b) => b.maxSeverity - a.maxSeverity || b.uniqueFailureModes.length - a.uniqueFailureModes.length || b.failingConfigurations - a.failingConfigurations || a.runtimeMs - b.runtimeMs);
  const bestByCode = new Map();
  for (const strategy of strategies) {
    for (const [code, result] of Object.entries(strategy.bestFailuresByMode)) {
      const previous = bestByCode.get(code);
      if (!previous || result.score > previous.score) bestByCode.set(code, result);
    }
  }
  const counterexamples = [...bestByCode.entries()].map(([failureCode, result]) => ({ failureCode, ...minimizeFailure(scenario, result) }));
  const highestSeverity = Math.max(0, ...strategies.map((strategy) => strategy.maxSeverity));
  return {
    schema: 'pqc-forge.breaklab-run/v1', scenario: scenario.name, scenarioSchema: scenario.schema, seed: Number(seed),
    evaluationBudgetPerStrategy: effectiveBudget, totalStates: allCandidates.length, winner: ranked[0].strategy, strategies, counterexamples,
    verdict: { highestSeverity, failureModes: [...new Set(strategies.flatMap((strategy) => strategy.uniqueFailureModes))].sort(), pass: highestSeverity < Number(scenario.policy.failSeverity ?? 80) }
  };
}
