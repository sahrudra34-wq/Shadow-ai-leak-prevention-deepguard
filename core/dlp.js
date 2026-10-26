const RULES = [
  { id: 'EMAIL', label: 'Email address', weight: 15, re: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi },
  { id: 'PHONE', label: 'Phone number', weight: 15, re: /(?:\+?91[-\s]?)?[6-9]\d{9}\b/g },
  { id: 'PAN', label: 'PAN-like identifier', weight: 32, re: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g },
  { id: 'AADHAAR', label: 'Aadhaar-like identifier', weight: 38, re: /\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b/g },
  { id: 'CARD', label: 'Payment card number', weight: 58, re: /\b(?:\d[ -]*?){13,19}\b/g, validate: luhnCandidate },
  { id: 'JWT', label: 'JWT token', weight: 70, re: /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g },
  { id: 'AWS_KEY', label: 'AWS access key', weight: 92, re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: 'PRIVATE_KEY', label: 'Private key', weight: 100, re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { id: 'API_KEY', label: 'API key / secret token', weight: 60, re: /\b(?:sk|pk|ghp|gho|github_pat|xoxb|xoxp|AIza|hf_|npm_|pypi-|SG\.)[-_A-Za-z0-9.]{12,}\b|\b(?:[A-Za-z0-9]+[_-])?api[_-]?key[_-][A-Za-z0-9]{8,}\b/gi },
  { id: 'BEARER_TOKEN', label: 'Bearer access token', weight: 65, re: /\bBearer\s+[A-Za-z0-9._~+\/-]{20,}=*/gi },
  { id: 'PASSWORD', label: 'Password / secret assignment', weight: 55, preservePrefix: true, re: /\b(?:password|passwd|pwd|secret)\s*[:=]\s*["']?[^\s"']{6,}["']?/gi },
  { id: 'NAME', label: 'Personal name', weight: 14, preservePrefix: true, re: /\b((?:full\s+name|first\s+name|last\s+name|name)\s*[:=]\s*)["']?[A-Za-z][A-Za-z.'-]{1,30}(?:\s+[A-Z][A-Za-z.'-]{1,30}){0,2}["']?/g },
  { id: 'ADDRESS', label: 'Personal address', weight: 18, preservePrefix: true, re: /\b((?:home\s+address|address|street\s+address)\s*[:=]\s*)["']?[^\n\r]{5,120}["']?/gi },
  { id: 'DOB', label: 'Date of birth', weight: 16, preservePrefix: true, re: /\b((?:date\s+of\s+birth|dob|birth\s*date)\s*[:=]\s*)["']?\d{1,4}[\/\-.]\d{1,2}[\/\-.]\d{1,4}["']?/gi },
  { id: 'PERSONAL_ID', label: 'Personal/customer ID', weight: 16, preservePrefix: true, re: /\b((?:customer\s+id|employee\s+id|student\s+id|user\s+id|personal\s+id)\s*[:=]\s*)["']?[A-Za-z0-9_-]{4,40}["']?/gi },
  { id: 'IP_ADDRESS', label: 'IP address', weight: 15, preservePrefix: true, re: /\b((?:ip\s*address|ip)\s*[:=]\s*)(?:\d{1,3}\.){3}\d{1,3}\b/gi },
  { id: 'DATABASE_URL', label: 'Database connection string', weight: 80, re: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[^\s"']+/gi },
  { id: 'INTERNAL_URL', label: 'Internal/private URL', weight: 42, re: /\bhttps?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b[^\s]*/gi },
  { id: 'SECRET_ASSIGNMENT', label: 'Secret-like assignment', weight: 40, re: /\b(?:token|api[_-]?key|client[_-]?secret|access[_-]?token|encryption[_-]?key)\s*[:=]\s*["']?[^\s"']{10,}["']?/gi },
  { id: 'SOURCE_CODE', label: 'Source-code / proprietary code indicator', weight: 24, re: /(?:```(?:javascript|typescript|python|java|go|csharp|cpp|rust|sql)?\s+[\s\S]{80,}```|\b(?:import|require)\s*\(|\bclass\s+\w+\s*\{|\bfunc\s+\w+\s*\(|\bdef\s+\w+\s*\()/gi },
  { id: 'PROMPT_INJECTION', label: 'Prompt injection indicator', weight: 22, re: /\b(?:ignore (?:all|any|previous) instructions|reveal system prompt|reveal secrets|jailbreak|developer message|bypass safety|disable safeguards)\b/gi }
];

// Inspired by the adversary-resistant normalization approach used by Prompt Gate:
// normalize look-alike Unicode and zero-width characters before matching.
const HOMOGLYPHS = new Map(Object.entries({
  'А':'A','а':'a','В':'B','Е':'E','е':'e','К':'K','М':'M','Н':'H','О':'O','о':'o','Р':'P','р':'p','С':'C','с':'c','Т':'T','Х':'X','х':'x','І':'I','і':'i','Ј':'J','ј':'j','Ѕ':'S','ѕ':'s','З':'3','з':'3','Ү':'Y','ү':'y',
  'Α':'A','Β':'B','Ε':'E','Ζ':'Z','Η':'H','Ι':'I','Κ':'K','Μ':'M','Ν':'N','Ο':'O','Ρ':'P','Τ':'T','Χ':'X','Υ':'Y','α':'a','β':'b','ο':'o','ρ':'p','τ':'t','χ':'x','υ':'y'
}));

function normalize(input) {
  return String(input ?? '')
    .normalize('NFKC')
    .replace(/[А-Яа-яЁёΑ-Ωα-ωІіЈјЅѕЗзҮү]/g, ch => HOMOGLYPHS.get(ch) || ch)
    .replace(/[\u200B-\u200D\uFEFF\u2060\u00AD]/g, '');
}

function luhnCandidate(value) {
  const digits = String(value).replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let parity = digits.length % 2;
  for (let i = 0; i < digits.length; i++) {
    let n = Number(digits[i]);
    if (i % 2 === parity) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
  }
  return sum % 10 === 0;
}

function publicExampleOnly(value) {
  const v = String(value).toLowerCase();
  return /^(test|example|placeholder|dummy|sample)[-_]/.test(v) || /@example\.com$/.test(v);
}

function scanPrompt(input, ctx = {}) {
  const text = normalize(input);
  const candidates = [];
  const secretRules = new Set(['API_KEY','AWS_KEY','BEARER_TOKEN','JWT','PRIVATE_KEY','PASSWORD','SECRET_ASSIGNMENT','DATABASE_URL']);

  for (const rule of RULES) {
    for (const match of text.matchAll(rule.re)) {
      const value = match[0];
      if (rule.validate && !rule.validate(value)) continue;
      const publicExample = publicExampleOnly(value);
      const effectiveWeight = rule.weight;
      candidates.push({
        id: rule.id,
        label: rule.label,
        weight: effectiveWeight,
        sample: mask(value),
        example: publicExample,
        start: Number(match.index ?? 0),
        end: Number(match.index ?? 0) + value.length
      });
    }
  }

  // Avoid scoring the same secret twice when a broad rule (e.g. SECRET_ASSIGNMENT)
  // overlaps a more specific rule (e.g. API_KEY/PASSWORD).
  candidates.sort((a, b) => b.weight - a.weight || a.start - b.start);
  const accepted = [];
  const seenValues = new Set();
  for (const item of candidates) {
    const sameValue = `${item.id}:${item.sample}`;
    if (seenValues.has(sameValue)) continue;
    const overlaps = accepted.some(x => item.start < x.end && item.end > x.start);
    if (overlaps) continue;
    accepted.push(item);
    seenValues.add(sameValue);
  }
  accepted.sort((a, b) => a.start - b.start);

  const volumeBonus = text.length > 8000 ? 8 : text.length > 4000 ? 5 : text.length > 2000 ? 2 : 0;
  const destination = String(ctx.destination || 'unknown').toLowerCase();
  const codeDestinationBias = /(?:github|gitlab|bitbucket|cursor|copilot|code)/.test(destination) ? -4 : 0;
  const weights = accepted.map(f => f.weight).sort((a, b) => b - a);
  let score = 0;
  if (weights.length) {
    // Base on the strongest finding, then add diminishing contributions from
    // additional findings. This prevents 4 ordinary PII fields from becoming 100.
    score = weights[0];
    for (let i = 1; i < weights.length; i++) score += Math.round(weights[i] * (i === 1 ? 0.25 : 0.12));
    score += Math.max(0, weights.length - 1) * 2;
  }
  score = Math.max(0, Math.min(100, score + volumeBonus + codeDestinationBias));

  const blockScore = Number(ctx.blockScore ?? 98);
  const redactScore = Number(ctx.redactScore ?? 10);
  const warnScore = Number(ctx.warnScore ?? 94);
  const hasCriticalSecret = accepted.some(f => ['PRIVATE_KEY','AWS_KEY','DATABASE_URL'].includes(f.id));
  // WARN is intentionally reserved for suspicious prompt/code behavior.
  // Ordinary PII, passwords and API keys should be REDACTed unless the
  // request is critical enough to BLOCK. This keeps normal protection useful
  // instead of turning every secret into an outright denial.
  const onlySuspicious = accepted.length > 0 && accepted.every(f => ['SOURCE_CODE','PROMPT_INJECTION'].includes(f.id));
  const action = hasCriticalSecret || score >= blockScore
    ? 'block'
    : onlySuspicious && score >= warnScore ? 'warn'
    : score >= redactScore ? 'redact'
    : 'allow';

  return {
    riskScore: score,
    severity: score >= blockScore ? 'critical' : score >= warnScore ? 'high' : score >= redactScore ? 'medium' : accepted.length ? 'low' : 'none',
    action,
    destination: ctx.destination || 'unknown',
    channel: ctx.channel || 'unknown',
    findings: accepted.map(({start, end, ...f}) => f),
    findingCount: accepted.length
  };
}

function mask(value) {
  const s = String(value);
  if (s.length <= 8) return '[REDACTED]';
  return `${s.slice(0, 3)}…${s.slice(-3)}`;
}

function redactText(input) {
  const text = normalize(input);
  const matches = [];
  for (const rule of RULES) {
    for (const match of text.matchAll(rule.re)) {
      const value = match[0];
      if (rule.validate && !rule.validate(value)) continue;
      const start = Number(match.index ?? 0);
      matches.push({ start, end: start + value.length, rule });
    }
  }
  // Prefer higher-risk/specific matches when rules overlap. Redact every
  // non-overlapping sensitive value found in the prompt; there is no arbitrary
  // per-prompt redaction-count limit.
  matches.sort((a, b) => b.rule.weight - a.rule.weight || a.start - b.start);
  const accepted = [];
  for (const item of matches) {
    if (accepted.some(x => item.start < x.end && item.end > x.start)) continue;
    accepted.push(item);
  }
  accepted.sort((a, b) => a.start - b.start);
  let out = text;
  for (let i = accepted.length - 1; i >= 0; i--) {
    const m = accepted[i];
    const raw = out.slice(m.start, m.end);
    const replacement = m.rule.preservePrefix ? raw.replace(/^(.*?[:=]\s*)[^:=]*$/, '$1[REDACTED_BY_DEEPGUARD]') : '[REDACTED_BY_DEEPGUARD]';
    out = out.slice(0, m.start) + replacement + out.slice(m.end);
  }
  return out;
}

if (require.main === module) console.log(JSON.stringify(scanPrompt(process.argv.slice(2).join(' ')), null, 2));
module.exports = { RULES, normalize, scanPrompt, redactText, luhnCandidate };
