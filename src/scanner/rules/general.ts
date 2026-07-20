import type { Rule, RuleMatch, ScanFile } from "../types";
import {
  looksLikePlaceholder,
  matchAll,
  matchLines,
  snippetAt,
  lineAt,
  columnAt,
} from "../helpers";

const isJsLike = (f: ScanFile) => /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.path);

/** High-precision provider secret patterns. */
const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { name: "OpenAI API key", re: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b/g },
  { name: "Stripe secret key", re: /\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b/g },
  { name: "GitHub token", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}\b/g },
  { name: "GitHub fine-grained PAT", re: /\bgithub_pat_[0-9A-Za-z_]{50,}\b/g },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: "Slack token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { name: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  {
    name: "Private key block",
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
  },
  // Note: Twilio Account SID (AC+32hex) intentionally NOT included — it is a
  // public identifier, not a secret, and collides with md5-like cache keys.
];

// Firebase web apps embed a public `apiKey` (AIza…) by design; suppress the
// Google-API-key pattern when the file is clearly Firebase config.
const FIREBASE_MARKER =
  /firebaseConfig|initializeApp|authDomain|firebase\/app|getFirestore|getAuth\(|firebase/i;

// Known PUBLIC key prefixes — safe to commit, must not be flagged as secrets.
const PUBLIC_KEY_PREFIX = /^(pk_|sb_publishable_|pub_|pk\.eyJ|6L[0-9A-Za-z_-]{38})/;
// Stripe ephemeral client secrets are designed to be sent to the browser.
const STRIPE_CLIENT_SECRET = /^(pi|seti)_[A-Za-z0-9]+_secret_[A-Za-z0-9]+$/;

/** Curated, conservative advisory list (sample set for the MVP).
 *  `fixedBelow` = a single global floor (simple deps). `fixedByMajor` = a floor
 *  per major release branch, for packages (like Next.js) that backport fixes to
 *  several maintained majors — a single global floor there is WRONG, because a
 *  higher major always compares "greater" and slips through even when it has its
 *  own known-vulnerable range. */
const KNOWN_VULN_DEPS: {
  name: string;
  fixedBelow?: [number, number, number];
  fixedByMajor?: Record<number, [number, number, number]>;
  advisory: string;
}[] = [
  {
    name: "next",
    // Next.js maintains parallel branches. Patched floors: 15.5.18 and 16.2.6
    // (the May-2026 set + CVE-2025-29927). 14.x and older got no fix for the
    // latest set, so any major below 15 is flagged outright.
    fixedByMajor: { 15: [15, 5, 18], 16: [16, 2, 6] },
    advisory:
      "Next.js middleware/proxy bypass, SSRF, cache poisoning and DoS advisories (incl. CVE-2025-29927 and the May 2026 release) — patch to 15.5.18+ or 16.2.6+; 14.x and older have no fix branch.",
  },
  { name: "lodash", fixedBelow: [4, 17, 21], advisory: "Prototype pollution / ReDoS fixed in lodash 4.17.21." },
  { name: "axios", fixedBelow: [1, 8, 0], advisory: "SSRF / credential leak advisories fixed in axios 1.8.0." },
  { name: "jsonwebtoken", fixedBelow: [9, 0, 0], advisory: "Signature bypass issues fixed in jsonwebtoken 9.0.0." },
  { name: "minimist", fixedBelow: [1, 2, 6], advisory: "Prototype pollution fixed in minimist 1.2.6." },
  { name: "semver", fixedBelow: [7, 5, 2], advisory: "ReDoS fixed in semver 7.5.2." },
  { name: "ws", fixedBelow: [8, 17, 1], advisory: "DoS via many headers fixed in ws 8.17.1." },
];

function parseVersion(v: string): [number, number, number] | null {
  const cleaned = v.replace(/^[\^~>=<\s]+/, "").trim();
  const m = cleaned.match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function lt(a: [number, number, number], b: [number, number, number]): boolean {
  for (let i = 0; i < 3; i++) {
    if (a[i] < b[i]) return true;
    if (a[i] > b[i]) return false;
  }
  return false;
}

/** The patched version an advisory says to reach, if `ver` is vulnerable — else
 *  null. Handles both a single global floor and per-major branch floors. */
function depFixTarget(
  ver: [number, number, number],
  adv: {
    fixedBelow?: [number, number, number];
    fixedByMajor?: Record<number, [number, number, number]>;
  }
): [number, number, number] | null {
  if (adv.fixedByMajor) {
    const major = ver[0];
    const own = adv.fixedByMajor[major];
    if (own) return lt(ver, own) ? own : null;
    const majors = Object.keys(adv.fixedByMajor).map(Number);
    const minMajor = Math.min(...majors);
    // Older than any patched branch → no fix exists for it: flag, pointing at
    // the lowest maintained branch. Newer than every known branch → assume the
    // future major carries the fix, so stay silent (precision over coverage).
    if (major < minMajor) return adv.fixedByMajor[minMajor];
    return null;
  }
  if (adv.fixedBelow) return lt(ver, adv.fixedBelow) ? adv.fixedBelow : null;
  return null;
}

export const generalRules: Rule[] = [
  // ──────────────────────────────────────────────────────────────────────
  // CRITICAL — hardcoded provider secret
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "general/hardcoded-secret",
    title: "Hardcoded secret in source",
    severity: "critical",
    category: "general",
    cwe: "CWE-798",
    message:
      "A credential that matches a known provider format is hardcoded in source. Anything committed to git is effectively public to anyone who can read the repo or its history.",
    recommendation:
      "Move the secret to an environment variable, purge it from git history (e.g. git filter-repo / BFG), and rotate it at the provider.",
    scan: (f) => {
      const out: RuleMatch[] = [];
      const firebaseCtx = FIREBASE_MARKER.test(f.content);
      for (const { name, re } of SECRET_PATTERNS) {
        const rx = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
        rx.lastIndex = 0;
        let m: RegExpExecArray | null;
        let guard = 0;
        while ((m = rx.exec(f.content)) !== null) {
          if (++guard > 1000) break;
          const token = m[0];
          // Firebase public web apiKey — not a secret.
          if (name === "Google API key" && firebaseCtx) continue;
          // Placeholder-check the matched TOKEN, never the whole line.
          if (name !== "Private key block" && looksLikePlaceholder(token)) continue;
          out.push({
            line: lineAt(f.content, m.index),
            column: columnAt(f.content, m.index),
            snippet: snippetAt(f.content, m.index),
            message: `${name} detected in source.`,
          });
        }
      }
      return out;
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // CRITICAL — generic assigned secret (key/token/password = "literal")
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "general/assigned-secret-literal",
    title: "Credential assigned to a string literal",
    severity: "critical",
    category: "general",
    cwe: "CWE-798",
    message:
      "A variable named like a secret (apiKey / token / password / secret) is assigned a long string literal. This is a hardcoded credential rather than a configuration reference.",
    recommendation:
      "Replace the literal with process.env.<NAME>, keep the real value in an untracked .env, and rotate the exposed value.",
    appliesTo: (f) =>
      isJsLike(f) || /\.(json|yml|yaml|env)$/.test(f.path) || /\.env/.test(f.path),
    scan: (f) => {
      const firebaseCtx = FIREBASE_MARKER.test(f.content);
      return matchLines(f, (line) => {
        // Optional identifier prefix so dbPassword / myApiKey / stripeSecret
        // are caught, not just the bare keyword.
        const m = line.match(
          /(?:^|[^A-Za-z0-9_])([A-Za-z0-9_]*?(?:api[_-]?key|secret|token|password|passwd|pwd|access[_-]?token|auth[_-]?token))\s*[:=]\s*["'`]([^"'`]{12,})["'`]/i
        );
        if (!m) return null;
        const value = m[2];
        if (looksLikePlaceholder(value)) return null;
        if (/\s/.test(value)) return null; // UI/i18n/help copy, design tokens
        if (PUBLIC_KEY_PREFIX.test(value)) return null; // publishable/public keys
        // A Supabase anon/publishable JWT (eyJ….eyJ….) is PUBLIC by design and
        // safe to commit — measured as the #1 false positive on AI-built Supabase
        // apps (they hardcode it in vite.config/client). Skip it here; the
        // dangerous variant, a service_role JWT, still fires — its payload carries
        // the service_role marker (and supabase/service-role-jwt-literal catches it).
        if (
          /^eyJ[A-Za-z0-9_-]+\.eyJ/.test(value) &&
          !/service_role|c2VydmljZV9yb2xl/.test(value)
        ) {
          return null;
        }
        if (STRIPE_CLIENT_SECRET.test(value)) return null; // ephemeral client secret
        // Firebase web apiKey (AIza…) is public by design.
        if (firebaseCtx && /^AIza[0-9A-Za-z_-]{35}$/.test(value)) return null;
        // Require credential-like structure (some entropy), not a plain word.
        if (!/[0-9]/.test(value) && !/[A-Z]/.test(value) && value.length < 24) {
          return null;
        }
        return {
          column: (m.index ?? 0) + 1,
          message: `Hardcoded value assigned to "${m[1]}".`,
        };
      });
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — known-vulnerable dependency
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "general/vulnerable-dependency",
    title: "Dependency with a known advisory",
    severity: "warning",
    category: "general",
    cwe: "CWE-1395",
    message:
      "A dependency is pinned below a version that fixes a known security advisory.",
    recommendation:
      "Upgrade to the patched version and run npm audit to confirm the advisory is resolved.",
    appliesTo: (f) => /(^|[\/\\])package\.json$/.test(f.path),
    scan: (f) => {
      let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
      try {
        pkg = JSON.parse(f.content);
      } catch {
        return [];
      }
      // Pull only the two known keys — never spread arbitrary uploaded JSON
      // into an object (prototype-pollution hygiene).
      const deps: Record<string, string> = {};
      if (pkg && typeof pkg.dependencies === "object") {
        for (const [k, v] of Object.entries(pkg.dependencies)) {
          if (k !== "__proto__") deps[k] = v as string;
        }
      }
      if (pkg && typeof pkg.devDependencies === "object") {
        for (const [k, v] of Object.entries(pkg.devDependencies)) {
          if (k !== "__proto__" && !(k in deps)) deps[k] = v as string;
        }
      }
      const out: RuleMatch[] = [];
      for (const adv of KNOWN_VULN_DEPS) {
        const raw = deps[adv.name];
        if (!raw || typeof raw !== "string") continue;
        const ver = parseVersion(raw);
        if (!ver) continue;
        const target = depFixTarget(ver, adv);
        if (target) {
          const idx = f.content.indexOf(`"${adv.name}"`);
          out.push({
            line: idx >= 0 ? lineAt(f.content, idx) : 1,
            snippet:
              idx >= 0 ? snippetAt(f.content, idx) : `"${adv.name}": "${raw}"`,
            message: `${adv.name}@${raw}: ${adv.advisory} (upgrade to >= ${target.join(".")}).`,
          });
        }
      }
      return out;
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — SQL built by string interpolation / concatenation
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "general/sql-injection",
    title: "Possible SQL injection",
    severity: "warning",
    category: "general",
    cwe: "CWE-89",
    message:
      "A SQL statement is assembled with template interpolation or string concatenation. User-controlled values spliced into SQL text enable injection.",
    recommendation:
      "Use parameterised queries / prepared statements (placeholders + bound values) instead of building SQL strings. With Supabase prefer the query builder or .rpc() with typed args.",
    appliesTo: (f) => isJsLike(f),
    scan: (f) => {
      const out: RuleMatch[] = [];
      // Template literal that contains a DML statement AND an interpolation.
      // Every run is bounded and newline-excluded => ReDoS-safe. The negative
      // lookbehind excludes parameterised tagged templates (sql`…`), which are
      // safe. Requiring a real DML verb (not a bare WHERE/FROM) avoids flagging
      // ordinary prose that happens to contain SQL keywords.
      // A REAL SQL statement shape, not a bare keyword: SELECT…FROM, INSERT
      // INTO, UPDATE…SET, DELETE FROM. Requiring the companion keyword stops
      // ordinary prose ("An update about …", "select an option") from matching.
      out.push(
        ...matchAll(
          f,
          /(?<![A-Za-z0-9_$.])`\s*(?:SELECT\s+\*\s+FROM\b|SELECT\b[^`\n]{1,200}\bFROM\b[^`\n]{0,200}\b(?:WHERE|JOIN|GROUP|ORDER|LIMIT|HAVING|UNION)\b|INSERT\s+INTO\b|UPDATE\b[^`\n]{1,150}\bSET\b|DELETE\s+FROM\b)[^`\n]{0,250}\$\{[^}\n]{1,150}\}[^`\n]{0,150}`/gi
        )
      );
      // Concatenation: "<sql shape>" + variable
      out.push(
        ...matchAll(
          f,
          /["']\s*(?:SELECT\s+\*\s+FROM\b|SELECT\b[^"'\n]{1,200}\bFROM\b[^"'\n]{0,200}\b(?:WHERE|JOIN|GROUP|ORDER|LIMIT|HAVING|UNION)\b|INSERT\s+INTO\b|UPDATE\b[^"'\n]{1,150}\bSET\b|DELETE\s+FROM\b)[^"'\n]{0,200}["']\s*\+\s*[A-Za-z_$]/gi
        )
      );
      return out;
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — eval / Function constructor
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "general/dangerous-eval",
    title: "Use of eval()",
    severity: "warning",
    category: "general",
    cwe: "CWE-95",
    message:
      "eval() (or the Function constructor) executes arbitrary code. If any part of the argument is attacker-influenced, this is remote code execution.",
    recommendation:
      "Remove eval()/new Function(). Parse data with JSON.parse, dispatch via a lookup table, or use a safe expression evaluator.",
    appliesTo: (f) => isJsLike(f),
    // Require a non-empty argument so the bare word "eval()" in prose, strings,
    // docs, or comments about security isn't flagged — only real calls.
    scan: (f) => matchAll(f, /\beval\s*\(\s*[^)\s]|new\s+Function\s*\(\s*[^)\s]/g),
  },

  // ──────────────────────────────────────────────────────────────────────
  // INFO — dangerouslySetInnerHTML (potential XSS)
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "general/dangerous-inner-html",
    title: "dangerouslySetInnerHTML usage",
    severity: "info",
    category: "general",
    cwe: "CWE-79",
    message:
      "dangerouslySetInnerHTML injects raw HTML, bypassing React's escaping. If the HTML includes any user-provided content it becomes a stored/reflected XSS vector.",
    recommendation:
      "Avoid raw HTML where possible. If you must render it, sanitise first with a vetted library (e.g. DOMPurify) and never pass unsanitised user input.",
    appliesTo: (f) => /\.(tsx|jsx)$/.test(f.path),
    // Require the JSX prop assignment so prose mentioning the API isn't flagged.
    scan: (f) => {
      const out: RuleMatch[] = [];
      const re = /dangerouslySetInnerHTML\s*=/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(f.content)) !== null) {
        // Exempt JSON-LD structured-data scripts — the universal, SAFE pattern
        // (<script type="application/ld+json" dangerouslySetInnerHTML=...>): the
        // payload is serialized data, not author-written markup. Confirm the
        // ld+json type sits in the SAME unclosed tag (no '>' between it and the
        // prop), so an unrelated dangerouslySetInnerHTML nearby still flags.
        const before = f.content.slice(Math.max(0, m.index - 300), m.index);
        const ld = before.lastIndexOf("application/ld+json");
        if (ld !== -1 && !before.slice(ld).includes(">")) continue;
        out.push({
          line: lineAt(f.content, m.index),
          column: columnAt(f.content, m.index),
          snippet: snippetAt(f.content, m.index),
        });
      }
      return out;
    },
  },
];
