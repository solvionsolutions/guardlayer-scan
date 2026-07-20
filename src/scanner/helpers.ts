import type { RuleMatch, ScanFile } from "./types";

/** Map a 0-based string index to a 1-based line number. */
export function lineAt(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === "\n") line++;
  }
  return line;
}

/** Column (1-based) of an index within its line. */
export function columnAt(content: string, index: number): number {
  let col = 1;
  for (let i = index - 1; i >= 0; i--) {
    if (content[i] === "\n") break;
    col++;
  }
  return col;
}

const SNIPPET_CAP = 200;

/** Extract and tidy the source line containing `index`. */
export function snippetAt(content: string, index: number): string {
  const start = content.lastIndexOf("\n", index - 1) + 1;
  let end = content.indexOf("\n", index);
  if (end === -1) end = content.length;
  const raw = content.slice(start, end).trim();
  return raw.length > SNIPPET_CAP ? raw.slice(0, SNIPPET_CAP) + "…" : raw;
}

/**
 * Run a regex over a whole file and return one RuleMatch per hit, with
 * accurate line/column/snippet. The regex MUST be global (`g`).
 */
export function matchAll(
  file: ScanFile,
  regex: RegExp,
  build?: (m: RegExpExecArray) => Partial<RuleMatch> | void
): RuleMatch[] {
  const out: RuleMatch[] = [];
  const content = file.content;
  let m: RegExpExecArray | null;
  // Defensive: ensure global flag so exec advances.
  const re = regex.global ? regex : new RegExp(regex.source, regex.flags + "g");
  re.lastIndex = 0;
  let guard = 0;
  while ((m = re.exec(content)) !== null) {
    if (++guard > 5000) break; // pathological input guard
    // Skip zero-width matches outright: advance and don't record a spurious
    // finding. Keeps matchAll correct for any future rule whose regex can
    // match the empty string.
    if (m[0].length === 0) {
      re.lastIndex++;
      continue;
    }
    const extra = build ? build(m) || {} : {};
    out.push({
      line: lineAt(content, m.index),
      column: columnAt(content, m.index),
      snippet: snippetAt(content, m.index),
      ...extra,
    });
  }
  return out;
}

/** Per-line scan: invoke `test` on each line; collect matches. */
export function matchLines(
  file: ScanFile,
  test: (line: string, lineNo: number) => Omit<RuleMatch, "line" | "snippet"> | null
): RuleMatch[] {
  const out: RuleMatch[] = [];
  const lines = file.content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const res = test(lines[i], i + 1);
    if (res) {
      const raw = lines[i].trim();
      out.push({
        line: i + 1,
        snippet: raw.length > SNIPPET_CAP ? raw.slice(0, SNIPPET_CAP) + "…" : raw,
        ...res,
      });
    }
  }
  return out;
}

/** Best-effort language label from the file extension. */
export function languageOf(path: string): string {
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  const map: Record<string, string> = {
    ts: "typescript",
    tsx: "tsx",
    js: "javascript",
    jsx: "jsx",
    mjs: "javascript",
    cjs: "javascript",
    sql: "sql",
    json: "json",
    env: "dotenv",
    py: "python",
    go: "go",
    rb: "ruby",
    php: "php",
    yml: "yaml",
    yaml: "yaml",
    toml: "toml",
    sh: "bash",
  };
  if (path.endsWith(".env") || path.includes(".env.")) return "dotenv";
  return map[ext] ?? "text";
}

const CODE_EXT = new Set([
  "ts",
  "tsx",
  "js",
  "jsx",
  "mjs",
  "cjs",
  "sql",
  "json",
  "env",
  "py",
  "go",
  "rb",
  "php",
  "yml",
  "yaml",
  "toml",
  "sh",
  "txt",
]);

/** Should this path be scanned at all (skip binaries, lockfiles, vendored)? */
export function isScannable(path: string): boolean {
  const lower = path.toLowerCase();
  if (
    lower.includes("/node_modules/") ||
    lower.startsWith("node_modules/") ||
    lower.includes("/.next/") ||
    lower.includes("/dist/") ||
    lower.includes("/.git/") ||
    lower.endsWith("package-lock.json") ||
    lower.endsWith("pnpm-lock.yaml") ||
    lower.endsWith("yarn.lock")
  ) {
    return false;
  }
  if (lower.endsWith(".env") || lower.includes(".env.")) return true;
  const ext = lower.split(".").pop() ?? "";
  return CODE_EXT.has(ext);
}

/** True when a TS/JS file runs on the client (`"use client"` directive). */
export function isClientComponent(content: string): boolean {
  // Directive must be near the top, before imports.
  const head = content.slice(0, 400);
  return /^[\s\n]*['"]use client['"]/.test(head) || /\n\s*['"]use client['"]/.test(head);
}

/** True when a TS/JS file declares a Server Action context. */
export function hasUseServer(content: string): boolean {
  return /['"]use server['"]/.test(content);
}

/**
 * Recognise obvious non-secrets so the hardcoded-secret rule stays precise.
 * Placeholders, env references, and example values are ignored.
 */
export function looksLikePlaceholder(value: string): boolean {
  const v = value.toLowerCase();
  // Strong, unambiguous markers — substring match is fine.
  if (
    v.includes("process.env") ||
    v.includes("import.meta.env") ||
    v.includes("your_") ||
    v.includes("your-") ||
    v.includes("placeholder") ||
    v.includes("changeme") ||
    v.includes("change_me") ||
    v.includes("xxxx") ||
    v.includes("...") ||
    v.includes("<") ||
    v.includes("${") ||
    v.includes("redacted") ||
    /^[*•x]+$/.test(v) ||
    v.length < 8
  ) {
    return true;
  }
  // Weak words (test/sample/dummy/example/fake) only count as placeholders
  // when they appear as standalone tokens — not as base62 noise inside a real
  // secret (e.g. "attestation", "latest") which would suppress a live key.
  return /(?:^|[^a-z0-9])(?:test|sample|dummy|example|fake|demo)(?:[^a-z0-9]|$)/.test(
    v
  );
}

/** Is this path a Supabase edge function? */
export function isEdgeFunction(path: string): boolean {
  return /supabase[\/\\]functions[\/\\]/.test(path);
}

/** Is this path a Next.js API route handler? */
export function isApiRoute(path: string): boolean {
  return /app[\/\\].*route\.(ts|js|tsx|jsx)$/.test(path) || /pages[\/\\]api[\/\\]/.test(path);
}

/** Is this a SQL/migration file? */
export function isSql(path: string): boolean {
  return path.toLowerCase().endsWith(".sql");
}

/**
 * Blank out JS/TS comments while PRESERVING line structure (so line numbers
 * computed against the original content still line up). Used by prose-sensitive
 * rules so a defensive comment that merely mentions a term isn't flagged.
 */
export function stripJsComments(content: string): string {
  // Block comments: replace with same number of newlines + spaces.
  let out = content.replace(/\/\*[\s\S]*?\*\//g, (block) =>
    block.replace(/[^\n]/g, " ")
  );
  // Line comments (avoid http:// by requiring the // not be preceded by ':').
  out = out.replace(/([^:"'`\n]|^)\/\/[^\n]*/g, (_m, p1: string) => p1);
  return out;
}
