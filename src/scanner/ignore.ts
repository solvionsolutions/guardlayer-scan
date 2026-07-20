import ignore from "ignore";

/** The conventional ignore-file name at a repo root. */
export const IGNORE_FILE = ".guardlayerignore";

/**
 * Vendor/build output that is never the user's own code, so it's always
 * skipped. Deliberately conservative — we do NOT default-ignore test/fixture
 * paths, because silently skipping real code is the dangerous direction for a
 * security scanner. Teams exclude their own fixtures via .guardlayerignore.
 */
const ALWAYS_IGNORE = [
  "node_modules/",
  ".next/",
  ".git/",
  "dist/",
  "build/",
  "out/",
  "coverage/",
  IGNORE_FILE,
];

/**
 * Build a predicate from optional .guardlayerignore content. Returns
 * `(path) => true` when the file SHOULD be scanned (i.e. is NOT ignored).
 * Uses full gitignore syntax via the `ignore` package (globs, **, negation,
 * comments). Fails OPEN — on any matcher error a file is scanned, never
 * silently dropped, so a bad pattern can't hide vulnerable code.
 */
export function buildScanFilter(
  ignoreContent?: string | null
): (path: string) => boolean {
  const ig = ignore().add(ALWAYS_IGNORE);
  if (ignoreContent && ignoreContent.trim()) ig.add(ignoreContent);
  return (path: string): boolean => {
    const p = String(path ?? "")
      .replace(/\\/g, "/")
      .replace(/^\.?\/+/, "");
    if (!p) return false;
    try {
      return !ig.ignores(p);
    } catch {
      return true;
    }
  };
}
