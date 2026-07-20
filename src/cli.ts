/**
 * guardlayer-scan — GitHub Action entrypoint.
 *
 * Walks the checked-out repo, runs the GuardLayer static engine (the SAME
 * engine as guardlayer.io), and reports findings as inline PR annotations +
 * a job summary. Fails the build per the `fail-on` input. Free, no signup.
 */
import * as fs from "fs";
import * as path from "path";
import * as core from "@actions/core";
import { runScan, RULE_COUNT, ENGINE_VERSION } from "./scanner";
import type { ScanFile, Finding } from "./scanner";
import { isScannable } from "./scanner/helpers";

/** Mirror the hosted per-file cap so results match a real GuardLayer scan. */
const MAX_FILE_BYTES = 200_000;

const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  ".next",
  "dist",
  "build",
  "out",
  ".output",
  ".vercel",
  ".turbo",
  "coverage",
]);

function collect(root: string): { files: ScanFile[]; skippedLarge: number } {
  const files: ScanFile[] = [];
  let skippedLarge = 0;

  const walk = (dir: string) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        walk(full);
        continue;
      }
      if (!e.isFile()) continue;

      // POSIX-normalize — the engine's path rules (app/api/**,
      // supabase/migrations/*.sql, middleware.ts) are written for forward
      // slashes. A raw win32 path would silently miss every one of them.
      const rel = path.relative(root, full).split(path.sep).join("/");
      if (!isScannable(rel)) continue;

      let size = 0;
      try {
        size = fs.statSync(full).size;
      } catch {
        continue;
      }
      if (size > MAX_FILE_BYTES) {
        skippedLarge++;
        continue;
      }
      try {
        files.push({ path: rel, content: fs.readFileSync(full, "utf8") });
      } catch {
        /* unreadable / binary — skip */
      }
    }
  };

  walk(root);
  return { files, skippedLarge };
}

function readIgnore(root: string): string | null {
  try {
    return fs.readFileSync(path.join(root, ".guardlayerignore"), "utf8");
  } catch {
    return null;
  }
}

function annotate(f: Finding): void {
  const props = { file: f.file, startLine: f.line, title: `GuardLayer: ${f.title}` };
  const body =
    `${f.message}\n\nFix: ${f.recommendation}` + (f.cwe ? `  [${f.cwe}]` : "");
  if (f.severity === "critical") core.error(body, props);
  else if (f.severity === "warning") core.warning(body, props);
  else core.notice(body, props);
}

function main(): void {
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const failOn = (core.getInput("fail-on") || "critical").trim().toLowerCase();

  const { files, skippedLarge } = collect(workspace);
  const report = runScan(files, {
    id: "guardlayer-action",
    name: process.env.GITHUB_REPOSITORY || "repository",
    now: new Date().toISOString(),
    ignoreContent: readIgnore(workspace),
  });
  const { summary, findings } = report;

  // Inline annotations on the exact file+line (show up in the PR "Files
  // changed" tab and the checks UI).
  for (const f of findings) annotate(f);

  // Console log — grouped, readable.
  const icon = (s: string) => (s === "critical" ? "✖" : s === "warning" ? "▲" : "•");
  core.info(
    `\nGuardLayer scanned ${summary.filesScanned} files with ${RULE_COUNT} checks (engine ${ENGINE_VERSION}).`
  );
  core.info(
    `Score ${summary.score}/100 (${summary.grade}) · ${summary.critical} critical · ${summary.warning} warning · ${summary.info} info` +
      (skippedLarge ? ` · ${skippedLarge} large files skipped` : "")
  );
  for (const f of findings) {
    core.info(
      `  ${icon(f.severity)} [${f.severity}] ${f.file}:${f.line}  ${f.ruleId}\n      ${f.message}`
    );
  }
  if (findings.length === 0) core.info("  No issues found. ✔");

  // Rich job summary (rendered on the workflow run page). Only available on a
  // real runner, where GITHUB_STEP_SUMMARY points at the summary file; write()
  // is async, so swallow any rejection rather than leak an unhandled one.
  if (process.env.GITHUB_STEP_SUMMARY) {
    try {
      core.summary
        .addHeading(`GuardLayer scan — score ${summary.score}/100 (${summary.grade})`, 2)
        .addRaw(
          `${summary.critical} critical · ${summary.warning} warning · ${summary.info} info — across ${summary.filesScanned} files, ${RULE_COUNT} checks.\n\n`
        );
      if (findings.length > 0) {
        core.summary.addTable([
          [
            { data: "Severity", header: true },
            { data: "Rule", header: true },
            { data: "Location", header: true },
            { data: "Issue", header: true },
          ],
          ...findings.slice(0, 100).map((f) => [
            f.severity,
            `\`${f.ruleId}\``,
            `\`${f.file}:${f.line}\``,
            f.message,
          ]),
        ]);
      } else {
        core.summary.addRaw("No issues found. ✔");
      }
      core.summary.addRaw(
        `\n\n— [GuardLayer](https://www.guardlayer.io) · free static security scanner for Next.js + Supabase`
      );
      void core.summary.write().catch(() => {});
    } catch {
      /* summary is best-effort */
    }
  }

  core.setOutput("score", String(summary.score));
  core.setOutput("grade", summary.grade);
  core.setOutput("critical", String(summary.critical));
  core.setOutput("warning", String(summary.warning));
  core.setOutput("findings", String(summary.totalFindings));

  const shouldFail =
    failOn === "never"
      ? false
      : failOn === "warning"
        ? summary.critical + summary.warning > 0
        : summary.critical > 0; // default: critical

  if (shouldFail) {
    core.setFailed(
      `GuardLayer found ${summary.critical} critical and ${summary.warning} warning issue(s). ` +
        `See the annotations above, or scan with the exact fixes at https://www.guardlayer.io/scan`
    );
  } else {
    core.info("GuardLayer check passed.");
  }
}

try {
  main();
} catch (err) {
  core.setFailed(`guardlayer-scan crashed: ${err instanceof Error ? err.message : String(err)}`);
}
