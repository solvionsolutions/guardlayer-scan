import type { Rule, RuleMatch, ScanFile } from "../types";
import {
  looksLikePlaceholder,
  matchAll,
  matchLines,
  lineAt,
  columnAt,
  snippetAt,
} from "../helpers";

/**
 * MCP / AI-agent config rules.
 *
 * The big agent footgun is the "lethal trifecta": an agent that has (1) access
 * to private data, (2) exposure to untrusted input, and (3) a way to act/
 * exfiltrate. Statically we can catch (1) — an over-privileged agent — and the
 * secrets people routinely commit into agent config files.
 */

/** A known MCP config filename, or any JSON/YAML that declares an `mcpServers`
 *  block (the canonical MCP key used by Claude Desktop, Cursor, Cline, etc.). */
const MCP_FILE =
  /(^|[/\\])(\.?mcp(?:[._-]?config)?\.json|claude_desktop_config\.json|mcp[._-]?servers?\.json|cline_mcp_settings\.json)$/i;

const isMcpConfig = (f: ScanFile) =>
  MCP_FILE.test(f.path) ||
  (/\.(jsonc?|ya?ml)$/i.test(f.path) && /["']?mcpServers["']?\s*:/.test(f.content));

const DB_URL_WITH_PW =
  /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|mssql|sqlserver):\/\/[^:@\s/"']+:([^@\s/"']+)@/gi;

export const mcpRules: Rule[] = [
  // ──────────────────────────────────────────────────────────────────────
  // CRITICAL — service_role key handed to an AI agent (the lethal trifecta)
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "mcp/service-role-in-config",
    title: "service_role key exposed to an AI agent",
    severity: "critical",
    category: "mcp",
    cwe: "CWE-269",
    message:
      "An MCP server / AI agent is configured with the Supabase service_role key, which bypasses Row Level Security. An agent that also sees untrusted input (the 'lethal trifecta') can be prompt-injected into reading or modifying your entire database.",
    recommendation:
      "Never hand an agent the service_role key. Give it a scoped key / a dedicated DB role with RLS enforced, and put any privileged action behind a narrow tool the agent can't be tricked into calling with arbitrary arguments.",
    appliesTo: isMcpConfig,
    scan: (f) => matchAll(f, /SUPABASE_SERVICE_ROLE_KEY|\bservice_role\b/gi),
  },

  // ──────────────────────────────────────────────────────────────────────
  // CRITICAL — a secret hardcoded into an agent config file
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "mcp/secret-in-config",
    title: "Hardcoded secret in an MCP / agent config",
    severity: "critical",
    category: "mcp",
    cwe: "CWE-798",
    message:
      "A credential is hardcoded in an MCP server / AI-agent config. These files get committed, so the value is exposed to anyone with repo access — and to the agent itself.",
    recommendation:
      "Reference the value from an environment variable instead (e.g. \"env\": { \"X\": \"${X}\" }), keep the real secret in an untracked .env, and rotate anything already committed.",
    appliesTo: isMcpConfig,
    scan: (f) => {
      const out: RuleMatch[] = [];

      // (a) a database connection string with an inline password
      const re = new RegExp(DB_URL_WITH_PW.source, "gi");
      let m: RegExpExecArray | null;
      let guard = 0;
      while ((m = re.exec(f.content)) !== null) {
        if (++guard > 1000) break;
        const pw = m[1];
        if (looksLikePlaceholder(pw) || pw.length < 4) continue;
        if (/^[$%{]/.test(pw)) continue; // ${VAR} / %VAR% reference, not hardcoded
        out.push({
          line: lineAt(f.content, m.index),
          column: columnAt(f.content, m.index),
          snippet: snippetAt(f.content, m.index),
          message: "Database connection string with an inline password.",
        });
      }

      // (b) a credential-named field assigned a hardcoded literal value
      out.push(
        ...matchLines(f, (line) => {
          // Keys general/assigned-secret-literal already covers (secret/token/
          // password/api_key) are left to that rule — we catch the gaps it
          // misses in agent configs: *_key, PAT, credentials, DSN.
          const mm = line.match(
            /["']?([A-Za-z0-9_]*(?:[_-]key|pat|credentials?|dsn))["']?\s*:\s*["']([^"']{12,})["']/i
          );
          if (!mm) return null;
          const value = mm[2];
          if (looksLikePlaceholder(value)) return null;
          if (/\s/.test(value)) return null; // prose / help text, not a token
          if (/^[$%{]/.test(value)) return null; // ${VAR} reference
          if (/^(pk_|sb_publishable_|pub_)/.test(value)) return null; // public keys
          // Provider-format secrets are caught by general/hardcoded-secret — don't
          // double-flag them here.
          if (/^(sk-|sk_live_|rk_live_|gh[opusr]_|github_pat_|AKIA|AIza|xox[baprs]-|SG\.)/.test(value)) {
            return null;
          }
          // Require some entropy so a plain word isn't flagged.
          if (!/[0-9]/.test(value) && !/[A-Z]/.test(value) && value.length < 24) {
            return null;
          }
          return {
            column: (mm.index ?? 0) + 1,
            message: `Hardcoded credential assigned to "${mm[1]}".`,
          };
        })
      );

      return out;
    },
  },
];
