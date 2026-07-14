/**
 * CLI argument parsing. Pure: takes argv, returns an options value or
 * throws `CliError` — the CLI maps that to exit code 2. Kept apart from
 * cli.ts so every flag and rejection path is unit-testable without
 * spawning a process.
 */
import type { DeliveryContext, FailLevel } from "./types.js";

export class CliError extends Error {}

export type Command = "check" | "coverage" | "explain" | "help" | "version";

export interface CliOptions {
  command: Command;
  /** Raw policy string given on the command line ("-" means stdin). */
  policy: string | null;
  /** Files to read policies from (via --file). */
  files: string[];
  /** Topic for the explain command. */
  topic: string | null;
  format: "text" | "json";
  failOn: FailLevel;
  context: DeliveryContext;
  quiet: boolean;
}

export const HELP_TEXT = `cspdoctor — parse a Content-Security-Policy and flag what weakens it

Usage:
  cspdoctor check [policy] [flags]     lint a policy string, --file, or "-" (stdin)
  cspdoctor coverage [policy] [flags]  show which directive governs each load context
  cspdoctor explain <topic>            explain a rule code, directive, or keyword

Input:
  [policy] is a raw policy value in one argument (quote it!), or "-" for stdin.
  --file <path> reads a raw policy or saved header lines; repeatable.
  Content-Security-Policy[-Report-Only]: header names are stripped
  automatically, and each header line is checked as its own policy.

Flags:
  --file <path>          read the policy from a file ("-" reads stdin)
  --format text|json     output format (default: text)
  --fail-on <level>      exit 1 at or above: error, warning, info, never
                         (default: warning)
  --context header|meta  how the policy is delivered (default: header)
  -q, --quiet            per-policy summary lines only
  -h, --help             show this help
  -V, --version          print the version

Exit codes:
  0  no findings at or above --fail-on
  1  findings at or above --fail-on
  2  usage or input error

Explain topics: rule codes (E110), directives (script-src), keywords
(strict-dynamic, nonce), or: fallbacks, strict-csp, exit-codes, meta,
report-only.
`;

const COMMANDS: ReadonlySet<string> = new Set(["check", "coverage", "explain"]);

/** Parse argv (without the node/script prefix) into CliOptions. */
export function parseCliArgs(argv: readonly string[]): CliOptions {
  const options: CliOptions = {
    command: "check",
    policy: null,
    files: [],
    topic: null,
    format: "text",
    failOn: "warning",
    context: "header",
    quiet: false,
  };

  const positionals: string[] = [];
  let commandSet = false;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === undefined) continue;

    if (arg === "-h" || arg === "--help") return { ...options, command: "help" };
    if (arg === "-V" || arg === "--version") return { ...options, command: "version" };

    if (!commandSet && positionals.length === 0 && COMMANDS.has(arg)) {
      options.command = arg as Command;
      commandSet = true;
      continue;
    }

    if (arg === "-q" || arg === "--quiet") {
      options.quiet = true;
      continue;
    }

    const [flag, inlineValue] = splitInline(arg);
    switch (flag) {
      case "--file":
        options.files.push(requireValue(flag, inlineValue ?? argv[++i]));
        continue;
      case "--format":
        options.format = oneOf(flag, requireValue(flag, inlineValue ?? argv[++i]), [
          "text",
          "json",
        ] as const);
        continue;
      case "--fail-on":
        options.failOn = oneOf(flag, requireValue(flag, inlineValue ?? argv[++i]), [
          "error",
          "warning",
          "info",
          "never",
        ] as const);
        continue;
      case "--context":
        options.context = oneOf(flag, requireValue(flag, inlineValue ?? argv[++i]), [
          "header",
          "meta",
        ] as const);
        continue;
      default:
        break;
    }

    if (arg.startsWith("--") || (arg.startsWith("-") && arg !== "-")) {
      throw new CliError(`unknown flag: ${arg}`);
    }
    positionals.push(arg);
  }

  if (options.command === "explain") {
    const topic = positionals[0];
    if (topic === undefined) {
      throw new CliError("explain needs a topic, e.g.: cspdoctor explain E110");
    }
    if (positionals.length > 1) {
      throw new CliError("explain takes exactly one topic");
    }
    return { ...options, topic };
  }

  if (positionals.length > 1) {
    throw new CliError(
      `expected one policy argument but got ${positionals.length} — quote the policy: cspdoctor check "default-src 'self'"`
    );
  }
  options.policy = positionals[0] ?? null;

  if (options.policy === null && options.files.length === 0) {
    throw new CliError(
      'no policy given — pass a quoted policy string, --file <path>, or "-" for stdin'
    );
  }
  if (options.policy !== null && options.files.length > 0) {
    throw new CliError("pass a policy string or --file, not both");
  }
  return options;
}

function splitInline(arg: string): [string, string | null] {
  const eq = arg.indexOf("=");
  if (arg.startsWith("--") && eq > 2) return [arg.slice(0, eq), arg.slice(eq + 1)];
  return [arg, null];
}

function requireValue(flag: string, value: string | undefined | null): string {
  if (value === undefined || value === null || value === "") {
    throw new CliError(`${flag} needs a value`);
  }
  return value;
}

function oneOf<T extends string>(flag: string, value: string, allowed: readonly T[]): T {
  for (const candidate of allowed) {
    if (candidate === value) return candidate;
  }
  throw new CliError(`${flag} must be one of: ${allowed.join(", ")} (got "${value}")`);
}
