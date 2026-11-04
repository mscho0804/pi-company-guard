/**
 * Configuration loading for pi-company-guard.
 *
 * Merge order (later wins, list fields are appended):
 *   1. built-in defaults (this file)
 *   2. /etc/pi/company-guard.json            (admin / company-wide baseline)
 *   3. ~/.pi/agent/company-guard.json        (per-user)
 *   4. $PI_GUARD_CONFIG                      (explicit path, e.g. for tests)
 *
 * Project-level (repo) config is intentionally NOT supported: a cloned repository
 * must never be able to loosen the guardrails.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export type Decision = "allow" | "confirm" | "block";

export interface GuardConfig {
	enabled: boolean;
	/** Paths that may be neither read nor written (globs, see paths.ts). Appended to defaults. */
	sensitivePaths: string[];
	/** Paths that may be read but never written/edited. Appended to defaults. */
	writeProtectedPaths: string[];
	/** Exceptions that override sensitivePaths / writeProtectedPaths. Appended to defaults. */
	allowPaths: string[];
	/** Block file tools that touch paths outside the session cwd (and the temp dir). */
	workspaceOnly: boolean;
	/** Regex (case-insensitive) for host names that run in read-only mode, e.g. "prod". Empty = off. */
	readOnlyHostPattern: string;
	/** Hosts reachable with curl/wget without confirmation. "*.corp.com" wildcards allowed. */
	egressAllowedHosts: string[];
	/** What "confirm" means when there is no UI (pi -p, rpc without UI): block or allow. */
	nonInteractive: "block" | "allow";
	/** Redact secrets from tool output before it reaches the model. */
	redact: boolean;
	/** Extra regex sources for redaction (case-sensitive, global). */
	extraRedactPatterns: string[];
	/** Rule ids (see commands.ts) to disable. */
	disabledRules: string[];
	/** Rule ids that should be escalated from confirm to block. */
	blockRules: string[];
}

export interface AuditConfig {
	enabled: boolean;
	path: string;
}

export interface NotifyConfig {
	/** Only notify when a run took at least this long. 0 = always. */
	minDurationSec: number;
	teams: {
		enabled: boolean;
		/** Webhook URL. Prefer webhookUrlEnv so the URL never lands in a file. */
		webhookUrl: string;
		/** Environment variable holding the webhook URL. */
		webhookUrlEnv: string;
		timeoutSec: number;
		/** Extra text appended to the card (e.g. team name). */
		title: string;
	};
	terminal: {
		enabled: boolean;
		/** Ring the terminal bell (BEL). Works over SSH and inside tmux/screen. */
		bell: boolean;
		/** Desktop notification escape sequence: off | osc777 | osc9 | osc99. */
		osc: "off" | "osc777" | "osc9" | "osc99";
		/** Set the terminal/tab title while working / when done. */
		title: boolean;
	};
}

export interface CompanyGuardConfig {
	guard: GuardConfig;
	audit: AuditConfig;
	notify: NotifyConfig;
	/** Files that were merged, for /guard status. */
	loadedFrom: string[];
}

export const DEFAULT_SENSITIVE_PATHS = [
	// dotenv files (examples/templates are allowed via allowPaths)
	".env",
	".env.*",
	"*.env",
	// keys & certificates
	"*.pem",
	"*.key",
	"*.p12",
	"*.pfx",
	"*.jks",
	"*.keystore",
	"*.kdbx",
	"id_rsa*",
	"id_dsa*",
	"id_ecdsa*",
	"id_ed25519*",
	// credential stores
	".netrc",
	".pgpass",
	".git-credentials",
	".npmrc",
	".pypirc",
	".htpasswd",
	"credentials",
	"credentials.json",
	"secrets.yaml",
	"secrets.yml",
	"secrets.json",
	"**/.ssh/**",
	"**/.gnupg/**",
	"**/.aws/**",
	"**/.azure/**",
	"**/.kube/**",
	"**/.docker/config.json",
	"**/.config/gcloud/**",
	"**/.config/gh/hosts.yml",
	"**/.vault-token",
	"**/.pi/agent/auth.json",
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/sudoers.d/**",
	"/proc/*/environ",
];

export const DEFAULT_WRITE_PROTECTED_PATHS = [
	// the guard must not be able to switch itself off
	// (config, settings, extensions and installed packages all live below ~/.pi/agent)
	"**/.pi/agent/**",
	"/etc/pi/**",
	// shell startup files: persistence / env tampering
	"**/.bashrc",
	"**/.bash_profile",
	"**/.profile",
	"**/.zshrc",
	"**/.ssh/authorized_keys",
	"**/.git/config",
	"**/.git/hooks/**",
	"/etc/**",
	"/usr/**",
	"/boot/**",
];

export const DEFAULT_ALLOW_PATHS = [".env.example", ".env.sample", ".env.template", ".env.dist", "*.pub"];

export const DEFAULT_EGRESS_ALLOWED_HOSTS = [
	"localhost",
	"127.0.0.1",
	"github.com",
	"*.github.com",
	"*.githubusercontent.com",
	"registry.npmjs.org",
	"pypi.org",
	"files.pythonhosted.org",
];

export function defaultConfig(): CompanyGuardConfig {
	return {
		guard: {
			enabled: true,
			sensitivePaths: [...DEFAULT_SENSITIVE_PATHS],
			writeProtectedPaths: [...DEFAULT_WRITE_PROTECTED_PATHS],
			allowPaths: [...DEFAULT_ALLOW_PATHS],
			workspaceOnly: false,
			readOnlyHostPattern: "",
			egressAllowedHosts: [...DEFAULT_EGRESS_ALLOWED_HOSTS],
			nonInteractive: "block",
			redact: true,
			extraRedactPatterns: [],
			disabledRules: [],
			blockRules: [],
		},
		audit: {
			enabled: true,
			path: "~/.pi/agent/logs/company-guard-audit.jsonl",
		},
		notify: {
			minDurationSec: 30,
			teams: {
				enabled: true,
				webhookUrl: "",
				webhookUrlEnv: "PI_TEAMS_WEBHOOK_URL",
				timeoutSec: 10,
				title: "pi",
			},
			terminal: {
				enabled: true,
				bell: true,
				osc: "off",
				title: true,
			},
		},
		loadedFrom: [],
	};
}

export function expandHome(p: string): string {
	if (p === "~") return os.homedir();
	if (p.startsWith("~/") || p.startsWith("~\\")) return path.join(os.homedir(), p.slice(2));
	return p;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Deep merge: objects merge, arrays append (deduplicated), scalars replace. */
export function mergeInto(target: Record<string, unknown>, source: Record<string, unknown>): void {
	for (const [key, value] of Object.entries(source)) {
		if (key === "loadedFrom") continue;
		const current = target[key];
		if (Array.isArray(current) && Array.isArray(value)) {
			target[key] = [...new Set([...current, ...value])];
		} else if (isPlainObject(current) && isPlainObject(value)) {
			mergeInto(current, value);
		} else if (value !== undefined) {
			target[key] = value;
		}
	}
}

export function configCandidates(): string[] {
	const list = ["/etc/pi/company-guard.json", path.join(os.homedir(), ".pi", "agent", "company-guard.json")];
	if (process.env.PI_GUARD_CONFIG) list.push(expandHome(process.env.PI_GUARD_CONFIG));
	return list;
}

export function loadConfig(files: string[] = configCandidates()): CompanyGuardConfig {
	const config = defaultConfig();
	for (const file of files) {
		let raw: string;
		try {
			raw = fs.readFileSync(file, "utf8");
		} catch {
			continue;
		}
		try {
			const parsed = JSON.parse(raw);
			if (isPlainObject(parsed)) {
				mergeInto(config as unknown as Record<string, unknown>, parsed);
				config.loadedFrom.push(file);
			}
		} catch (err) {
			// Fail closed: a broken config must not silently disable anything. Defaults stay active.
			config.loadedFrom.push(`${file} (INVALID JSON: ${(err as Error).message})`);
		}
	}
	return config;
}

/** Resolve the Teams webhook URL: env var first, then config value. */
export function resolveWebhookUrl(cfg: NotifyConfig): string {
	const fromEnv = cfg.teams.webhookUrlEnv ? process.env[cfg.teams.webhookUrlEnv] : undefined;
	return (fromEnv ?? "").trim() || (cfg.teams.webhookUrl ?? "").trim();
}
