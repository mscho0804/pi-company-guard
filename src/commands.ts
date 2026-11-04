/**
 * Shell command evaluation: dangerous commands, secret access, data egress.
 *
 * This is a best-effort, pattern-based safety net against *mistakes* and obvious misuse.
 * It is not a sandbox: a determined actor can always obfuscate a command. Combine it with
 * OS-level isolation (dedicated user, file permissions, containers) for real protection.
 */
import os from "node:os";
import type { GuardConfig } from "./config.ts";
import { classifyPath, extractPathTokens } from "./paths.ts";

export type Level = "confirm" | "block";

export interface CommandRule {
	id: string;
	level: Level;
	category: "destructive" | "privilege" | "git" | "infra" | "database" | "egress" | "secrets" | "readonly";
	description: string;
	pattern: RegExp;
	/** Only active when the host is in read-only mode. */
	readOnlyOnly?: boolean;
}

export interface RuleMatch {
	id: string;
	level: Level;
	category: string;
	description: string;
}

export interface CommandVerdict {
	decision: "allow" | "confirm" | "block";
	matches: RuleMatch[];
	reason: string;
}

/** Start of a command: beginning, after a separator, or after a wrapper such as sudo/env/xargs. */
const CMD = String.raw`(?:^|[;&|(\x60]\s*|\$\(\s*|\b(?:sudo|exec|xargs|env|nohup|time|nice|command)\s+(?:-\S+\s+)*)`;
const rx = (src: string, flags = "") => new RegExp(src, flags);

export const RULES: CommandRule[] = [
	// ---- hard blocks -------------------------------------------------------------------------
	{
		id: "rm-root",
		level: "block",
		category: "destructive",
		description: "recursive delete of /, ~, $HOME, . or *",
		pattern: rx(
			String.raw`\brm\b(?=[^;&|]*\s-(?:[a-zA-Z]*[rR]|-recursive))[^;&|]*\s(?:/|/\*|~/?|~/\*|\$HOME/?|\$\{HOME\}/?|\.\.?/?|\*)(?=$|[\s;&|])`,
		),
	},
	{ id: "mkfs", level: "block", category: "destructive", description: "format a filesystem", pattern: rx(String.raw`\bmkfs(?:\.\w+)?\b`) },
	{ id: "dd-device", level: "block", category: "destructive", description: "dd onto a device", pattern: rx(String.raw`\bdd\b[^;&|]*\bof=/dev/`) },
	{
		id: "device-write",
		level: "block",
		category: "destructive",
		description: "redirect onto a block device",
		pattern: rx(String.raw`>\s*/dev/(?:sd|nvme|hd|xvd|vd|mmcblk)`),
	},
	{ id: "fork-bomb", level: "block", category: "destructive", description: "fork bomb", pattern: rx(String.raw`:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`) },
	{
		id: "pipe-to-shell",
		level: "block",
		category: "egress",
		description: "pipe downloaded script into a shell",
		pattern: rx(String.raw`\b(?:curl|wget)\b[^;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k|fi)?sh\b`),
	},
	{
		id: "power",
		level: "block",
		category: "destructive",
		description: "shutdown / reboot the machine",
		pattern: rx(String.raw`${CMD}(?:shutdown|reboot|halt|poweroff)\b|${CMD}init\s+[06]\b`),
	},

	// ---- confirmation required ---------------------------------------------------------------
	{
		id: "rm-recursive",
		level: "confirm",
		category: "destructive",
		description: "recursive delete",
		pattern: rx(String.raw`\brm\s+(?:-\S*\s+)*-(?:[a-zA-Z]*[rR][a-zA-Z]*|-recursive)\b`),
	},
	{ id: "sudo", level: "confirm", category: "privilege", description: "privilege escalation", pattern: rx(String.raw`(?:^|[;&|(]\s*)(?:sudo|su|doas|pkexec)(?=\s|$)`) },
	{ id: "chmod-777", level: "confirm", category: "privilege", description: "world-writable permissions", pattern: rx(String.raw`\bchmod\b[^;&|]*(?:\b0?777\b|a\+rwx|o\+w)`) },
	{ id: "chown-recursive", level: "confirm", category: "privilege", description: "recursive chown", pattern: rx(String.raw`\bchown\s+(?:-\S+\s+)*-[a-zA-Z]*R`) },
	{
		id: "git-force-push",
		level: "confirm",
		category: "git",
		description: "force push",
		pattern: rx(String.raw`\bgit\b[^;&|]*\bpush\b[^;&|]*(?:\s--force(?:-with-lease)?\b|\s-[a-zA-Z]*f\b|\s\+\S+)`),
	},
	{ id: "git-reset-hard", level: "confirm", category: "git", description: "git reset --hard", pattern: rx(String.raw`\bgit\b[^;&|]*\breset\b[^;&|]*--hard`) },
	{ id: "git-clean", level: "confirm", category: "git", description: "git clean -f", pattern: rx(String.raw`\bgit\b[^;&|]*\bclean\b[^;&|]*\s-[a-zA-Z]*f`) },
	{ id: "git-branch-delete", level: "confirm", category: "git", description: "force delete branch", pattern: rx(String.raw`\bgit\b[^;&|]*\bbranch\b[^;&|]*\s-D\b`) },
	{
		id: "git-history-rewrite",
		level: "confirm",
		category: "git",
		description: "history rewrite",
		pattern: rx(String.raw`\bgit\b[^;&|]*\b(?:filter-branch|filter-repo|update-ref\s+-d|reflog\s+expire)\b`),
	},
	{
		id: "kubectl-mutate",
		level: "confirm",
		category: "infra",
		description: "kubectl change",
		pattern: rx(String.raw`\bkubectl\b[^;&|]*\s(?:delete|apply|create|replace|patch|scale|drain|cordon|uncordon|edit|set|label|annotate|rollout\s+(?:restart|undo))\b`),
	},
	{ id: "helm-mutate", level: "confirm", category: "infra", description: "helm change", pattern: rx(String.raw`\bhelm\b[^;&|]*\s(?:install|upgrade|uninstall|delete|rollback)\b`) },
	{
		id: "terraform-mutate",
		level: "confirm",
		category: "infra",
		description: "terraform change",
		pattern: rx(String.raw`\b(?:terraform|tofu|terragrunt)\b[^;&|]*\s(?:apply|destroy|import|taint|state\s+(?:rm|mv|push))\b`),
	},
	{
		id: "docker-destructive",
		level: "confirm",
		category: "infra",
		description: "docker remove / prune",
		pattern: rx(String.raw`\b(?:docker|podman)\b[^;&|]*\s(?:rm|rmi|kill|(?:system|volume|image|container|network|builder)\s+(?:prune|rm))\b`),
	},
	{
		id: "service-control",
		level: "confirm",
		category: "infra",
		description: "stop / restart a system service",
		pattern: rx(String.raw`\bsystemctl\b[^;&|]*\s(?:stop|restart|disable|mask|kill|isolate)\b|\bservice\s+\S+\s+(?:stop|restart)\b`),
	},
	{ id: "kill-process", level: "confirm", category: "infra", description: "kill processes", pattern: rx(String.raw`\bkill\s+-(?:9|KILL|SIGKILL)\b|${CMD}(?:killall|pkill)\b`) },
	{ id: "crontab-remove", level: "confirm", category: "infra", description: "remove crontab", pattern: rx(String.raw`\bcrontab\s+(?:-\S+\s+)*-r\b`) },
	{ id: "firewall", level: "confirm", category: "infra", description: "firewall change", pattern: rx(String.raw`${CMD}(?:iptables|ip6tables|nft|ufw|firewall-cmd)\b`) },
	{
		id: "sql-destructive",
		level: "confirm",
		category: "database",
		description: "DROP / TRUNCATE / DELETE without WHERE",
		pattern: rx(String.raw`\b(?:drop\s+(?:table|database|schema|index|collection)|truncate\s+(?:table\s+)?[\w."]+|delete\s+from\s+[\w."]+\s*(?:;|$|["'])|\.drop(?:Database)?\(\))`, "i"),
	},
	{
		id: "env-dump",
		level: "confirm",
		category: "secrets",
		description: "dump environment variables (may contain secrets)",
		pattern: rx(String.raw`${CMD}(?:env|printenv|export\s+-p|set|declare\s+-x)\s*(?=$|[;&|>])`),
	},
	{
		id: "secret-tools",
		level: "confirm",
		category: "secrets",
		description: "print credentials from a CLI",
		pattern: rx(
			String.raw`\b(?:aws\s+configure\s+(?:get|export-credentials)|aws\s+sts\s+get-session-token|aws\s+secretsmanager\s+get-secret-value|aws\s+ssm\s+get-parameters?\b[^;&|]*--with-decryption|gcloud\s+auth\s+(?:print-access-token|print-identity-token)|az\s+account\s+get-access-token|kubectl\b[^;&|]*\s(?:get|describe)\s+secrets?\b|vault\s+(?:read|kv\s+get)|gh\s+auth\s+token|git\s+credential\s+fill|security\s+find-(?:generic|internet)-password)`,
		),
	},
	{
		id: "egress-transfer",
		level: "confirm",
		category: "egress",
		description: "file transfer / raw network tool",
		pattern: rx(String.raw`${CMD}(?:scp|sftp|ftp|lftp|nc|ncat|netcat|socat|telnet)\b|\brsync\b[^;&|]*\s[\w.@-]+:`),
	},
	{
		id: "egress-upload",
		level: "confirm",
		category: "egress",
		description: "HTTP upload / POST",
		pattern: rx(
			String.raw`\bcurl\b[^;&|]*(?:\s-d\b|\s--data(?:-\w+)?\b|\s-F\b|\s--form\b|\s-T\b|\s--upload-file\b|\s-X\s*(?:POST|PUT|PATCH)\b|\s--request\s+(?:POST|PUT|PATCH)\b|\s--json\b)|\bwget\b[^;&|]*--(?:post|body)-(?:data|file)|\bInvoke-(?:WebRequest|RestMethod)\b[^;&|]*-Method\s+(?:Post|Put|Patch)`,
			"i",
		),
	},

	// ---- read-only hosts only ----------------------------------------------------------------
	{
		id: "fs-mutate",
		level: "block",
		category: "readonly",
		readOnlyOnly: true,
		description: "file system change on a read-only host",
		pattern: rx(
			String.raw`${CMD}(?:rm|mv|cp|mkdir|rmdir|touch|truncate|tee|chmod|chown|ln|install|patch|git\s+(?:commit|push|merge|rebase|checkout|reset|stash|pull))\b|\bsed\s+(?:-\S+\s+)*-i|(?:^|[^0-9&>])>{1,2}\s*(?!&|/dev/null)\S`,
		),
	},
];

/** Variants of the command to test: original plus a de-obfuscated version (quotes/backslashes removed). */
function variants(command: string): string[] {
	const joined = command.replace(/\\\r?\n/g, " ");
	const dequoted = joined.replace(/(?<=\w)['"]{2}(?=\w)/g, "").replace(/\\(?=\w)/g, "");
	const stripped = joined.replace(/['"\\]/g, "");
	return [...new Set([joined, dequoted, stripped])];
}

function hostAllowed(host: string, allowed: string[]): boolean {
	const h = host.toLowerCase();
	return allowed.some((a) => {
		const p = a.toLowerCase();
		if (p.startsWith("*.")) return h.endsWith(p.slice(1)) || h === p.slice(2);
		return h === p;
	});
}

/** Hosts contacted by curl / wget / Invoke-WebRequest in the command. */
export function extractEgressHosts(command: string): string[] {
	if (!/\b(?:curl|wget|http|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/i.test(command)) return [];
	const hosts = new Set<string>();
	for (const m of command.matchAll(/\bhttps?:\/\/(?:[^@/\s'"]+@)?(\[[^\]]+\]|[^/\s:'"?#]+)/gi)) hosts.add(m[1].toLowerCase());
	return [...hosts];
}

export function isReadOnlyHost(cfg: GuardConfig, hostname = os.hostname()): boolean {
	if (!cfg.readOnlyHostPattern) return false;
	try {
		return new RegExp(cfg.readOnlyHostPattern, "i").test(hostname);
	} catch {
		return false;
	}
}

export function evaluateCommand(command: string, cwd: string, cfg: GuardConfig, opts: { readOnly?: boolean } = {}): CommandVerdict {
	const matches: RuleMatch[] = [];
	const texts = variants(command);

	// 1. sensitive paths referenced anywhere in the command
	const seen = new Set<string>();
	for (const text of texts) {
		for (const token of extractPathTokens(text)) {
			if (seen.has(token)) continue;
			seen.add(token);
			const v = classifyPath(token, cwd, { ...cfg, workspaceOnly: false }, "read");
			if (v.decision === "block") {
				matches.push({ id: "sensitive-path", level: "block", category: "secrets", description: v.reason ?? `sensitive path ${token}` });
			}
		}
	}

	// 2. pattern rules
	for (const rule of RULES) {
		if (cfg.disabledRules.includes(rule.id)) continue;
		if (rule.readOnlyOnly && !opts.readOnly) continue;
		if (!texts.some((t) => rule.pattern.test(t))) continue;
		let level: Level = rule.level;
		if (cfg.blockRules.includes(rule.id) || opts.readOnly) level = "block";
		matches.push({ id: rule.id, level, category: rule.category, description: rule.description });
	}

	// 3. egress to non-allowlisted hosts
	if (!cfg.disabledRules.includes("egress-host")) {
		const unknown = extractEgressHosts(command).filter((h) => !hostAllowed(h, cfg.egressAllowedHosts));
		if (unknown.length > 0) {
			const level: Level = cfg.blockRules.includes("egress-host") || opts.readOnly ? "block" : "confirm";
			matches.push({ id: "egress-host", level, category: "egress", description: `network access to non-allowlisted host(s): ${unknown.join(", ")}` });
		}
	}

	const decision = matches.some((m) => m.level === "block") ? "block" : matches.length > 0 ? "confirm" : "allow";
	const reason = matches.map((m) => `[${m.id}] ${m.description}`).join("; ");
	return { decision, matches, reason };
}
