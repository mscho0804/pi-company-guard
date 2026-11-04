/**
 * Secret redaction for tool output, applied before the output reaches the LLM provider.
 */

export interface RedactPattern {
	kind: string;
	re: RegExp;
	/** Replacement; "$1" etc. keep surrounding context such as the key name. */
	replace: string;
}

const R = (kind: string, src: string, flags: string, replace = `[REDACTED:${kind}]`): RedactPattern => ({
	kind,
	re: new RegExp(src, flags.includes("g") ? flags : `${flags}g`),
	replace,
});

export const BUILTIN_PATTERNS: RedactPattern[] = [
	R("private-key", String.raw`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$)`, ""),
	R("aws-access-key", String.raw`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b`, ""),
	R("github-token", String.raw`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b`, ""),
	R("gitlab-token", String.raw`\bglpat-[A-Za-z0-9_-]{20,}\b`, ""),
	R("slack-token", String.raw`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`, ""),
	R("slack-webhook", String.raw`https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+`, ""),
	R("teams-webhook", String.raw`https://[\w.-]+\.(?:webhook\.office\.com|logic\.azure\.com|environment\.api\.powerplatform\.com)[^\s'"]*`, "i"),
	R("anthropic-key", String.raw`\bsk-ant-[A-Za-z0-9_-]{20,}\b`, ""),
	R("openai-key", String.raw`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b`, ""),
	R("google-api-key", String.raw`\bAIza[0-9A-Za-z_-]{35}\b`, ""),
	R("stripe-key", String.raw`\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}\b`, ""),
	R("npm-token", String.raw`\bnpm_[A-Za-z0-9]{36}\b`, ""),
	R("jwt", String.raw`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`, ""),
	R("bearer", String.raw`(\b(?:Authorization|Proxy-Authorization)\s*:\s*(?:Bearer|Basic|Token)\s+)[A-Za-z0-9._~+/=-]{8,}`, "i", "$1[REDACTED:bearer]"),
	R("url-credentials", String.raw`(\b[a-z][a-z0-9+.-]*://[^:/\s@'"]+:)[^@\s'"/]+(@)`, "i", "$1[REDACTED:password]$2"),
	// KEY=value lines (dotenv / shell). Key must be UPPER_CASE so code like `token = getToken()` survives.
	R(
		"env-secret",
		String.raw`^(\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH)[A-Z0-9_]*\s*=\s*)(["']?)(?!\[REDACTED)([^\s"'#]{4,})\2`,
		"m",
		"$1$2[REDACTED:env-secret]$2",
	),
	// "password": "literal" / password: 'literal' / password="literal" (quoted literal values only)
	R(
		"quoted-secret",
		String.raw`((?:["']?)[\w.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)["']?\s*[:=]\s*)(["'])(?!\[REDACTED)([^"'\s]{6,})\2`,
		"i",
		"$1$2[REDACTED:secret]$2",
	),
];

export interface RedactResult {
	text: string;
	count: number;
	kinds: string[];
}

export function buildPatterns(extra: string[] = []): RedactPattern[] {
	const custom: RedactPattern[] = [];
	for (const src of extra) {
		try {
			custom.push(R("custom", src, "g"));
		} catch {
			/* invalid regex in config: ignore */
		}
	}
	return [...BUILTIN_PATTERNS, ...custom];
}

export function redactText(input: string, patterns: RedactPattern[] = BUILTIN_PATTERNS): RedactResult {
	let text = input;
	let count = 0;
	const kinds = new Set<string>();
	for (const p of patterns) {
		p.re.lastIndex = 0;
		const n = text.match(p.re)?.length ?? 0;
		if (n === 0) continue;
		count += n;
		kinds.add(p.kind);
		p.re.lastIndex = 0;
		text = text.replace(p.re, p.replace);
	}
	return { text, count, kinds: [...kinds] };
}

/** Recursively redact all strings inside a JSON value. */
export function redactDeep<T>(value: T, patterns: RedactPattern[] = BUILTIN_PATTERNS): { value: T; count: number; kinds: string[] } {
	let count = 0;
	const kinds = new Set<string>();
	const walk = (v: unknown): unknown => {
		if (typeof v === "string") {
			const r = redactText(v, patterns);
			count += r.count;
			for (const k of r.kinds) kinds.add(k);
			return r.text;
		}
		if (Array.isArray(v)) return v.map(walk);
		if (v && typeof v === "object") {
			const out: Record<string, unknown> = {};
			for (const [k, val] of Object.entries(v)) out[k] = walk(val);
			return out;
		}
		return v;
	};
	const result = walk(value) as T;
	return { value: result, count, kinds: [...kinds] };
}
