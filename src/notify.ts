/**
 * Completion notifications: Microsoft Teams (Workflows webhook) and terminal (bell / OSC).
 */
import { spawn } from "node:child_process";
import os from "node:os";

// ---------------------------------------------------------------------------------------------
// Teams
// ---------------------------------------------------------------------------------------------

export interface RunSummary {
	title: string;
	status: "done" | "aborted" | "test";
	durationSec: number;
	host: string;
	user: string;
	cwd: string;
	toolCalls: number;
	blocked: number;
	model?: string;
}

export function formatDuration(sec: number): string {
	const s = Math.max(0, Math.round(sec));
	const h = Math.floor(s / 3600);
	const m = Math.floor((s % 3600) / 60);
	const r = s % 60;
	if (h > 0) return `${h}h ${m}m ${r}s`;
	if (m > 0) return `${m}m ${r}s`;
	return `${r}s`;
}

/**
 * Message format accepted by the Teams Workflows template
 * "Post to a channel when a webhook request is received" (Adaptive Card attachment).
 * Deliberately contains only metadata — never prompts, output or file contents.
 */
export function buildTeamsPayload(s: RunSummary): Record<string, unknown> {
	const icon = s.status === "done" ? "✅" : s.status === "aborted" ? "⛔" : "🔔";
	const headline = s.status === "done" ? "작업 완료" : s.status === "aborted" ? "작업 중단됨" : "테스트 알림";
	const facts = [
		{ title: "Host", value: `${s.user}@${s.host}` },
		{ title: "Dir", value: s.cwd },
		{ title: "Duration", value: formatDuration(s.durationSec) },
		{ title: "Tool calls", value: String(s.toolCalls) },
	];
	if (s.blocked > 0) facts.push({ title: "Blocked", value: String(s.blocked) });
	if (s.model) facts.push({ title: "Model", value: s.model });
	return {
		type: "message",
		attachments: [
			{
				contentType: "application/vnd.microsoft.card.adaptive",
				contentUrl: null,
				content: {
					$schema: "http://adaptivecards.io/schemas/adaptive-card.json",
					type: "AdaptiveCard",
					version: "1.4",
					body: [
						{ type: "TextBlock", size: "Medium", weight: "Bolder", wrap: true, text: `${icon} ${s.title}: ${headline}` },
						{ type: "FactSet", facts },
					],
				},
			},
		],
	};
}

/** Quote a value for a curl config file (-K). */
export function curlQuote(value: string): string {
	return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\r/g, "\\r").replace(/\n/g, "\\n").replace(/\t/g, "\\t")}"`;
}

/**
 * Build a curl config. URL and body are passed via stdin (`curl -K -`) so the webhook URL
 * never shows up in `ps` output for other users on a shared server.
 */
export function buildCurlConfig(url: string, body: string, timeoutSec: number): string {
	return [
		`url = ${curlQuote(url)}`,
		`request = "POST"`,
		`header = "Content-Type: application/json"`,
		`data-binary = ${curlQuote(body)}`,
		`max-time = ${Math.max(1, Math.round(timeoutSec))}`,
		`silent`,
		`show-error`,
		`output = ${curlQuote(os.devNull)}`,
		`write-out = "%{http_code}"`,
		"",
	].join("\n");
}

export interface SendResult {
	ok: boolean;
	status?: number;
	error?: string;
	via: "curl" | "fetch";
}

function sendViaFetch(url: string, body: string, timeoutSec: number): Promise<SendResult> {
	return fetch(url, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body,
		signal: AbortSignal.timeout(timeoutSec * 1000),
	})
		.then((r) => ({ ok: r.ok, status: r.status, via: "fetch" as const, error: r.ok ? undefined : `HTTP ${r.status}` }))
		.catch((e: Error) => ({ ok: false, error: e.message, via: "fetch" as const }));
}

/**
 * POST JSON to a webhook. Uses curl (honours HTTP(S)_PROXY / NO_PROXY like the rest of the
 * server) and falls back to fetch when curl is not installed.
 */
export function sendWebhook(url: string, payload: unknown, timeoutSec = 10, curlBin = "curl"): Promise<SendResult> {
	const body = JSON.stringify(payload);
	return new Promise((resolve) => {
		let settled = false;
		const done = (r: SendResult) => {
			if (!settled) {
				settled = true;
				resolve(r);
			}
		};
		let child: ReturnType<typeof spawn>;
		try {
			child = spawn(curlBin, ["-K", "-"], { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
		} catch {
			void sendViaFetch(url, body, timeoutSec).then(done);
			return;
		}
		let out = "";
		let err = "";
		let spawnFailed = false;
		child.stdout?.on("data", (d) => (out += d));
		child.stderr?.on("data", (d) => (err += d));
		child.on("error", (e: NodeJS.ErrnoException) => {
			spawnFailed = true;
			if (e.code === "ENOENT") void sendViaFetch(url, body, timeoutSec).then(done);
			else done({ ok: false, error: e.message, via: "curl" });
		});
		child.on("close", (code) => {
			if (spawnFailed) return; // handled by the "error" listener (fetch fallback)
			const status = Number.parseInt(out.trim(), 10);
			const ok = code === 0 && status >= 200 && status < 300;
			done({
				ok,
				status: Number.isFinite(status) ? status : undefined,
				error: ok ? undefined : (err.trim() || `curl exit ${code}, HTTP ${out.trim() || "?"}`).slice(0, 500),
				via: "curl",
			});
		});
		child.stdin?.on("error", () => {
			/* handled by close/error */
		});
		child.stdin?.end(buildCurlConfig(url, body, timeoutSec));
	});
}

// ---------------------------------------------------------------------------------------------
// Terminal
// ---------------------------------------------------------------------------------------------

export type OscMode = "off" | "osc777" | "osc9" | "osc99";

const ESC = "\x1b";
const BEL = "\x07";
const ST = `${ESC}\\`;

function sanitize(s: string): string {
	// Strip control characters / separators that would break the escape sequence.
	// biome-ignore lint/suspicious/noControlCharactersInRegex: intentional
	return s.replace(/[\x00-\x1f\x7f;]/g, " ").slice(0, 200);
}

/** Wrap an escape sequence for tmux passthrough (requires `set -g allow-passthrough on`). */
export function tmuxWrap(seq: string): string {
	return `${ESC}Ptmux;${seq.replaceAll(ESC, ESC + ESC)}${ST}`;
}

export function buildTerminalSequence(
	opts: { bell: boolean; osc: OscMode; title: string; body: string },
	env: NodeJS.ProcessEnv = process.env,
): string {
	let seq = "";
	const t = sanitize(opts.title);
	const b = sanitize(opts.body);
	let osc = "";
	if (opts.osc === "osc777") osc = `${ESC}]777;notify;${t};${b}${BEL}`;
	else if (opts.osc === "osc9") osc = `${ESC}]9;${t}: ${b}${BEL}`;
	else if (opts.osc === "osc99") osc = `${ESC}]99;i=1:d=0;${t}${ST}${ESC}]99;i=1:p=body;${b}${ST}`;
	if (osc) seq += env.TMUX ? tmuxWrap(osc) : osc;
	// BEL works natively through SSH, tmux and screen: tab highlight / taskbar flash / sound.
	if (opts.bell) seq += BEL;
	return seq;
}
