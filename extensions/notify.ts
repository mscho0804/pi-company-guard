/**
 * pi-company-guard: notify extension
 *
 * When pi finishes a run (agent_settled) that took at least `notify.minDurationSec`:
 *   - Teams: POST an Adaptive Card to a Workflows webhook (URL from $PI_TEAMS_WEBHOOK_URL)
 *   - Terminal: ring the bell (BEL) and optionally emit an OSC desktop notification;
 *     works over SSH because the escape sequences travel to your local terminal.
 *
 * Commands: /notify-test   send a test notification on every channel
 */
import os from "node:os";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { writeAudit } from "../src/audit.ts";
import { type CompanyGuardConfig, loadConfig, resolveWebhookUrl } from "../src/config.ts";
import { buildTeamsPayload, buildTerminalSequence, formatDuration, type RunSummary, type SendResult, sendWebhook } from "../src/notify.ts";

const STATS_KEY = Symbol.for("pi-company-guard.stats");

export interface NotifyDeps {
	send: (url: string, payload: unknown, timeoutSec: number) => Promise<SendResult>;
	writeTerminal: (data: string) => void;
	now: () => number;
}

const defaultDeps: NotifyDeps = {
	send: (url, payload, timeoutSec) => sendWebhook(url, payload, timeoutSec),
	writeTerminal: (data) => {
		if (process.stdout.isTTY || process.env.PI_NOTIFY_FORCE_TERMINAL) process.stdout.write(data);
	},
	now: () => Date.now(),
};

function blockedCount(): number {
	const s = (globalThis as Record<symbol, { blocked?: number; denied?: number } | undefined>)[STATS_KEY];
	return (s?.blocked ?? 0) + (s?.denied ?? 0);
}

export function createNotifyExtension(deps: NotifyDeps = defaultDeps) {
	return function companyNotify(pi: ExtensionAPI) {
		let config: CompanyGuardConfig = loadConfig();
		let runStartedAt: number | undefined;
		let toolCalls = 0;
		let blockedAtStart = 0;

		const summary = (ctx: ExtensionContext, status: RunSummary["status"], durationSec: number): RunSummary => ({
			title: config.notify.teams.title || "pi",
			status,
			durationSec,
			host: os.hostname(),
			user: (() => {
				try {
					return os.userInfo().username;
				} catch {
					return "unknown";
				}
			})(),
			cwd: ctx.cwd,
			toolCalls,
			blocked: Math.max(0, blockedCount() - blockedAtStart),
			model: ctx.model ? `${ctx.model.provider}/${ctx.model.id}` : undefined,
		});

		async function notifyAll(ctx: ExtensionContext, s: RunSummary, force: boolean): Promise<string[]> {
			const report: string[] = [];
			const n = config.notify;
			// Capture everything needed from ctx up front: after an await the session may have been
			// replaced or disposed (/new, reload, exit) and touching a stale ctx throws.
			const cwd = s.cwd;
			const hasUI = ctx.hasUI;
			const ui = ctx.ui;
			const safeNotify = (msg: string) => {
				try {
					ui.notify(msg, "warning");
				} catch {
					/* stale UI */
				}
			};

			// terminal first: instant, local, no network
			if (n.terminal.enabled) {
				const body = `${s.status === "aborted" ? "aborted" : "done"} in ${formatDuration(s.durationSec)} — ${s.cwd}`;
				const seq = buildTerminalSequence({ bell: n.terminal.bell, osc: n.terminal.osc, title: s.title, body });
				if (seq) deps.writeTerminal(seq);
				if (n.terminal.title && ctx.hasUI) ctx.ui.setTitle(`${s.status === "aborted" ? "⛔" : "✅"} ${s.title} — ${os.hostname()}`);
				report.push(`terminal: bell=${n.terminal.bell} osc=${n.terminal.osc}`);
			}

			if (n.teams.enabled) {
				const url = resolveWebhookUrl(n);
				if (!url) {
					report.push(`teams: skipped (set $${n.teams.webhookUrlEnv} or notify.teams.webhookUrl)`);
				} else {
					const r = await deps.send(url, buildTeamsPayload(s), n.teams.timeoutSec);
					report.push(r.ok ? `teams: sent (HTTP ${r.status ?? "?"}, via ${r.via})` : `teams: FAILED via ${r.via} — ${r.error}`);
					writeAudit(config.audit, { event: "notify", channel: "teams", ok: r.ok, status: r.status, error: r.error }, cwd);
					if (!r.ok && (force || hasUI)) safeNotify(`📣 Teams notification failed: ${r.error}`);
				}
			}
			return report;
		}

		pi.on("session_start", async () => {
			config = loadConfig();
		});

		pi.on("agent_start", async (_event, ctx) => {
			// agent_start fires for every low-level run (retries, compaction...). Only the first counts.
			if (runStartedAt !== undefined) return;
			runStartedAt = deps.now();
			toolCalls = 0;
			blockedAtStart = blockedCount();
			if (config.notify.terminal.enabled && config.notify.terminal.title && ctx.hasUI) {
				ctx.ui.setTitle(`⏳ ${config.notify.teams.title || "pi"} — ${os.hostname()}`);
			}
		});

		pi.on("tool_execution_end", async () => {
			toolCalls++;
		});

		pi.on("agent_settled", async (event, ctx) => {
			const started = runStartedAt;
			runStartedAt = undefined;
			if (started === undefined) return;
			const durationSec = (deps.now() - started) / 1000;
			if (durationSec < config.notify.minDurationSec) return;
			// Don't await network I/O in the event loop of the agent: fire and forget.
			void notifyAll(ctx, summary(ctx, event.aborted ? "aborted" : "done", durationSec), false).catch(() => {});
		});

		pi.registerCommand("notify-test", {
			description: "Send a test notification (Teams webhook + terminal bell)",
			handler: async (_args, ctx) => {
				config = loadConfig();
				const report = await notifyAll(ctx, summary(ctx, "test", 0), true);
				ctx.ui.notify(`📣 ${report.join("\n")}`, "info");
			},
		});
	};
}

export default createNotifyExtension();
