/**
 * Environment check for the SSH server — run BEFORE wiring things into pi:
 *
 *   node scripts/check-notify.ts              # uses $PI_TEAMS_WEBHOOK_URL / company-guard.json
 *   node scripts/check-notify.ts <webhook-url>
 *
 * Prints proxy settings, rings the terminal bell, and sends a test Teams card.
 * (Node >= 22.18 runs .ts files directly.)
 */
import os from "node:os";
import { loadConfig, resolveWebhookUrl } from "../src/config.ts";
import { buildTeamsPayload, buildTerminalSequence, sendWebhook } from "../src/notify.ts";

const cfg = loadConfig();
const url = process.argv[2] || resolveWebhookUrl(cfg.notify);

console.log("== pi-company-guard notify check ==");
console.log(`host:        ${os.hostname()}`);
console.log(`config:      ${cfg.loadedFrom.join(", ") || "(defaults)"}`);
for (const k of ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"]) {
	if (process.env[k]) console.log(`${k.padEnd(12)} ${process.env[k]}`);
}
console.log(`TERM:        ${process.env.TERM ?? "-"}${process.env.TMUX ? " (inside tmux)" : ""}`);

process.stdout.write(buildTerminalSequence({ bell: true, osc: cfg.notify.terminal.osc, title: "pi", body: "notify check" }));
console.log("terminal:    bell sent — your terminal tab should flash / beep");

if (!url) {
	console.log(`teams:       SKIPPED — export ${cfg.notify.teams.webhookUrlEnv}='https://...' or pass the URL as an argument`);
	process.exit(0);
}
const masked = url.replace(/([?&]sig=)[^&]+/i, "$1***");
console.log(`teams:       POST ${masked.slice(0, 80)}${masked.length > 80 ? "…" : ""}`);
const r = await sendWebhook(
	url,
	buildTeamsPayload({ title: cfg.notify.teams.title || "pi", status: "test", durationSec: 0, host: os.hostname(), user: os.userInfo().username, cwd: process.cwd(), toolCalls: 0, blocked: 0 }),
	cfg.notify.teams.timeoutSec,
);
if (r.ok) {
	console.log(`teams:       OK (HTTP ${r.status}, via ${r.via}) — check the Teams channel`);
} else {
	console.log(`teams:       FAILED (via ${r.via}) ${r.status ? `HTTP ${r.status}` : ""}\n             ${r.error}`);
	console.log("hints:       'Could not resolve host' / timeout -> outbound blocked: set HTTPS_PROXY or ask IT to allow the host");
	console.log("             401/403/404 -> wrong URL or the Workflow is turned off");
	process.exit(1);
}
