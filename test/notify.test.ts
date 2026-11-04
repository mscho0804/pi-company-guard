import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { defaultConfig, loadConfig, resolveWebhookUrl } from "../src/config.ts";
import { buildCurlConfig, buildTeamsPayload, buildTerminalSequence, curlQuote, formatDuration, type RunSummary, sendWebhook } from "../src/notify.ts";

const summary: RunSummary = {
	title: "pi",
	status: "done",
	durationSec: 125,
	host: "dev-01",
	user: "ms",
	cwd: "/home/ms/proj",
	toolCalls: 12,
	blocked: 1,
	model: "anthropic/claude",
};

describe("teams payload", () => {
	it("is an Adaptive Card message accepted by Teams Workflows", () => {
		const p = buildTeamsPayload(summary) as any;
		assert.equal(p.type, "message");
		assert.equal(p.attachments[0].contentType, "application/vnd.microsoft.card.adaptive");
		const card = p.attachments[0].content;
		assert.equal(card.type, "AdaptiveCard");
		assert.match(card.body[0].text, /✅ pi: 작업 완료/);
		const facts = Object.fromEntries(card.body[1].facts.map((f: any) => [f.title, f.value]));
		assert.equal(facts.Host, "ms@dev-01");
		assert.equal(facts.Duration, "2m 5s");
		assert.equal(facts.Blocked, "1");
	});
	it("formatDuration", () => {
		assert.equal(formatDuration(5), "5s");
		assert.equal(formatDuration(3725), "1h 2m 5s");
	});
});

describe("curl config", () => {
	it("quotes safely", () => {
		assert.equal(curlQuote(`a"b\\c\nd`), `"a\\"b\\\\c\\nd"`);
	});
	it("puts url and body in the config, not argv", () => {
		const c = buildCurlConfig("https://x.example/hook?sig=a&b=c", JSON.stringify({ t: 'say "hi"' }), 7);
		assert.match(c, /^url = "https:\/\/x\.example\/hook\?sig=a&b=c"$/m);
		assert.match(c, /^data-binary = "\{\\"t\\":\\"say \\\\\\"hi\\\\\\"\\"\}"$/m);
		assert.match(c, /^max-time = 7$/m);
	});
});

describe("sendWebhook (real curl against a local server)", () => {
	let server: http.Server;
	let url = "";
	const received: { headers: http.IncomingHttpHeaders; body: string }[] = [];
	before(async () => {
		server = http.createServer((req, res) => {
			let body = "";
			req.on("data", (d) => (body += d));
			req.on("end", () => {
				received.push({ headers: req.headers, body });
				res.statusCode = req.url?.includes("fail") ? 400 : 202; // Teams Workflows answers 202
				res.end();
			});
		});
		await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
		url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/workflows/test`;
	});
	after(() => server.close());

	it("delivers the card via curl", async () => {
		const r = await sendWebhook(url, buildTeamsPayload(summary), 5);
		assert.equal(r.via, "curl");
		assert.ok(r.ok, r.error);
		assert.equal(r.status, 202);
		const last = received.at(-1)!;
		assert.equal(last.headers["content-type"], "application/json");
		assert.deepEqual(JSON.parse(last.body), buildTeamsPayload(summary));
	});
	it("reports HTTP errors", async () => {
		const r = await sendWebhook(`${url}/fail`, { a: 1 }, 5);
		assert.equal(r.ok, false);
		assert.equal(r.status, 400);
	});
	it("falls back to fetch when curl is missing", async () => {
		const r = await sendWebhook(url, { a: 1 }, 5, "curl-does-not-exist-xyz");
		assert.equal(r.via, "fetch");
		assert.ok(r.ok, r.error);
	});
	it("reports unreachable hosts", async () => {
		const r = await sendWebhook("http://127.0.0.1:1/x", { a: 1 }, 3);
		assert.equal(r.ok, false);
		assert.ok(r.error);
	});
});

describe("terminal sequence", () => {
	it("bell only by default", () => {
		assert.equal(buildTerminalSequence({ bell: true, osc: "off", title: "pi", body: "done" }, {}), "\x07");
	});
	it("osc777 + bell", () => {
		assert.equal(buildTerminalSequence({ bell: true, osc: "osc777", title: "pi", body: "done" }, {}), "\x1b]777;notify;pi;done\x07\x07");
	});
	it("osc9", () => {
		assert.equal(buildTerminalSequence({ bell: false, osc: "osc9", title: "pi", body: "done" }, {}), "\x1b]9;pi: done\x07");
	});
	it("strips control chars and separators from text", () => {
		const s = buildTerminalSequence({ bell: false, osc: "osc777", title: "p;i", body: "a\x1b]0;evil\x07b" }, {});
		assert.equal(s, "\x1b]777;notify;p i;a ]0 evil b\x07");
	});
	it("wraps OSC for tmux passthrough, bell stays raw", () => {
		const s = buildTerminalSequence({ bell: true, osc: "osc777", title: "pi", body: "x" }, { TMUX: "/tmp/tmux-1/default,1,0" });
		assert.ok(s.startsWith("\x1bPtmux;\x1b\x1b]777;"));
		assert.ok(s.endsWith("\x1b\\\x07"));
	});
});

describe("config", () => {
	it("merges files: arrays append, scalars replace, invalid json ignored", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pcg-cfg-"));
		const a = path.join(dir, "a.json");
		const b = path.join(dir, "b.json");
		const bad = path.join(dir, "bad.json");
		fs.writeFileSync(a, JSON.stringify({ guard: { sensitivePaths: ["**/secret-dir/**"], workspaceOnly: true } }));
		fs.writeFileSync(b, JSON.stringify({ guard: { workspaceOnly: false, readOnlyHostPattern: "prod" }, notify: { minDurationSec: 5 } }));
		fs.writeFileSync(bad, "{ nope");
		const c = loadConfig([a, b, bad, path.join(dir, "missing.json")]);
		assert.ok(c.guard.sensitivePaths.includes("**/secret-dir/**"));
		assert.ok(c.guard.sensitivePaths.includes(".env"), "defaults kept");
		assert.equal(c.guard.workspaceOnly, false);
		assert.equal(c.guard.readOnlyHostPattern, "prod");
		assert.equal(c.notify.minDurationSec, 5);
		assert.equal(c.notify.teams.webhookUrlEnv, "PI_TEAMS_WEBHOOK_URL");
		assert.equal(c.loadedFrom.length, 3);
		assert.match(c.loadedFrom[2], /INVALID JSON/);
	});
	it("webhook url: env wins over file", () => {
		const n = defaultConfig().notify;
		n.teams.webhookUrl = "https://file.example";
		n.teams.webhookUrlEnv = "PCG_TEST_HOOK";
		assert.equal(resolveWebhookUrl(n), "https://file.example");
		process.env.PCG_TEST_HOOK = "https://env.example";
		assert.equal(resolveWebhookUrl(n), "https://env.example");
		delete process.env.PCG_TEST_HOOK;
	});
});
