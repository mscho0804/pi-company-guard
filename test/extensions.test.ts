/**
 * Extension-level tests: load the real extension factories into a minimal fake ExtensionAPI
 * and drive them with tool_call / tool_result / agent events.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pcg-ext-"));
const auditFile = path.join(tmp, "audit.jsonl");
const cfgFile = path.join(tmp, "company-guard.json");
fs.writeFileSync(cfgFile, JSON.stringify({ audit: { path: auditFile }, notify: { minDurationSec: 10, teams: { webhookUrlEnv: "PCG_EXT_HOOK" } } }));
process.env.PI_GUARD_CONFIG = cfgFile;

type Handler = (event: any, ctx: any) => any;

function fakePi() {
	const handlers = new Map<string, Handler[]>();
	const commands = new Map<string, any>();
	const api: any = {
		on(name: string, h: Handler) {
			handlers.set(name, [...(handlers.get(name) ?? []), h]);
			return () => {};
		},
		registerCommand(name: string, def: any) {
			commands.set(name, def);
		},
	};
	const emit = async (name: string, event: any, ctx: any) => {
		let last: any;
		for (const h of handlers.get(name) ?? []) last = await h(event, ctx);
		return last;
	};
	return { api, emit, commands };
}

function fakeCtx(opts: { hasUI?: boolean; confirm?: boolean; cwd?: string } = {}) {
	const notes: string[] = [];
	const confirms: string[] = [];
	const titles: string[] = [];
	const ctx: any = {
		hasUI: opts.hasUI ?? true,
		cwd: opts.cwd ?? tmp,
		model: { provider: "test", id: "model" },
		ui: {
			notify: (m: string) => notes.push(m),
			confirm: async (_t: string, m: string) => {
				confirms.push(m);
				return opts.confirm ?? false;
			},
			setStatus: () => {},
			setTitle: (t: string) => titles.push(t),
		},
	};
	return { ctx, notes, confirms, titles };
}

const call = (toolName: string, input: Record<string, unknown>) => ({ type: "tool_call", toolCallId: "1", toolName, input });

describe("guardrail extension", async () => {
	const { default: guardrail } = await import("../extensions/guardrail.ts");
	const pi = fakePi();
	guardrail(pi.api);
	await pi.emit("session_start", { type: "session_start" }, fakeCtx().ctx);

	it("blocks reading .env with a model-facing reason", async () => {
		const { ctx, notes } = fakeCtx();
		const r = await pi.emit("tool_call", call("read", { path: ".env" }), ctx);
		assert.equal(r?.block, true);
		assert.match(r.reason, /company guardrail/);
		assert.match(r.reason, /Do not try to work around/);
		assert.ok(notes.some((n) => n.includes("Blocked read")));
	});

	it("blocks writing to ~/.ssh and to the guard config", async () => {
		const { ctx } = fakeCtx();
		assert.equal((await pi.emit("tool_call", call("write", { path: "~/.ssh/authorized_keys", content: "x" }), ctx))?.block, true);
		assert.equal((await pi.emit("tool_call", call("edit", { path: "~/.pi/agent/company-guard.json", edits: [] }), ctx))?.block, true);
	});

	it("blocks grep with a sensitive glob", async () => {
		const r = await pi.emit("tool_call", call("grep", { pattern: "KEY", path: ".", glob: "*.env" }), fakeCtx().ctx);
		assert.equal(r?.block, true);
	});

	it("allows normal file access", async () => {
		const { ctx } = fakeCtx();
		assert.equal(await pi.emit("tool_call", call("read", { path: "src/index.ts" }), ctx), undefined);
		assert.equal(await pi.emit("tool_call", call("write", { path: "out/a.txt", content: "" }), ctx), undefined);
		assert.equal(await pi.emit("tool_call", call("ls", {}), ctx), undefined);
	});

	it("hard-blocks catastrophic bash without asking", async () => {
		const { ctx, confirms } = fakeCtx({ confirm: true });
		const r = await pi.emit("tool_call", call("bash", { command: "rm -rf ~" }), ctx);
		assert.equal(r?.block, true);
		assert.equal(confirms.length, 0);
	});

	it("asks for confirmation on risky bash — user approves", async () => {
		const { ctx, confirms } = fakeCtx({ confirm: true });
		const r = await pi.emit("tool_call", call("bash", { command: "git push --force" }), ctx);
		assert.equal(r, undefined);
		assert.equal(confirms.length, 1);
		assert.match(confirms[0], /git-force-push/);
	});

	it("asks for confirmation on risky bash — user denies", async () => {
		const { ctx } = fakeCtx({ confirm: false });
		const r = await pi.emit("tool_call", call("bash", { command: "kubectl delete ns prod" }), ctx);
		assert.equal(r?.block, true);
		assert.match(r.reason, /denied by user/);
	});

	it("non-interactive mode blocks confirm-level commands", async () => {
		const { ctx } = fakeCtx({ hasUI: false });
		const r = await pi.emit("tool_call", call("bash", { command: "sudo systemctl restart nginx" }), ctx);
		assert.equal(r?.block, true);
		assert.match(r.reason, /no interactive UI/);
	});

	it("checks path-like inputs of custom tools", async () => {
		const r = await pi.emit("tool_call", call("mcp_fs_read", { file_path: "~/.aws/credentials" }), fakeCtx().ctx);
		assert.equal(r?.block, true);
	});

	it("redacts secrets from tool results (content + structuredContent)", async () => {
		const { ctx, notes } = fakeCtx();
		const r = await pi.emit(
			"tool_result",
			{
				type: "tool_result",
				toolCallId: "1",
				toolName: "bash",
				input: { command: "cat config.yml" },
				content: [{ type: "text", text: "db:\n  password: 'hunter2hunter2'\naws: AKIAIOSFODNN7EXAMPLE\n" }],
				structuredContent: { output: "AKIAIOSFODNN7EXAMPLE" },
				isError: false,
				details: undefined,
			},
			ctx,
		);
		assert.ok(r, "expected a modified result");
		assert.doesNotMatch(r.content[0].text, /hunter2hunter2|AKIAIOSFODNN7EXAMPLE/);
		assert.deepEqual(r.structuredContent, { output: "[REDACTED:aws-access-key]" });
		assert.ok(notes.some((n) => n.includes("Redacted 3 secret")), notes.join("|"));
	});

	it("leaves clean results untouched", async () => {
		const r = await pi.emit(
			"tool_result",
			{ type: "tool_result", toolCallId: "1", toolName: "read", input: {}, content: [{ type: "text", text: "hello" }], isError: false, details: undefined },
			fakeCtx().ctx,
		);
		assert.equal(r, undefined);
	});

	it("writes a redacted JSONL audit log", () => {
		const lines = fs.readFileSync(auditFile, "utf8").trim().split("\n").map((l) => JSON.parse(l));
		assert.ok(lines.some((l) => l.event === "session_start"));
		assert.ok(lines.some((l) => l.event === "tool_call" && l.decision === "block" && l.target === ".env"));
		assert.ok(lines.some((l) => l.decision === "confirm-approved" && l.rules.includes("git-force-push")));
		assert.ok(lines.some((l) => l.decision === "confirm-denied"));
		assert.ok(lines.some((l) => l.event === "tool_result" && l.decision === "redacted" && l.count === 3));
		assert.ok(lines.every((l) => l.ts && l.user && l.host));
		assert.ok(!fs.readFileSync(auditFile, "utf8").includes("AKIAIOSFODNN7EXAMPLE"));
	});

	it("/guard command reports status", async () => {
		const { ctx, notes } = fakeCtx();
		await pi.commands.get("guard").handler("", ctx);
		assert.match(notes.at(-1)!, /company-guard ON/);
		assert.match(notes.at(-1)!, /blocked \d+/);
	});
});

describe("read-only host", async () => {
	it("blocks write/edit and mutating bash when hostname matches", async () => {
		const roCfg = path.join(tmp, "ro.json");
		fs.writeFileSync(roCfg, JSON.stringify({ audit: { enabled: false }, guard: { readOnlyHostPattern: "." } }));
		process.env.PI_GUARD_CONFIG = roCfg;
		try {
			const { default: guardrail } = await import(`../extensions/guardrail.ts?ro=${Date.now()}`);
			const pi = fakePi();
			guardrail(pi.api);
			const { ctx, notes } = fakeCtx({ confirm: true });
			await pi.emit("session_start", {}, ctx);
			assert.ok(notes.some((n) => n.includes("readOnlyHostPattern")));
			assert.equal((await pi.emit("tool_call", call("write", { path: "a.txt", content: "" }), ctx))?.block, true);
			assert.equal((await pi.emit("tool_call", call("bash", { command: "echo x > a.txt" }), ctx))?.block, true);
			assert.equal((await pi.emit("tool_call", call("bash", { command: "git push --force" }), ctx))?.block, true, "confirm escalated");
			assert.equal(await pi.emit("tool_call", call("bash", { command: "tail -n 50 app.log" }), ctx), undefined);
		} finally {
			process.env.PI_GUARD_CONFIG = cfgFile;
		}
	});
});

describe("notify extension", async () => {
	const { createNotifyExtension } = await import("../extensions/notify.ts");
	let clock = 1_000_000;
	const sent: { url: string; payload: any }[] = [];
	const terminal: string[] = [];
	let sendOk = true;
	const deps = {
		now: () => clock,
		writeTerminal: (s: string) => terminal.push(s),
		send: async (url: string, payload: unknown) => {
			sent.push({ url, payload });
			return sendOk ? { ok: true, status: 202, via: "curl" as const } : { ok: false, error: "proxy refused", via: "curl" as const };
		},
	};
	const pi = fakePi();
	createNotifyExtension(deps)(pi.api);
	const flush = () => new Promise((r) => setTimeout(r, 10));

	before(() => {
		process.env.PCG_EXT_HOOK = "https://example.webhook.office.com/hook";
	});
	after(() => {
		delete process.env.PCG_EXT_HOOK;
	});

	async function run(seconds: number, ctx: any, aborted = false, tools = 2) {
		await pi.emit("agent_start", {}, ctx);
		await pi.emit("agent_start", {}, ctx); // retry: must not reset the timer
		for (let i = 0; i < tools; i++) await pi.emit("tool_execution_end", {}, ctx);
		clock += seconds * 1000;
		await pi.emit("agent_settled", { type: "agent_settled", aborted }, ctx);
		await flush();
	}

	it("does nothing for short runs", async () => {
		const { ctx } = fakeCtx();
		await pi.emit("session_start", {}, ctx);
		await run(3, ctx);
		assert.equal(sent.length, 0);
		assert.equal(terminal.length, 0);
	});

	it("sends Teams card + terminal bell for long runs", async () => {
		const { ctx, titles } = fakeCtx();
		await run(95, ctx, false, 4);
		assert.equal(sent.length, 1);
		assert.equal(sent[0].url, "https://example.webhook.office.com/hook");
		const card = sent[0].payload.attachments[0].content;
		assert.match(card.body[0].text, /작업 완료/);
		const facts = Object.fromEntries(card.body[1].facts.map((f: any) => [f.title, f.value]));
		assert.equal(facts.Duration, "1m 35s");
		assert.equal(facts["Tool calls"], "4");
		assert.equal(facts.Model, "test/model");
		assert.deepEqual(terminal, ["\x07"]);
		assert.ok(titles[0].startsWith("⏳"));
		assert.ok(titles.at(-1)!.startsWith("✅"));
	});

	it("reports aborted runs", async () => {
		const { ctx } = fakeCtx();
		await run(60, ctx, true);
		assert.match(sent.at(-1)!.payload.attachments[0].content.body[0].text, /중단/);
	});

	it("warns the user when Teams delivery fails, terminal still works", async () => {
		sendOk = false;
		const { ctx, notes } = fakeCtx();
		const before = terminal.length;
		await run(60, ctx);
		assert.equal(terminal.length, before + 1);
		assert.ok(notes.some((n) => n.includes("Teams notification failed: proxy refused")));
		sendOk = true;
	});

	it("/notify-test sends immediately and reports", async () => {
		const { ctx, notes } = fakeCtx();
		const n = sent.length;
		await pi.commands.get("notify-test").handler("", ctx);
		assert.equal(sent.length, n + 1);
		assert.match(notes.at(-1)!, /teams: sent \(HTTP 202/);
		assert.match(notes.at(-1)!, /terminal: bell=true/);
	});

	it("skips Teams cleanly without a webhook URL", async () => {
		delete process.env.PCG_EXT_HOOK;
		const { ctx, notes } = fakeCtx();
		const n = sent.length;
		await pi.commands.get("notify-test").handler("", ctx);
		assert.equal(sent.length, n);
		assert.match(notes.at(-1)!, /teams: skipped \(set \$PCG_EXT_HOOK/);
		process.env.PCG_EXT_HOOK = "https://example.webhook.office.com/hook";
	});
});
