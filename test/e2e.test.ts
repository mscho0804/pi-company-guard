/**
 * End-to-end: real pi runtime (SDK + extension loader via jiti) driven by pi-ai's scripted
 * "faux" model provider. Verifies the extensions as pi actually loads and runs them:
 * tool calls are blocked, secrets are redacted before the model sees them, and the Teams
 * webhook is delivered (with real curl) when the run settles.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { fauxAssistantMessage, fauxProvider, fauxToolCall } from "@earendil-works/pi-ai/providers/faux";
import { createAgentSession, DefaultResourceLoader, ModelRuntime, SessionManager, SettingsManager } from "@earendil-works/pi-coding-agent";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pcg-e2e-"));
const project = path.join(tmp, "project");
const agentDir = path.join(tmp, "agent");
fs.mkdirSync(project, { recursive: true });
fs.mkdirSync(agentDir, { recursive: true });
fs.writeFileSync(path.join(project, ".env"), "DB_PASSWORD=super-secret-value\n");
fs.writeFileSync(path.join(project, "config.txt"), "region=ap-northeast-2\naws_key=AKIAIOSFODNN7EXAMPLE\n");
fs.writeFileSync(path.join(project, "hello.txt"), "hello world\n");

describe("e2e: real pi session with faux model", () => {
	let server: http.Server;
	const hooks: any[] = [];

	before(async () => {
		server = http.createServer((req, res) => {
			let body = "";
			req.on("data", (d) => (body += d));
			req.on("end", () => {
				hooks.push(JSON.parse(body));
				res.statusCode = 202;
				res.end();
			});
		});
		await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
		const cfg = path.join(tmp, "company-guard.json");
		fs.writeFileSync(
			cfg,
			JSON.stringify({
				audit: { path: path.join(tmp, "audit.jsonl") },
				notify: {
					minDurationSec: 0,
					terminal: { enabled: false },
					teams: { webhookUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}/hook`, webhookUrlEnv: "PCG_E2E_UNSET" },
				},
			}),
		);
		process.env.PI_GUARD_CONFIG = cfg;
	});
	after(() => server.close());

	it("blocks, redacts and notifies inside a real agent run", async () => {
		const faux = fauxProvider();
		const modelRuntime = await ModelRuntime.create({ authPath: path.join(agentDir, "auth.json"), modelsPath: path.join(agentDir, "models.json") });
		modelRuntime.registerNativeProvider(faux.provider);

		faux.setResponses([
			fauxAssistantMessage([fauxToolCall("read", { path: ".env" })], { stopReason: "toolUse" }),
			fauxAssistantMessage([fauxToolCall("bash", { command: "cat ~/.ssh/id_rsa" })], { stopReason: "toolUse" }),
			fauxAssistantMessage([fauxToolCall("read", { path: "config.txt" })], { stopReason: "toolUse" }),
			fauxAssistantMessage([fauxToolCall("bash", { command: "rm -rf build" })], { stopReason: "toolUse" }),
			fauxAssistantMessage([fauxToolCall("read", { path: "hello.txt" })], { stopReason: "toolUse" }),
			fauxAssistantMessage("All done."),
		]);

		const resourceLoader = new DefaultResourceLoader({
			cwd: project,
			agentDir,
			additionalExtensionPaths: [path.join(root, "extensions", "guardrail.ts"), path.join(root, "extensions", "notify.ts")],
		});
		await resourceLoader.reload();

		const { session, extensionsResult } = await createAgentSession({
			cwd: project,
			agentDir,
			model: faux.getModel(),
			thinkingLevel: "off",
			modelRuntime,
			resourceLoader,
			tools: ["read", "bash"],
			sessionManager: SessionManager.inMemory(project),
			settingsManager: SettingsManager.inMemory({ compaction: { enabled: false }, retry: { enabled: false } }),
		});
		assert.deepEqual(extensionsResult.errors, [], JSON.stringify(extensionsResult.errors));
		assert.equal(extensionsResult.extensions.length, 2);

		try {
			await session.prompt("do the task");
		} finally {
			session.dispose();
		}

		const results = (session.messages as any[]).filter((m) => m.role === "toolResult");
		const text = (m: any) => m.content.map((c: any) => c.text ?? "").join("");
		assert.equal(results.length, 5, results.map(text).join("\n---\n"));

		// 1. read .env -> blocked, secret never read
		assert.equal(results[0].isError, true);
		assert.match(text(results[0]), /Blocked by company guardrail/);
		// 2. cat ~/.ssh/id_rsa -> blocked
		assert.equal(results[1].isError, true);
		assert.match(text(results[1]), /sensitive/);
		// 3. config.txt read, AWS key redacted before reaching the model
		assert.equal(results[2].isError, false);
		assert.match(text(results[2]), /region=ap-northeast-2/);
		assert.match(text(results[2]), /\[REDACTED:aws-access-key\]/);
		assert.doesNotMatch(text(results[2]), /AKIAIOSFODNN7EXAMPLE/);
		// 4. rm -rf build -> confirm-level, no UI in SDK mode -> blocked (fail closed)
		assert.equal(results[3].isError, true);
		assert.match(text(results[3]), /no interactive UI/);
		// 5. normal read passes through untouched
		assert.equal(results[4].isError, false);
		assert.match(text(results[4]), /hello world/);

		// Nothing secret anywhere in what the model saw
		const transcript = JSON.stringify(session.messages);
		assert.doesNotMatch(transcript, /super-secret-value|AKIAIOSFODNN7EXAMPLE/);

		// Teams webhook delivered via curl after agent_settled (fire-and-forget -> poll)
		for (let i = 0; i < 50 && hooks.length === 0; i++) await new Promise((r) => setTimeout(r, 100));
		assert.equal(hooks.length, 1, "webhook not received");
		const card = hooks[0].attachments[0].content;
		assert.match(card.body[0].text, /작업 완료/);
		const facts = Object.fromEntries(card.body[1].facts.map((f: any) => [f.title, f.value]));
		assert.equal(facts["Tool calls"], "5");
		assert.equal(facts.Blocked, "3");

		// Audit log written by the real runtime (notify entry lands after curl exits -> poll)
		const auditFile = path.join(tmp, "audit.jsonl");
		for (let i = 0; i < 50 && !fs.readFileSync(auditFile, "utf8").includes('"event":"notify"'); i++) await new Promise((r) => setTimeout(r, 100));
		const audit = fs.readFileSync(auditFile, "utf8");
		assert.match(audit, /"decision":"block"/);
		assert.match(audit, /"decision":"redacted"/);
		assert.match(audit, /"event":"notify"/);
	});
});
