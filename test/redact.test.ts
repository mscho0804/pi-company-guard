import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildPatterns, redactDeep, redactText } from "../src/redact.ts";

describe("redactText", () => {
	const cases: [string, string, string][] = [
		["aws key", "key AKIAIOSFODNN7EXAMPLE here", "aws-access-key"],
		["github", "token ghp_0123456789abcdefghijklmnopqrstuvwxyzAB", "github-token"],
		["github pat", "github_pat_11ABCDEFG0123456789_abcdefghijklmnop", "github-token"],
		["gitlab", "glpat-abcdefghij0123456789", "gitlab-token"],
		["slack", "xoxb-1234567890-abcdefghij", "slack-token"],
		["openai", "sk-proj-abcdefghijklmnopqrstuvwxyz0123", "openai-key"],
		["anthropic", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz", "anthropic-key"],
		["google", "AIzaSyA-1234567890abcdefghijklmnopqrstu", "google-api-key"],
		["jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "jwt"],
		["bearer", "Authorization: Bearer abcdef123456789xyz", "bearer"],
		["url creds", "postgres://admin:hunter2pass@db.internal:5432/app", "url-credentials"],
		["teams webhook", "https://prod-12.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=xyz", "teams-webhook"],
	];
	for (const [name, input, kind] of cases) {
		it(name, () => {
			const r = redactText(input);
			assert.ok(r.count >= 1, `no redaction in ${input}`);
			assert.ok(r.kinds.includes(kind), `kinds ${r.kinds}`);
			assert.ok(r.text.includes("[REDACTED"), r.text);
		});
	}

	it("private key block", () => {
		const pem = "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nAAAA\n-----END OPENSSH PRIVATE KEY-----\nafter";
		const r = redactText(pem);
		assert.equal(r.text, "before\n[REDACTED:private-key]\nafter");
	});

	it("dotenv file keeps keys, hides values", () => {
		const env = "DB_HOST=localhost\nDB_PASSWORD=s3cr3t!pw\nexport API_KEY='abcd1234efgh'\nSTRIPE_SECRET_KEY=\"sk_live_abcdefghijklmnopqrstuvwx\"\nDEBUG=true";
		const r = redactText(env);
		assert.match(r.text, /DB_HOST=localhost/);
		assert.match(r.text, /DB_PASSWORD=\[REDACTED:env-secret\]/);
		assert.match(r.text, /export API_KEY='\[REDACTED:env-secret\]'/);
		assert.doesNotMatch(r.text, /s3cr3t|abcd1234efgh|sk_live/);
		assert.match(r.text, /DEBUG=true/);
	});

	it("quoted secrets in JSON / YAML / code", () => {
		const r = redactText(`{"password": "hunter2hunter2", "user": "bob"}\nclient_secret: 'abcDEF123456'`);
		assert.doesNotMatch(r.text, /hunter2hunter2|abcDEF123456/);
		assert.match(r.text, /"user": "bob"/);
	});

	it("does not mangle ordinary code", () => {
		const code = [
			"const token = getToken();",
			"if (password.length < 8) throw new Error('weak');",
			"max_tokens: 1000",
			"PWD=/home/user/project",
			"author: John Smith",
			"import { secretManager } from './secrets';",
		].join("\n");
		const r = redactText(code);
		assert.equal(r.count, 0, r.text);
		assert.equal(r.text, code);
	});

	it("is idempotent", () => {
		const once = redactText("DB_PASSWORD=abcdefgh").text;
		const twice = redactText(once);
		assert.equal(twice.text, once);
		assert.equal(twice.count, 0);
	});

	it("custom patterns", () => {
		const r = redactText("employee CORP-12345678 ok", buildPatterns(["CORP-[0-9]{8}"]));
		assert.equal(r.text, "employee [REDACTED:custom] ok");
	});
});

describe("redactDeep", () => {
	it("walks nested structures", () => {
		const r = redactDeep({ a: ["AKIAIOSFODNN7EXAMPLE", { b: "ok" }], n: 3 });
		assert.deepEqual(r.value, { a: ["[REDACTED:aws-access-key]", { b: "ok" }], n: 3 });
		assert.equal(r.count, 1);
	});
});
