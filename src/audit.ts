/**
 * Append-only JSONL audit log of guarded tool calls.
 * Entries are redacted and truncated; file content written by the agent is never logged.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { type AuditConfig, expandHome } from "./config.ts";
import { redactText } from "./redact.ts";

export interface AuditEntry {
	event: "tool_call" | "tool_result" | "session_start" | "notify";
	tool?: string;
	target?: string;
	decision?: "allow" | "block" | "confirm-approved" | "confirm-denied" | "redacted" | "error";
	rules?: string[];
	reason?: string;
	[key: string]: unknown;
}

const MAX_FIELD = 2000;

function clip(s: string): string {
	return s.length > MAX_FIELD ? `${s.slice(0, MAX_FIELD)}…(+${s.length - MAX_FIELD} chars)` : s;
}

let cachedUser: string | undefined;
function currentUser(): string {
	if (cachedUser) return cachedUser;
	try {
		cachedUser = os.userInfo().username;
	} catch {
		cachedUser = process.env.USER ?? process.env.USERNAME ?? "unknown";
	}
	return cachedUser;
}

export function auditPath(cfg: AuditConfig): string {
	return path.resolve(expandHome(cfg.path));
}

export function writeAudit(cfg: AuditConfig, entry: AuditEntry, cwd: string = process.cwd()): void {
	if (!cfg.enabled) return;
	try {
		const file = auditPath(cfg);
		fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
		const record: Record<string, unknown> = {
			ts: new Date().toISOString(),
			user: currentUser(),
			host: os.hostname(),
			pid: process.pid,
			cwd,
			...entry,
		};
		if (typeof record.target === "string") record.target = clip(redactText(record.target).text);
		if (typeof record.reason === "string") record.reason = clip(record.reason);
		fs.appendFileSync(file, `${JSON.stringify(record)}\n`, { encoding: "utf8", mode: 0o600 });
	} catch {
		// Auditing must never break the agent.
	}
}
