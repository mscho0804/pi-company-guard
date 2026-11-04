/**
 * pi-company-guard: guardrail extension
 *
 *  - blocks read/write of sensitive files (.env, keys, ~/.ssh, ~/.aws, ...)
 *  - blocks writes to protected locations (pi config, shell rc files, /etc, ...)
 *  - gates dangerous shell commands (block or ask for confirmation)
 *  - flags data egress (uploads, scp/nc, non-allowlisted hosts)
 *  - read-only mode on hosts matching `readOnlyHostPattern` (e.g. production)
 *  - redacts secrets from every tool result before it is sent to the model
 *  - writes a JSONL audit log
 *
 * Commands: /guard  (status)   /guard reload
 */
import os from "node:os";
import type { ExtensionAPI, ExtensionContext, ToolCallEvent, ToolCallEventResult } from "@earendil-works/pi-coding-agent";
import { writeAudit } from "../src/audit.ts";
import { evaluateCommand, isReadOnlyHost, type RuleMatch } from "../src/commands.ts";
import { type CompanyGuardConfig, loadConfig } from "../src/config.ts";
import { type Access, classifyPath } from "../src/paths.ts";
import { buildPatterns, type RedactPattern, redactDeep, redactText } from "../src/redact.ts";

const FILE_TOOLS: Record<string, Access> = {
	read: "read",
	grep: "read",
	find: "read",
	ls: "read",
	write: "write",
	edit: "write",
};
const SHELL_TOOLS = new Set(["bash", "powershell"]);
/** Input keys of custom tools that are treated as file paths. */
const GENERIC_PATH_KEYS = ["path", "file", "filePath", "file_path", "filename", "target", "source", "destination"];

export interface GuardStats {
	allowed: number;
	blocked: number;
	approved: number;
	denied: number;
	redactions: number;
}

/** Shared with the notify extension through globalThis (both load in the same process). */
export const STATS_KEY = Symbol.for("pi-company-guard.stats");

function blockMessage(reason: string): string {
	return `Blocked by company guardrail: ${reason}\nDo not try to work around this restriction (e.g. other tools, encodings or copies). If the task really needs it, stop and ask the user to do it manually.`;
}

export default function companyGuard(pi: ExtensionAPI) {
	let config: CompanyGuardConfig = loadConfig();
	let patterns: RedactPattern[] = buildPatterns(config.guard.extraRedactPatterns);
	let readOnly = isReadOnlyHost(config.guard);
	const stats: GuardStats = { allowed: 0, blocked: 0, approved: 0, denied: 0, redactions: 0 };
	(globalThis as Record<symbol, unknown>)[STATS_KEY] = stats;

	const reload = () => {
		config = loadConfig();
		patterns = buildPatterns(config.guard.extraRedactPatterns);
		readOnly = isReadOnlyHost(config.guard);
	};

	const audit = (ctx: ExtensionContext, entry: Parameters<typeof writeAudit>[1]) => writeAudit(config.audit, entry, ctx.cwd);

	async function decide(
		event: ToolCallEvent,
		ctx: ExtensionContext,
		target: string,
		decision: "allow" | "confirm" | "block",
		reason: string,
		rules: string[],
	): Promise<ToolCallEventResult | undefined> {
		if (decision === "allow") {
			stats.allowed++;
			audit(ctx, { event: "tool_call", tool: event.toolName, target, decision: "allow" });
			return undefined;
		}
		if (decision === "block") {
			stats.blocked++;
			audit(ctx, { event: "tool_call", tool: event.toolName, target, decision: "block", rules, reason });
			if (ctx.hasUI) ctx.ui.notify(`🛡️ Blocked ${event.toolName}: ${reason}`, "warning");
			return { block: true, reason: blockMessage(reason) };
		}
		// confirm
		let approved = false;
		if (ctx.hasUI) {
			approved = await ctx.ui.confirm("🛡️ Company guardrail", `${event.toolName}: ${target}\n\n${reason}\n\nAllow this once?`);
		} else {
			approved = config.guard.nonInteractive === "allow";
		}
		if (approved) {
			stats.approved++;
			audit(ctx, { event: "tool_call", tool: event.toolName, target, decision: "confirm-approved", rules, reason });
			return undefined;
		}
		stats.denied++;
		audit(ctx, { event: "tool_call", tool: event.toolName, target, decision: "confirm-denied", rules, reason });
		return {
			block: true,
			reason: blockMessage(ctx.hasUI ? `${reason} (denied by user)` : `${reason} (no interactive UI to confirm)`),
		};
	}

	pi.on("session_start", async (_event, ctx) => {
		reload();
		audit(ctx, { event: "session_start", readOnly, config: config.loadedFrom });
		if (!ctx.hasUI) return;
		if (!config.guard.enabled) {
			ctx.ui.setStatus("company-guard", "🛡️ guard OFF");
			return;
		}
		ctx.ui.setStatus("company-guard", readOnly ? "🛡️ guard (READ-ONLY host)" : "🛡️ guard");
		if (readOnly) ctx.ui.notify(`🛡️ ${os.hostname()} matches readOnlyHostPattern: write/edit and mutating commands are blocked.`, "warning");
		const invalid = config.loadedFrom.filter((f) => f.includes("INVALID"));
		if (invalid.length) ctx.ui.notify(`🛡️ Config error, defaults in effect: ${invalid.join(", ")}`, "error");
	});

	pi.on("tool_call", async (event, ctx) => {
		if (!config.guard.enabled) return undefined;
		try {
			const input = (event.input ?? {}) as Record<string, unknown>;

			// --- built-in file tools ---------------------------------------------------------
			const access = FILE_TOOLS[event.toolName];
			if (access) {
				const p = typeof input.path === "string" && input.path ? input.path : ".";
				if (readOnly && access === "write") {
					return decide(event, ctx, p, "block", `read-only host (${os.hostname()}): ${event.toolName} is disabled`, ["readonly"]);
				}
				const verdict = classifyPath(p, ctx.cwd, config.guard, access);
				if (verdict.decision === "block") {
					return decide(event, ctx, p, "block", verdict.reason ?? "protected path", [verdict.rule ?? "path"]);
				}
				// grep --glob "*.env" over a directory would read sensitive files in bulk
				if (event.toolName === "grep" && typeof input.glob === "string") {
					const g = classifyPath(input.glob, ctx.cwd, { ...config.guard, workspaceOnly: false }, "read");
					if (g.decision === "block") return decide(event, ctx, `${p} (glob ${input.glob})`, "block", g.reason ?? "sensitive glob", ["sensitive"]);
				}
				return decide(event, ctx, p, "allow", "", []);
			}

			// --- shell tools ---------------------------------------------------------------
			if (SHELL_TOOLS.has(event.toolName)) {
				const command = typeof input.command === "string" ? input.command : "";
				const v = evaluateCommand(command, ctx.cwd, config.guard, { readOnly });
				return decide(event, ctx, command, v.decision, v.reason, v.matches.map((m: RuleMatch) => m.id));
			}

			// --- custom / MCP tools: check anything that looks like a path ------------------
			for (const key of GENERIC_PATH_KEYS) {
				const val = input[key];
				if (typeof val !== "string" || !val) continue;
				const v = classifyPath(val, ctx.cwd, { ...config.guard, workspaceOnly: false }, "read");
				if (v.decision === "block") return decide(event, ctx, val, "block", v.reason ?? "protected path", [v.rule ?? "path"]);
			}
			return undefined;
		} catch (err) {
			// Fail closed: if the safety decision cannot be made, do not run the tool.
			stats.blocked++;
			audit(ctx, { event: "tool_call", tool: event.toolName, decision: "error", reason: String(err) });
			return { block: true, reason: blockMessage(`guardrail internal error: ${(err as Error).message}`) };
		}
	});

	pi.on("tool_result", async (event, ctx) => {
		if (!config.guard.enabled || !config.guard.redact) return undefined;
		let count = 0;
		const kinds = new Set<string>();
		const content = event.content.map((block) => {
			if (block.type !== "text") return block;
			const r = redactText(block.text, patterns);
			if (r.count === 0) return block;
			count += r.count;
			for (const k of r.kinds) kinds.add(k);
			return { ...block, text: r.text };
		});
		let structuredContent = event.structuredContent;
		if (structuredContent !== undefined) {
			const r = redactDeep(structuredContent, patterns);
			count += r.count;
			for (const k of r.kinds) kinds.add(k);
			structuredContent = r.value;
		}
		if (count === 0) return undefined;
		stats.redactions += count;
		audit(ctx, { event: "tool_result", tool: event.toolName, decision: "redacted", count, kinds: [...kinds] });
		if (ctx.hasUI) ctx.ui.notify(`🔒 Redacted ${count} secret(s) [${[...kinds].join(", ")}] from ${event.toolName} output`, "info");
		return structuredContent === undefined ? { content } : { content, structuredContent };
	});

	pi.registerCommand("guard", {
		description: "Company guardrail status (`/guard reload` to reload config)",
		handler: async (args, ctx) => {
			if (args.trim() === "reload") {
				reload();
				ctx.ui.notify("🛡️ company-guard config reloaded", "info");
			}
			const g = config.guard;
			const lines = [
				`🛡️ company-guard ${g.enabled ? "ON" : "OFF"}${readOnly ? " — READ-ONLY host" : ""}`,
				`config: ${config.loadedFrom.length ? config.loadedFrom.join(", ") : "(defaults only)"}`,
				`sensitive patterns: ${g.sensitivePaths.length}, write-protected: ${g.writeProtectedPaths.length}, allow: ${g.allowPaths.length}`,
				`workspaceOnly: ${g.workspaceOnly}, nonInteractive: ${g.nonInteractive}, redact: ${g.redact}`,
				`egress allowlist: ${g.egressAllowedHosts.join(", ")}`,
				`audit: ${config.audit.enabled ? config.audit.path : "off"}`,
				`this session — allowed ${stats.allowed}, blocked ${stats.blocked}, approved ${stats.approved}, denied ${stats.denied}, redactions ${stats.redactions}`,
			];
			ctx.ui.notify(lines.join("\n"), "info");
		},
	});
}
