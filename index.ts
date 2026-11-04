/**
 * Entry point when the repository is copied/cloned into ~/.pi/agent/extensions/pi-company-guard/
 * (pi loads `index.ts` of extension subdirectories). `pi install` uses the manifest in
 * package.json instead and loads the two extensions directly.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import guardrail from "./extensions/guardrail.ts";
import notify from "./extensions/notify.ts";

export default function (pi: ExtensionAPI) {
	guardrail(pi);
	notify(pi);
}
