import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { assertNodeVersion, SUPPORTED_NODE_RANGE } from "../src/cli/node-version-check.js";

const patched = ["22.23.4", "22.23.5", "22.24.0", "24.22.1", "24.22.2", "24.23.0", "26.12.1", "26.13.0"];
const rejected = [
	"20.20.0",
	"22.8.0",
	"22.23.3",
	"24.0.0",
	"24.22.0",
	"26.0.0",
	"26.12.0",
	"23.99.0",
	"25.99.0",
	"27.0.0",
	"28.0.0",
	"22.24.0-rc.1",
	"24.22.1-rc.1",
	"26.13.0-nightly.1",
	"not-a-version",
	"24.22",
	"024.22.1",
	"24.22.1.0",
];

function run(version: string) {
	const logs: string[] = [];
	let exitCode: number | null = null;
	const ok = assertNodeVersion({
		version,
		log: (message) => logs.push(message),
		exit: (code) => {
			exitCode = code;
		},
	});
	return { ok, logs, exitCode };
}

describe("CLI runtime security check", () => {
	test.each([...patched, "v22.23.4", "24.22.1+build.1"])("accepts patched Node %s", (version) => {
		expect(run(version)).toEqual({ ok: true, logs: [], exitCode: null });
	});
	test.each(rejected)("rejects Node %s before loading the CLI", (version) => {
		const result = run(version);
		expect(result.ok).toBe(false);
		expect(result.exitCode).toBe(1);
		expect(result.logs.join("\n")).toContain(SUPPORTED_NODE_RANGE);
		expect(result.logs.join("\n")).toContain("CVE-2026-111497");
	});
});

const installer = readFileSync(new URL("../../../install.sh", import.meta.url), "utf8");
const mainIndex = installer.lastIndexOf('\nmain "$@"');
if (mainIndex < 0) throw new Error("Installer main entrypoint not found");
const functions = installer.slice(0, mainIndex);

describe("installer runtime security check", () => {
	test.each([...patched, "v22.23.4"])("accepts patched Node %s", (version) => {
		const result = spawnSync("sh", ["-c", `${functions}\nnode_version_string_is_new_enough "$1"`, "test", version]);
		expect(result.status).toBe(0);
	});
	test.each(rejected)("rejects Node %s", (version) => {
		const result = spawnSync("sh", ["-c", `${functions}\nnode_version_string_is_new_enough "$1"`, "test", version]);
		expect(result.status).toBe(1);
	});
	test.each([
		["22.23.4-1nodesource1", 0],
		["1:24.22.1+dfsg-1", 0],
		["22.23.3-1nodesource1", 1],
		["24.23.0~rc1-1", 1],
		["26.13.0-rc1", 1],
	])("checks the upstream version of apt candidate %s", (version, status) => {
		const result = spawnSync("sh", [
			"-c",
			`${functions.replace("apt-cache policy nodejs", "apt_cache_mock")}\napt_cache_mock() { printf 'Candidate: %s\\n' "${version}"; }\napt_node_candidate_is_new_enough`,
		]);
		expect(result.status).toBe(status);
	});
	test("preflight rejects an old executable even when npm exists", () => {
		const result = spawnSync(
			"sh",
			["-c", `${functions}\nnode() { printf 'v24.22.0\\n'; }\nnpm() { :; }\nrun_preflight_checks`],
			{ encoding: "utf8" },
		);
		expect(result.status).toBe(1);
		expect(result.stdout).toContain("Found v24.22.0");
	});
});
