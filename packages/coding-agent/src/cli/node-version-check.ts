// Dependency-free and Node-20-safe so it can never crash on the versions it rejects.

export const MIN_NODE_VERSION = "22.23.4";
export const SUPPORTED_NODE_RANGE = "^22.23.4 || ^24.22.1 || ^26.12.1";
const PATCHED_MINIMUMS = new Map<number, readonly [number, number]>([
	[22, [23, 4]],
	[24, [22, 1]],
	[26, [12, 1]],
]);

export interface NodeVersionGuardIO {
	version: string;
	log: (message: string) => void;
	exit: (code: number) => void;
}

interface ParsedNodeVersion {
	parts: readonly [number, number, number];
	prerelease: boolean;
}

function parseVersion(version: string): ParsedNodeVersion | undefined {
	const match = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(
		version,
	);
	if (!match) {
		return undefined;
	}

	return {
		parts: [Number(match[1]), Number(match[2]), Number(match[3])],
		prerelease: match[4] !== undefined,
	};
}

function isSupportedNodeVersion(version: ParsedNodeVersion): boolean {
	const [major, minor, patch] = version.parts;
	const minimum = PATCHED_MINIMUMS.get(major);
	return Boolean(
		!version.prerelease && minimum && (minor > minimum[0] || (minor === minimum[0] && patch >= minimum[1])),
	);
}

export function assertNodeVersion(io: NodeVersionGuardIO): boolean {
	// Bun ships its own runtime; its node-compat version is unrelated to the user's Node.
	if (process.versions.bun) {
		return true;
	}

	const version = parseVersion(io.version);
	if (version && isSupportedNodeVersion(version)) {
		return true;
	}

	io.log(
		`prime-agent requires patched Node ${SUPPORTED_NODE_RANGE} (CVE-2026-111497), but the active Node is v${io.version}.`,
	);
	io.log("");
	io.log(
		`  1. Install Node ${MIN_NODE_VERSION} (e.g. "nvm install ${MIN_NODE_VERSION} && nvm use ${MIN_NODE_VERSION}", or from https://nodejs.org)`,
	);
	io.log("  2. Reinstall prime-agent under that Node so the command resolves to it:");
	io.log("     https://github.com/PrimeIntellect-ai/prime-agent/releases/latest");
	io.exit(1);
	return false;
}
