#!/usr/bin/env node
/**
 * Sandbox demo runner. Spawned as a short-lived, disposable child process by
 * POST /api/sandbox/node-demo - deliberately never runs inside the dashboard
 * hub's own long-running process. Installing the real network/process/fs
 * shields on the hub itself would risk the hub's own legitimate OSV/npm
 * registry calls (or its own scanner subprocess/file access) being caught by
 * a demo's block list; a throwaway child process contains that risk to
 * something that exits in milliseconds either way.
 *
 * Usage: node runner.js <network|process|fs> <hubUrl>
 */

process.env.PHISHGUARD_DISABLE_AUTOINSTALL = '1'; // install explicitly, below, with demo-only config

const { installAgent } = require('../index.js');

const [, , vector, hubUrl] = process.argv;

installAgent({
  hubUrl: hubUrl || 'http://localhost:4173',
  blockDomains: ['malicious-domain.com'],
  reportRuntime: false,
});

const demo = require('./node_modules/phishguard-demo-package');

async function main() {
  try {
    if (vector === 'network') await demo.networkDemo();
    else if (vector === 'process') demo.processDemo();
    else if (vector === 'fs') demo.fsDemo();
    else throw new Error(`unknown demo vector: ${vector}`);
  } catch {
    // Expected for a blocked demo - the shield already reported the real
    // enforcement outcome over telemetry. Nothing further to do here.
  }
  // sendTelemetry() is fire-and-forget; without this, a process this
  // short-lived can exit before its own POST /api/telemetry actually lands.
  await new Promise((resolve) => setTimeout(resolve, 500));
}

main();
