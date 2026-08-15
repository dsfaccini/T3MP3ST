#!/usr/bin/env node
/**
 * Pre-prod / CI hunt — no live packets.
 *
 * Ingests a local repo you own, writes reports/ci-hunt.json, and emits a
 * delta against the previous report when one exists. Optional decompose
 * runs only when T3MP3ST_CI_DECOMPOSE=1 and an LLM key is present.
 *
 * Usage: node scripts/ci-hunt.mjs [repoPath]
 */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');
const target = resolve(process.argv[2] || process.cwd());
const outDir = process.env.T3MP3ST_CI_HUNT_DIR || join(target, 'reports');
const outFile = join(outDir, 'ci-hunt.json');
const prevFile = join(outDir, 'ci-hunt.prev.json');

const dist = join(repoRoot, 'dist', 'recon', 'whitebox.js');
if (!existsSync(dist)) {
  console.log('ci-hunt: dist/ not built — skip (run npm run build first)');
  process.exit(0);
}

const whitebox = await import(pathToFileURL(dist).href);
const ingested = whitebox.ingestRepoToSourceContext(target);
const report = {
  at: new Date().toISOString(),
  repo: target,
  includedUnits: ingested.includedUnits,
  droppedUnits: ingested.droppedUnits,
  stats: ingested.stats,
  decomposed: false,
  findings: [],
};

if (process.env.T3MP3ST_CI_DECOMPOSE === '1' && (process.env.OPENROUTER_API_KEY || process.env.ANTHROPIC_API_KEY || process.env.OPENAI_API_KEY)) {
  try {
    const analysis = await whitebox.runWhiteboxAnalysis({
      repoPath: target,
      objective: process.env.T3MP3ST_CI_OBJECTIVE || 'Find high-impact, evidence-backed vulnerabilities in this owned repo.',
      maxRounds: 1,
    });
    report.decomposed = true;
    report.findings = (analysis.decomposition?.finalSynthesis?.findings || []).map((f) => ({
      type: f.type,
      title: f.title,
      severity: f.severity || 'info',
    }));
  } catch (err) {
    report.decomposeError = err instanceof Error ? err.message : String(err);
  }
}

await mkdir(outDir, { recursive: true });
if (existsSync(outFile)) {
  await writeFile(prevFile, await readFile(outFile, 'utf8'));
}
await writeFile(outFile, `${JSON.stringify(report, null, 2)}\n`);

let delta = { newTitles: [], goneTitles: [] };
if (existsSync(prevFile)) {
  try {
    const prev = JSON.parse(await readFile(prevFile, 'utf8'));
    const prevTitles = new Set((prev.findings || []).map((f) => f.title));
    const nowTitles = new Set(report.findings.map((f) => f.title));
    delta = {
      newTitles: [...nowTitles].filter((t) => !prevTitles.has(t)),
      goneTitles: [...prevTitles].filter((t) => !nowTitles.has(t)),
    };
  } catch { /* first well-formed run */ }
}

console.log(JSON.stringify({
  ok: true,
  includedUnits: report.includedUnits,
  decomposed: report.decomposed,
  findings: report.findings.length,
  delta,
  outFile,
}, null, 2));
