/**
 * Scoped lab executor — argv only, allowlisted binaries, no shell.
 * For PoC parameterization (the "right module, wrong flags" failure), not a general bash.
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import { resolve } from 'path';
import type { ToolContext, ToolResult } from '../types/index.js';
import { looksLikeHostileAct } from '../opsec/untrusted-output.js';

function hostOf(value: string): string {
  let s = value.trim();
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = new URL(s).hostname;
  } catch { /* bare host */ }
  s = s.replace(/^[^@/]*@/, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
  return s.toLowerCase();
}

const execFileAsync = promisify(execFile);

const ALLOWED = new Set(['python3', 'python', 'curl', 'openssl']);

function asStringList(value: unknown): string[] {
  if (Array.isArray(value)) return value.map((v) => String(v));
  if (typeof value === 'string') return value.split(/\s+/).filter(Boolean);
  return [];
}

export async function labExecHandler(context: ToolContext): Promise<ToolResult> {
  const argv = asStringList(context.parameters.argv);
  if (argv.length === 0) return { success: false, error: 'argv required (array, no shell)' };
  const bin = argv[0];
  if (!ALLOWED.has(bin)) {
    return { success: false, error: `lab_exec allows only: ${[...ALLOWED].join(', ')} — got ${bin}` };
  }
  const blob = argv.join(' ');
  if (looksLikeHostileAct(blob)) {
    return { success: false, error: 'ACT DENIED: argv looks like decode-and-exec or instruction-override' };
  }
  const scopedHost = hostOf(String(context.parameters.target || context.target?.address || ''));
  for (const arg of argv.slice(1)) {
    const h = hostOf(arg);
    if (h && scopedHost && h !== scopedHost && !h.endsWith(`.${scopedHost}`)) {
      return { success: false, error: `SCOPE DENIED: argv host '${h}' is not the scoped target '${scopedHost}'` };
    }
  }
  const cwd = typeof context.parameters.cwd === 'string' ? resolve(context.parameters.cwd) : process.cwd();
  const timeout = Math.min(Number(context.parameters.timeoutMs) || 15000, 30000);
  try {
    const { stdout, stderr } = await execFileAsync(bin, argv.slice(1), {
      cwd,
      timeout,
      maxBuffer: 256 * 1024,
      env: { ...process.env, PATH: process.env.PATH },
    });
    return {
      success: true,
      output: [stdout, stderr].filter(Boolean).join('\n').slice(0, 8000) || '(no output)',
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { success: false, error: `lab_exec failed: ${message}`.slice(0, 2000) };
  }
}
