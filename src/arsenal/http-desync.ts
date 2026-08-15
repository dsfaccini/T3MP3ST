/**
 * Raw HTTP/1.1 desync probe — TE/CL permutations over a socket.
 * Knowledge is often already in the model; this supplies mechanical throughput.
 */

import * as net from 'net';
import type { ToolContext, ToolResult } from '../types/index.js';

interface ProbeResult {
  name: string;
  status: string;
  bytes: number;
  ms: number;
  error?: string;
}

function sendRaw(host: string, port: number, payload: string, timeoutMs: number): Promise<ProbeResult & { name: string }> {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = new net.Socket();
    let buf = '';
    const done = (partial: Omit<ProbeResult, 'name' | 'ms'> & { name?: string }) => {
      socket.destroy();
      resolve({
        name: partial.name || 'probe',
        status: partial.status,
        bytes: partial.bytes,
        ms: Date.now() - started,
        error: partial.error,
      });
    };
    socket.setTimeout(timeoutMs);
    socket.on('data', (chunk) => { buf += chunk.toString('latin1'); });
    socket.on('timeout', () => done({ status: 'timeout', bytes: buf.length, error: 'timeout' }));
    socket.on('error', (err) => done({ status: 'error', bytes: buf.length, error: err.message }));
    socket.on('close', () => {
      const status = buf.match(/^HTTP\/1\.[01] (\d{3})/)?.[1] || (buf ? 'parse' : 'empty');
      done({ status, bytes: buf.length });
    });
    socket.connect(port, host, () => {
      socket.write(payload);
    });
  });
}

function frames(host: string, path: string): Array<{ name: string; payload: string }> {
  const dest = `${path} HTTP/1.1`;
  return [
    {
      name: 'cl-only',
      payload: `GET ${dest}\r\nHost: ${host}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`,
    },
    {
      name: 'te-cl',
      payload:
        `POST ${dest}\r\nHost: ${host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\nConnection: close\r\n\r\n` +
        `0\r\n\r\n`,
    },
    {
      name: 'te-te',
      payload:
        `POST ${dest}\r\nHost: ${host}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\nConnection: close\r\n\r\n` +
        `0\r\n\r\n`,
    },
  ];
}

export async function httpDesyncHandler(context: ToolContext): Promise<ToolResult> {
  const target = String(context.parameters.target || context.target?.address || '');
  if (!target) return { success: false, error: 'target required' };
  let host = target;
  let port = Number(context.parameters.port) || 80;
  try {
    if (/^[a-z]+:\/\//i.test(target)) {
      const u = new URL(target);
      host = u.hostname;
      port = Number(context.parameters.port) || (u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80));
    }
  } catch {
    return { success: false, error: `unparseable target: ${target}` };
  }
  if (port === 443) {
    return { success: false, error: 'http_desync_probe is HTTP/1.1 cleartext only — point it at an http:// hop or a proxy port, not TLS 443' };
  }
  const path = String(context.parameters.path || '/');
  const timeoutMs = Number(context.parameters.timeoutMs) || 2500;
  const results: ProbeResult[] = [];
  for (const frame of frames(host, path)) {
    const r = await sendRaw(host, port, frame.payload, timeoutMs);
    results.push({ ...r, name: frame.name });
  }
  const statuses = new Set(results.map((r) => r.status));
  const lengths = new Set(results.map((r) => r.bytes));
  const differential = statuses.size > 1 || lengths.size > 1;
  const lines = results.map((r) => `${r.name}: status=${r.status} bytes=${r.bytes} ${r.ms}ms${r.error ? ` err=${r.error}` : ''}`);
  return {
    success: true,
    output: [
      `HTTP desync probe ${host}:${port}${path}`,
      ...lines,
      differential
        ? 'DIFFERENTIAL: parsers disagreed — smuggle candidates exist (confirm with a canary, do not claim RCE from this alone).'
        : 'No status/length differential across TE/CL frames.',
    ].join('\n'),
    findings: differential
      ? [{
          title: 'HTTP request smuggling differential',
          severity: 'medium',
          details: `TE/CL permutations against ${host}:${port} produced unequal status or body lengths: ${lines.join('; ')}`,
        }]
      : undefined,
  };
}
