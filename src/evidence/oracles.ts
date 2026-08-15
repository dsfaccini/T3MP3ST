/**
 * Class-specific finding oracles.
 *
 * Provenance ("a tool ran") is not the same as proof ("the bug exists").
 * These oracles are the thin in-loop counterpart of XBOW-style validators:
 * they only apply when the finding is clearly of a known class, and they
 * refuse verification when the evidence is only a reflection / probe echo.
 */

export type OracleClass =
  | 'xss'
  | 'sqli'
  | 'ssrf'
  | 'rce'
  | 'lfi'
  | 'generic';

export interface OracleVerdict {
  class: OracleClass;
  /** True when the class is clear enough that the oracle should decide. */
  applied: boolean;
  passed: boolean;
  reason: string;
}

const XSS_HINT = /\bxss\b|cross[- ]site script/i;
const SQLI_HINT = /\bsql[- ]?inject|\bsqli\b|union select|blind sql/i;
const SSRF_HINT = /\bssrf\b|server[- ]side request/i;
const RCE_HINT = /\brce\b|remote code|command inject|arbitrary command/i;
const LFI_HINT = /\blfi\b|local file incl|path traversal|directory traversal/i;

const XSS_EXECUTED = /xss_oracle|javascript executed|payload executed|alert\(\d+\) fired|onerror fired|document\.cookie=/i;
const XSS_REFLECT_ONLY = /<script|%3cscript|&lt;script|alert\s*\(/i;

const SQLI_PROOF = /back-end dbms|sql syntax|mysql|postgresql|sqlite|syntax error at|union select .+from|extracted column|order by \d+/i;
const SSRF_PROOF = /canary|ssrf[-_]?hit|metadata\.google|169\.254\.169\.254|unique[-_]?token/i;
const RCE_PROOF = /\buid=\d+|gid=\d+|whoami\s*[:=]\s*\S+|nt authority|root:x:0:0/;
const LFI_PROOF = /root:x:\d+:\d+:|\[boot loader\]|<\?php|failed to open stream|include\(.+passwd/i;

function blobOf(title: string, details: string, evidenceText: string): string {
  return `${title}\n${details}\n${evidenceText}`;
}

export function classifyFinding(title: string, details: string): OracleClass {
  const text = `${title}\n${details}`;
  if (XSS_HINT.test(text)) return 'xss';
  if (SQLI_HINT.test(text)) return 'sqli';
  if (SSRF_HINT.test(text)) return 'ssrf';
  if (RCE_HINT.test(text)) return 'rce';
  if (LFI_HINT.test(text)) return 'lfi';
  return 'generic';
}

/**
 * Judge a finding against a class oracle. Generic / unclear classes do not apply —
 * the provenance gate remains the only bar. Applied classes fail closed when the
 * evidence is just a reflected probe with no class-specific success signal.
 */
export function evaluateOracle(
  title: string,
  details: string,
  evidenceText: string,
): OracleVerdict {
  const cls = classifyFinding(title, details);
  const evidence = evidenceText || '';
  if (cls === 'generic') {
    return { class: cls, applied: false, passed: true, reason: 'no class-specific oracle' };
  }
  if (!evidence.trim()) {
    return { class: cls, applied: true, passed: false, reason: `${cls} claim has no tool output for the class oracle` };
  }

  switch (cls) {
    case 'xss': {
      if (XSS_EXECUTED.test(blobOf(title, details, evidence))) {
        return { class: cls, applied: true, passed: true, reason: 'xss execution signal in evidence' };
      }
      if (XSS_REFLECT_ONLY.test(evidence)) {
        return { class: cls, applied: true, passed: false, reason: 'xss reflected in output but no execution signal (alert/onerror/oracle)' };
      }
      return { class: cls, applied: true, passed: false, reason: 'xss class without an execution oracle in tool output' };
    }
    case 'sqli': {
      const ok = SQLI_PROOF.test(evidence);
      return {
        class: cls,
        applied: true,
        passed: ok,
        reason: ok ? 'sqli proof in tool output' : 'sqli class without DBMS/error/extraction signal in tool output',
      };
    }
    case 'ssrf': {
      const ok = SSRF_PROOF.test(evidence);
      return {
        class: cls,
        applied: true,
        passed: ok,
        reason: ok ? 'ssrf canary/metadata signal in tool output' : 'ssrf class without canary or metadata hit in tool output',
      };
    }
    case 'rce': {
      const ok = RCE_PROOF.test(evidence);
      return {
        class: cls,
        applied: true,
        passed: ok,
        reason: ok ? 'rce command-output signal in tool output' : 'rce class without uid/whoami/id proof in tool output',
      };
    }
    case 'lfi': {
      const ok = LFI_PROOF.test(evidence);
      return {
        class: cls,
        applied: true,
        passed: ok,
        reason: ok ? 'lfi file-content signal in tool output' : 'lfi class without file-content proof in tool output',
      };
    }
    default:
      return { class: 'generic', applied: false, passed: true, reason: 'no class-specific oracle' };
  }
}
