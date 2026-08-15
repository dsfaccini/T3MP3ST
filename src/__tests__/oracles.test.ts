import { describe, it, expect } from 'vitest';
import { classifyFinding, evaluateOracle } from '../evidence/oracles.js';
import { gateLiveFinding } from '../evidence/gate.js';
import { KillChainPhase } from '../types/index.js';
import type { Finding } from '../types/index.js';

function finding(over: Partial<Finding>): Finding {
  return {
    id: 'f1',
    title: 'x',
    description: 'x',
    severity: 'high',
    targetId: 't',
    operatorId: 'o',
    phase: KillChainPhase.EXPLOIT,
    evidence: [],
    discoveredAt: 1,
    ...over,
  };
}

describe('class oracles', () => {
  it('classifies known vuln families', () => {
    expect(classifyFinding('Reflected XSS in q', '')).toBe('xss');
    expect(classifyFinding('SQL injection in /id', '')).toBe('sqli');
    expect(classifyFinding('SSRF via webhook', '')).toBe('ssrf');
    expect(classifyFinding('RCE through upload', '')).toBe('rce');
    expect(classifyFinding('LFI in page=', '')).toBe('lfi');
    expect(classifyFinding('open port 22', '')).toBe('generic');
  });

  it('rejects reflected XSS without an execution signal', () => {
    const v = evaluateOracle('Reflected XSS', 'q parameter', 'Hello <script>alert(1)</script>');
    expect(v.applied).toBe(true);
    expect(v.passed).toBe(false);
  });

  it('accepts XSS when the execution oracle is in the evidence', () => {
    const v = evaluateOracle('Stored XSS', '', 'payload executed; alert(1) fired in headless browser');
    expect(v.passed).toBe(true);
  });

  it('blocks verification of an XSS finding that only shows reflection', () => {
    const gate = gateLiveFinding(finding({
      title: 'XSS in search',
      description: 'reflected',
      evidence: [{ type: 'output', content: 'results for <script>alert(1)</script>', timestamp: 1 }],
    }));
    expect(gate.passed).toBe(false);
    expect(gate.reasons.join(' ')).toMatch(/execution/i);
  });

  it('still verifies generic tool-backed findings', () => {
    const gate = gateLiveFinding(finding({
      title: 'nmap found open port',
      description: 'ssh',
      evidence: [{ type: 'output', content: 'PORT 22/tcp open ssh', timestamp: 1 }],
    }));
    expect(gate.passed).toBe(true);
  });
});
