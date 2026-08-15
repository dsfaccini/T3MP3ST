/**
 * Hypothesis tree — search state that lives outside the LLM transcript.
 *
 * Work orders and live findings become nodes. The tick loop asks `takeOpen`
 * for the next cheapest open claim, records confirm/refute/fail, and prunes
 * a class after three failed variants. This is the TDA/EGATS seed: difficulty
 * plus fail-count, not eight personalities handing off.
 */

export type HypothesisStatus = 'open' | 'running' | 'confirmed' | 'refuted' | 'pruned';

export interface HypothesisNode {
  id: string;
  title: string;
  claim: string;
  vulnClass: string;
  target: string;
  parentId?: string;
  status: HypothesisStatus;
  failCount: number;
  difficulty: number;
  priority: number;
  falsifier: string;
  expectedSignal: string;
  workOrderId?: string;
  taskId?: string;
  evidenceNote?: string;
}

export interface HypothesisOutcome {
  confirmed?: boolean;
  refuted?: boolean;
  failed?: boolean;
  evidenceNote?: string;
  child?: {
    title: string;
    claim: string;
    vulnClass?: string;
  };
}

const PRUNE_AFTER = 3;

export class HypothesisTree {
  private readonly nodes = new Map<string, HypothesisNode>();

  add(partial: Omit<HypothesisNode, 'status' | 'failCount'> & { status?: HypothesisStatus; failCount?: number }): HypothesisNode {
    const node: HypothesisNode = {
      ...partial,
      status: partial.status ?? 'open',
      failCount: partial.failCount ?? 0,
      difficulty: clamp(partial.difficulty || 3, 1, 5),
      priority: clamp(partial.priority || 5, 1, 10),
    };
    this.nodes.set(node.id, node);
    return node;
  }

  get(id: string): HypothesisNode | undefined {
    return this.nodes.get(id);
  }

  all(): HypothesisNode[] {
    return [...this.nodes.values()];
  }

  size(): number {
    return this.nodes.size;
  }

  hasOpen(): boolean {
    return this.all().some((n) => n.status === 'open');
  }

  /**
   * Pick up to `limit` open nodes, cheapest difficulty first, then highest priority.
   * Marks them running and optionally binds a task id.
   */
  takeOpen(
    limit: number,
    bindTask?: (node: HypothesisNode) => string,
    match?: (node: HypothesisNode) => boolean,
  ): HypothesisNode[] {
    const open = this.all()
      .filter((n) => n.status === 'open' && (!match || match(n)))
      .sort((a, b) => a.difficulty - b.difficulty || b.priority - a.priority);
    const taken = open.slice(0, Math.max(0, limit));
    for (const node of taken) {
      node.status = 'running';
      if (bindTask) node.taskId = bindTask(node);
    }
    return taken;
  }

  recordOutcome(id: string, outcome: HypothesisOutcome): HypothesisNode | undefined {
    const node = this.nodes.get(id);
    if (!node) return undefined;
    if (outcome.evidenceNote) node.evidenceNote = outcome.evidenceNote;

    if (outcome.refuted) {
      node.status = 'refuted';
      return node;
    }
    if (outcome.confirmed) {
      node.status = 'confirmed';
      if (outcome.child) {
        this.add({
          id: `${node.id}::child`,
          title: outcome.child.title,
          claim: outcome.child.claim,
          vulnClass: outcome.child.vulnClass || node.vulnClass,
          target: node.target,
          parentId: node.id,
          difficulty: Math.min(5, node.difficulty + 1),
          priority: Math.min(10, node.priority + 1),
          falsifier: node.falsifier,
          expectedSignal: node.expectedSignal,
        });
      }
      return node;
    }
    if (outcome.failed) {
      node.failCount += 1;
      if (node.failCount >= PRUNE_AFTER) {
        node.status = 'pruned';
        this.pruneSiblingsOfClass(node);
      } else {
        node.status = 'open';
        node.taskId = undefined;
      }
    }
    return node;
  }

  private pruneSiblingsOfClass(node: HypothesisNode): void {
    for (const other of this.all()) {
      if (other.id === node.id) continue;
      if (other.vulnClass === node.vulnClass && other.status === 'open') {
        other.status = 'pruned';
      }
    }
  }

  /** Compact blackboard for the operator prompt — not the raw transcript. */
  snapshot(): string {
    if (this.nodes.size === 0) return '';
    const lines = ['### Hunt tree (external state — not your memory)'];
    for (const node of this.all()) {
      const parent = node.parentId ? ` parent=${node.parentId}` : '';
      lines.push(
        `- [${node.status}] d${node.difficulty} p${node.priority} fails=${node.failCount} ${node.vulnClass}: ${node.title}${parent}`,
      );
      if (node.evidenceNote) lines.push(`    evidence: ${node.evidenceNote}`);
    }
    const next = this.all().filter((n) => n.status === 'open').sort((a, b) => a.difficulty - b.difficulty)[0];
    if (next) {
      lines.push(`NEXT: ${next.title} — probe until "${next.expectedSignal}"; abandon if "${next.falsifier}".`);
    }
    return lines.join('\n');
  }

  toJSON(): HypothesisNode[] {
    return this.all().map((n) => ({ ...n }));
  }
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}
