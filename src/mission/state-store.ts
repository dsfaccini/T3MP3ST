/**
 * Hunt state store — tree + findings live on disk when a path is configured,
 * otherwise in memory. Operators read a compact snapshot, not the transcript.
 */

import { mkdir, readFile, writeFile } from 'fs/promises';
import { dirname } from 'path';
import { HypothesisTree, type HypothesisNode } from './hypothesis-tree.js';

export interface PersistedHuntState {
  updatedAt: number;
  nodes: HypothesisNode[];
  findingTitles: string[];
}

export class HuntStateStore {
  private findingTitles: string[] = [];

  constructor(private readonly filePath?: string) {}

  rememberFinding(title: string): void {
    if (title && !this.findingTitles.includes(title)) this.findingTitles.push(title);
  }

  async save(tree: HypothesisTree): Promise<void> {
    if (!this.filePath) return;
    const payload: PersistedHuntState = {
      updatedAt: Date.now(),
      nodes: tree.toJSON(),
      findingTitles: this.findingTitles.slice(),
    };
    await mkdir(dirname(this.filePath), { recursive: true });
    await writeFile(this.filePath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  }

  async loadInto(tree: HypothesisTree): Promise<boolean> {
    if (!this.filePath) return false;
    try {
      const raw = JSON.parse(await readFile(this.filePath, 'utf8')) as PersistedHuntState;
      if (!Array.isArray(raw.nodes)) return false;
      for (const node of raw.nodes) {
        if (!tree.get(node.id)) tree.add(node);
      }
      if (Array.isArray(raw.findingTitles)) this.findingTitles = raw.findingTitles.slice();
      return true;
    } catch {
      return false;
    }
  }

  blackboard(tree: HypothesisTree): string {
    const parts = [tree.snapshot()];
    if (this.findingTitles.length) {
      parts.push(`### Recorded findings\n${this.findingTitles.map((t) => `- ${t}`).join('\n')}`);
    }
    return parts.filter(Boolean).join('\n\n');
  }
}
