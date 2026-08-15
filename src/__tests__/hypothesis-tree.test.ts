import { describe, it, expect } from 'vitest';
import { HypothesisTree } from '../mission/hypothesis-tree.js';
import { MissionControl } from '../mission/index.js';

describe('HypothesisTree', () => {
  it('takes cheapest open nodes first and prunes a class after 3 fails', () => {
    const tree = new HypothesisTree();
    tree.add({
      id: 'hard', title: 'hard xss', claim: 'c', vulnClass: 'xss', target: 't',
      difficulty: 5, priority: 9, falsifier: 'f', expectedSignal: 's',
    });
    tree.add({
      id: 'easy', title: 'easy xss', claim: 'c', vulnClass: 'xss', target: 't',
      difficulty: 1, priority: 2, falsifier: 'f', expectedSignal: 's',
    });
    const first = tree.takeOpen(1);
    expect(first.map((n) => n.id)).toEqual(['easy']);
    expect(tree.get('easy')?.status).toBe('running');

    tree.recordOutcome('easy', { failed: true });
    tree.recordOutcome('easy', { failed: true });
    tree.recordOutcome('easy', { failed: true });
    expect(tree.get('easy')?.status).toBe('pruned');
    expect(tree.get('hard')?.status).toBe('pruned');
    expect(tree.hasOpen()).toBe(false);
  });

  it('spawns a child on confirm and snapshot names NEXT', () => {
    const tree = new HypothesisTree();
    tree.add({
      id: 'n1', title: 'SQLi in /id', claim: 'union works', vulnClass: 'sqli', target: 't',
      difficulty: 2, priority: 8, falsifier: 'waf', expectedSignal: 'mysql',
    });
    tree.takeOpen(1);
    tree.recordOutcome('n1', {
      confirmed: true,
      evidenceNote: 'back-end DBMS is MySQL',
      child: { title: 'Extract version', claim: '@@version' },
    });
    expect(tree.get('n1')?.status).toBe('confirmed');
    expect(tree.get('n1::child')?.status).toBe('open');
    expect(tree.snapshot()).toMatch(/NEXT: Extract version/);
  });
});

describe('MissionControl tree enqueue', () => {
  it('turns seeded work orders into a bounded batch of hypothesis tasks', () => {
    const control = new MissionControl();
    const mission = control.createMission({ name: 't', objectives: ['o'] });
    control.startMission(mission.id);
    control.seedWorkOrders([
      {
        id: 'a', title: 'A', target: 'http://127.0.0.1', assignedArchetype: 'scanner',
        hypothesis: 'h', safeProbe: 'p', expectedSignal: 'e', falsifier: 'f', retest: 'r',
        toolHints: [], priority: 9, kind: 'prove',
      },
      {
        id: 'b', title: 'B', target: 'http://127.0.0.1', assignedArchetype: 'scanner',
        hypothesis: 'h2', safeProbe: 'p', expectedSignal: 'e', falsifier: 'f', retest: 'r',
        toolHints: [], priority: 3, kind: 'prove',
      },
      {
        id: 'c', title: 'C', target: 'http://127.0.0.1', assignedArchetype: 'scanner',
        hypothesis: 'h3', safeProbe: 'p', expectedSignal: 'e', falsifier: 'f', retest: 'r',
        toolHints: [], priority: 1, kind: 'prove',
      },
    ]);
    control.generateTasksForTarget('http://127.0.0.1');
    const queued = control.getTaskQueue().getForMission(mission.id);
    expect(queued).toHaveLength(2);
    expect(queued.every((t) => t.hypothesisId)).toBe(true);
    expect(control.blackboard()).toMatch(/Hunt tree/);
  });
});
