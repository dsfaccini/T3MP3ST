import { describe, it, expect } from 'vitest';
import { createTasksFromWorkOrders, MissionControl, type SeededWorkOrder } from '../mission/index.js';
import { KillChainPhase } from '../types/index.js';

const order = (over: Partial<SeededWorkOrder> = {}): SeededWorkOrder => ({
  id: 'wo-1',
  title: 'Probe login CSRF boundary',
  target: 'http://127.0.0.1:3333',
  assignedArchetype: 'scanner',
  hypothesis: 'state-changing POST lacks a CSRF token',
  safeProbe: 'GET the form, compare token presence',
  expectedSignal: 'form posts without csrf hidden field',
  falsifier: 'token is bound to session and rejected when missing',
  retest: 'resubmit without token after fix',
  toolHints: ['http_request'],
  priority: 8,
  kind: 'prove',
  ...over,
});

describe('work orders become mission tasks', () => {
  it('renders hypothesis, probe, falsifier, and retest into the task body', () => {
    const tasks = createTasksFromWorkOrders('m1', 'http://127.0.0.1:3333', [order()]);
    expect(tasks).toHaveLength(1);
    expect(tasks[0].name).toBe('Probe login CSRF boundary');
    expect(tasks[0].operatorType).toBe('scanner');
    expect(tasks[0].phase).toBe(KillChainPhase.WEAPONIZE);
    expect(tasks[0].description).toMatch(/Hypothesis:/);
    expect(tasks[0].description).toMatch(/Falsifier:/);
    expect(tasks[0].description).toMatch(/http_request/);
  });

  it('seeds the live queue from work orders instead of canned recon lists', () => {
    const control = new MissionControl();
    const mission = control.createMission({
      name: 'wo-mission',
      objectives: ['probe'],
    });
    control.startMission(mission.id);
    control.seedWorkOrders([order()]);
    control.generateTasksForTarget('http://127.0.0.1:3333');

    const queued = control.getTaskQueue().getForMission(mission.id);
    expect(queued.map((t) => t.name)).toEqual(['Probe login CSRF boundary']);
    expect(queued.some((t) => t.name === 'DNS Enumeration')).toBe(false);
  });
});
