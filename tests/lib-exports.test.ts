import { describe, it, expect } from 'vitest';
import * as lib from '../src/lib.js';

describe('library exports', () => {
  it('exports PolicyError so runScan callers can catch it by type', () => {
    expect(typeof (lib as any).PolicyError).toBe('function');
  });
});
