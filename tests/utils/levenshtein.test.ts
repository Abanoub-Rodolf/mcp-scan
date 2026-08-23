import { describe, it, expect } from 'vitest';
import { levenshteinDistance, normalizedLevenshtein } from '../../src/utils/levenshtein.js';

describe('levenshteinDistance', () => {
  it('returns 0 for identical strings', () => {
    expect(levenshteinDistance('express', 'express')).toBe(0);
  });

  it('counts substitutions, insertions and deletions (kitten -> sitting = 3)', () => {
    expect(levenshteinDistance('kitten', 'sitting')).toBe(3);
  });

  it('handles empty operands', () => {
    expect(levenshteinDistance('', 'abc')).toBe(3);
    expect(levenshteinDistance('abc', '')).toBe(3);
    expect(levenshteinDistance('', '')).toBe(0);
  });

  it('is symmetric', () => {
    expect(levenshteinDistance('filesystem', 'filesytem')).toBe(
      levenshteinDistance('filesytem', 'filesystem')
    );
  });

  it('detects single-character typosquatting distance', () => {
    expect(levenshteinDistance('mcp-filesystem', 'mcp-fileystem')).toBe(1);
  });
});

describe('normalizedLevenshtein', () => {
  it('returns 0 for identical strings', () => {
    expect(normalizedLevenshtein('same', 'same')).toBe(0);
  });

  it('returns 1 for completely different equal-length strings', () => {
    expect(normalizedLevenshtein('abc', 'xyz')).toBe(1);
  });

  it('never exceeds 1 regardless of length difference', () => {
    const n = normalizedLevenshtein('a', 'aaaaaaaaaa');
    expect(n).toBeLessThanOrEqual(1);
    expect(n).toBeGreaterThan(0);
  });

  it('returns 0 when both strings are empty', () => {
    expect(normalizedLevenshtein('', '')).toBe(0);
  });
});
