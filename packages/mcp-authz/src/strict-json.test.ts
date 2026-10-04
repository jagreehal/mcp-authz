import { describe, expect, it } from 'vitest';
import { holdsInexactNumber, parseChecked, parseVerbatim } from './strict-json';

describe('numbers, read without rounding', () => {
  it('keeps a number checkable when its text means exactly the double it parses to', () => {
    for (const text of [
      '1',
      '1.0',
      '0.1',
      '-2.50',
      '1e3',
      '1E+3',
      '1000e-3',
      '9007199254740991',
      '0',
      '-0',
    ]) {
      expect(holdsInexactNumber(parseChecked(`{"n":${text}}`)), text).toBe(false);
    }
  });

  it('marks one that would only check as its rounded neighbour, whatever the notation', () => {
    for (const text of [
      '9007199254740993',
      '9007199254740993e0',
      '90071992547409930e-1',
      '1.0000000000000001',
    ]) {
      expect(holdsInexactNumber(parseChecked(`{"n":${text}}`)), text).toBe(true);
    }
  });

  it('writes every number back as the text it arrived as', () => {
    const text = '{"a":1.0,"b":1.0000000000000001,"c":9007199254740993e0,"d":[0.1,-0,1E+3]}';
    expect(JSON.stringify(parseVerbatim(text))).toBe(text);
  });
});
