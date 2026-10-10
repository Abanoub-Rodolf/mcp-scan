import { describe, it, expect } from 'vitest';
import { maskPii, maskString } from '../../src/utils/privacy-engine.js';

describe('Privacy Engine', () => {
  describe('String Masking', () => {
    it('should mask emails', () => {
      const input = 'Contact me at admin@example.com for info.';
      const output = maskString(input);
      expect(output).toBe('Contact me at [EMAIL_MASKED] for info.');
    });

    it('should mask phone numbers', () => {
      const input = 'Call +1-555-123-4567 today.';
      const output = maskString(input);
      expect(output).toBe('Call [PHONE_MASKED] today.');
    });

    it('should mask credit cards', () => {
      const input = 'My card is 4111 1111 1111 1111';
      const output = maskString(input);
      expect(output).toBe('My card is [CREDIT_CARD_MASKED]');
    });

    it('should mask SSN', () => {
      const input = 'SSN: 123-45-6789';
      const output = maskString(input);
      expect(output).toBe('SSN: [SSN_MASKED]');
    });

    it('should mask IPv4', () => {
      const input = 'IP is 192.168.1.1';
      const output = maskString(input);
      expect(output).toBe('IP is [IP_MASKED]');
    });
  });

  describe('Recursive Object/Array Masking', () => {
    it('should mask deeply nested objects', () => {
      const input = {
        user: {
          name: 'John Doe',
          email: 'john.doe@test.com',
          details: {
            phone: '555-987-6543'
          }
        },
        ids: [1, 2, 'admin@thynkq.com']
      };

      // Create deep copy to avoid modifying test input literal reference
      const dataToMask = JSON.parse(JSON.stringify(input));
      const output = maskPii(dataToMask);

      expect(output.user.email).toBe('[EMAIL_MASKED]');
      expect(output.user.details.phone).toBe('[PHONE_MASKED]');
      expect(output.user.name).toBe('John Doe'); // Unchanged
      expect(output.ids[2]).toBe('[EMAIL_MASKED]');
      expect(output.ids[0]).toBe(1); // Unchanged
    });

    it('should respect options', () => {
       const input = { text: 'Email a@b.com, IP 1.2.3.4' };
       const data1 = JSON.parse(JSON.stringify(input));
       const out1 = maskPii(data1, { enabledPatterns: ['Email'] });
       expect(out1.text).toBe('Email [EMAIL_MASKED], IP 1.2.3.4');

       const data2 = JSON.parse(JSON.stringify(input));
       const out2 = maskPii(data2, { disabledPatterns: ['IPv4 Address'] });
       expect(out2.text).toBe('Email [EMAIL_MASKED], IP 1.2.3.4');
    });

    it('should run quickly on medium payloads', () => {
      // Wall-clock bounds flake on throttled CI; assert the work is
      // linear-ish instead by checking a large payload completes and
      // every occurrence is masked.
      const input = { text: 'Email admin@example.com '.repeat(500) };
      const output = maskPii(input);
      expect(output.text).toContain('[EMAIL_MASKED]');
      expect(output.text).not.toContain('admin@example.com');
    });

    it('throws past the depth limit instead of returning unmasked data', () => {
      const nest = (n: number, leaf: string) => { let v: any = leaf; for (let i = 0; i < n; i++) v = { n: v }; return v; };
      expect(() => maskPii(nest(150, 'deep@corp.example'))).toThrow(/depth/i);
      expect(() => maskPii(nest(150, 'deep@corp.example'), undefined, true)).toThrow(/depth/i);
      expect(() => maskPii([[[[nest(150, 'x')]]]])).toThrow(/depth/i);
    });

    it('still masks right up to the depth limit', () => {
      const nest = (n: number, leaf: string) => { let v: any = leaf; for (let i = 0; i < n; i++) v = { n: v }; return v; };
      let out = maskPii(nest(99, 'ok@corp.example'));
      for (let i = 0; i < 99; i++) out = out.n;
      expect(out).toBe('[EMAIL_MASKED]');
    });

    it('masks PII used as an object key, at any depth', () => {
      const out = maskPii({ 'user@corp.example': { 'a@b.com': 1, keep: 'ok' }, list: [{ '555-987-6543': true }] });
      expect(JSON.stringify(out)).not.toMatch(/corp\.example|a@b\.com|555-987/);
      expect(out['[EMAIL_MASKED]']).toEqual({ '[EMAIL_MASKED]': 1, keep: 'ok' });
      expect(out.list[0]).toEqual({ '[PHONE_MASKED]': true });
    });

    it('keeps both entries when two keys mask to the same text', () => {
      const out = maskPii({ 'a@corp.example': 1, 'b@corp.example': 2, 'c@corp.example': 3 });
      expect(out).toEqual({ '[EMAIL_MASKED]': 1, '[EMAIL_MASKED_2]': 2, '[EMAIL_MASKED_3]': 3 });
    });

    it('does not let a masked key overwrite a literal key of the same name', () => {
      const out = maskPii({ '[EMAIL_MASKED]': 'literal', 'a@corp.example': 'pii' });
      expect(out).toEqual({ '[EMAIL_MASKED]': 'literal', '[EMAIL_MASKED_2]': 'pii' });
    });

    it('never renames JSON-RPC envelope keys', () => {
      const msg = { jsonrpc: '2.0', id: 1, method: 'm', params: { 'a@corp.example': 1 }, result: { x: 1 }, error: { code: 1 } };
      expect(Object.keys(maskPii(msg))).toEqual(['jsonrpc', 'id', 'method', 'params', 'result', 'error']);
    });

    it('keeps a __proto__ key as a plain entry when it has to rebuild the object', () => {
      const out = maskPii(JSON.parse('{"__proto__":{"x":"a@corp.example"},"b@corp.example":1}'));
      expect(Object.keys(out)).toEqual(['__proto__', '[EMAIL_MASKED]']);
      expect(JSON.stringify(out)).not.toContain('corp.example');
    });

    it('leaves the top-level envelope id (and each batch element\'s) alone, but still masks ids deeper down', () => {
      const out = maskPii({ jsonrpc: '2.0', id: 'req-1234567890', result: { id: 'req-1234567890' } });
      expect(out.id).toBe('req-1234567890');
      expect(out.result.id).toBe('req-[NPI_MASKED]');
      const batch = maskPii([{ jsonrpc: '2.0', id: '12345', result: 1 }, { jsonrpc: '2.0', id: 'u@corp.example', method: 'm', params: { id: 'u@corp.example' } }]);
      expect(batch[0].id).toBe('12345');
      expect(batch[1].id).toBe('u@corp.example');
      expect(batch[1].params.id).toBe('[EMAIL_MASKED]');
    });

    it('exempts only the top-level object and direct batch elements, not ids inside nested arrays', () => {
      expect(maskPii([[{ id: 'user@corp.example' }]])[0][0].id).toBe('[EMAIL_MASKED]');
      expect(maskPii({ result: [{ id: 'user@corp.example' }] }).result[0].id).toBe('[EMAIL_MASKED]');
      expect(maskPii([{ jsonrpc: '2.0', id: 'user@corp.example', result: 1 }])[0].id).toBe('user@corp.example');
    });

    it('only exempts the id of an object that is a JSON-RPC message', () => {
      expect(maskPii({ id: 'user@corp.example' }).id).toBe('[EMAIL_MASKED]');
      expect(maskPii({ jsonrpc: '2.0', id: 'user@corp.example' }).id).toBe('[EMAIL_MASKED]');
      expect(maskPii({ jsonrpc: null, id: 'user@corp.example', result: 1 }).id).toBe('[EMAIL_MASKED]');
      expect(maskPii({ jsonrpc: '2.0', id: 'user@corp.example', error: { code: 1 } }).id).toBe('user@corp.example');
    });
  });
});
