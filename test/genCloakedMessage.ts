import { describe, it, expect } from 'vitest';
import { genCloakedMessage } from '../src/client/genCloakedMessage';

describe('generateKeyMessage', () => {
  it('produces the canonical signing prompt for known inputs', () => {
    const pin = '1234';
    const address = '0x1234567890abcdef1234567890abcdef12345678';

    const { message } = genCloakedMessage({ pin, address });

    const expected =
      `Sign this message to generate your Cloaked private payment keys.\n\n` +
      `WARNING: Only sign this message within a trusted website or platform to avoid loss of funds.\n\n` +
      `Secret: 8dc1f9b3177a6b7fc50f43fb345516805077baab8934e52f497cf8b77e949696`;

    expect(message).toBe(expected);
  });

  it('changes the embedded secret when address or pin changes', () => {
    const addressA = '0x1234567890abcdef1234567890abcdef12345678';
    const addressB = '0xabcdef1234567890abcdef1234567890abcdef12';
    const pinA = '1234';
    const pinB = '9999';

    const { message: base } = genCloakedMessage({
      pin: pinA,
      address: addressA,
    });
    const { message: differentPin } = genCloakedMessage({
      pin: pinB,
      address: addressA,
    });
    const { message: differentAddress } = genCloakedMessage({
      pin: pinA,
      address: addressB,
    });

    const secretFrom = (msg: string) => msg.split('Secret: ')[1];

    expect(secretFrom(base)).toBeDefined();
    expect(secretFrom(differentPin)).toBeDefined();
    expect(secretFrom(differentAddress)).toBeDefined();

    expect(secretFrom(base)).not.toEqual(secretFrom(differentPin));
    expect(secretFrom(base)).not.toEqual(secretFrom(differentAddress));

    const prefix =
      'Sign this message to generate your Cloaked private payment keys.\n\n' +
      'WARNING: Only sign this message within a trusted website or platform to avoid loss of funds.\n\n' +
      'Secret: ';

    expect(base.startsWith(prefix)).toBe(true);
    expect(differentPin.startsWith(prefix)).toBe(true);
    expect(differentAddress.startsWith(prefix)).toBe(true);
  });

  describe('validation', () => {
    it('should throw an error for an invalid address', () => {
      const pin = '1234';
      const invalidAddress = '0xinvalid';

      expect(() => genCloakedMessage({ pin, address: invalidAddress })).toThrow(
        'Address is not valid.'
      );
    });

    it('should throw an error for an address without 0x prefix', () => {
      const pin = '1234';
      const invalidAddress = '1234567890abcdef1234567890abcdef12345678';

      expect(() => genCloakedMessage({ pin, address: invalidAddress })).toThrow(
        'Address is not valid.'
      );
    });

    it('should throw an error for a PIN that is too short', () => {
      const pin = '123';
      const address = '0x1234567890abcdef1234567890abcdef12345678';

      expect(() => genCloakedMessage({ pin, address })).toThrow(
        'PIN must be exactly 4 digits.'
      );
    });

    it('should throw an error for a PIN that is too long', () => {
      const pin = '12345';
      const address = '0x1234567890abcdef1234567890abcdef12345678';

      expect(() => genCloakedMessage({ pin, address })).toThrow(
        'PIN must be exactly 4 digits.'
      );
    });

    it('should throw an error for a PIN with non-numeric characters', () => {
      const pin = '12ab';
      const address = '0x1234567890abcdef1234567890abcdef12345678';

      expect(() => genCloakedMessage({ pin, address })).toThrow(
        'PIN must be exactly 4 digits.'
      );
    });

    it('should throw an error for an empty PIN', () => {
      const pin = '';
      const address = '0x1234567890abcdef1234567890abcdef12345678';

      expect(() => genCloakedMessage({ pin, address })).toThrow(
        'PIN must be exactly 4 digits.'
      );
    });

    it('should throw an error for a PIN with spaces', () => {
      const pin = '12 34';
      const address = '0x1234567890abcdef1234567890abcdef12345678';

      expect(() => genCloakedMessage({ pin, address })).toThrow(
        'PIN must be exactly 4 digits.'
      );
    });
  });
});
