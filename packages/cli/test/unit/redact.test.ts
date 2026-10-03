import { describe, expect, it } from 'vitest';
import { redactSecrets, sanitizeOutput, stripControlCharacters } from '../../src/io/redact.js';

const jwt = `eyJhbGciOiJSUzI1NiJ9.${'eyJzdWIiOiJ1c2VyIn0'.repeat(2)}.c2lnbmF0dXJl`;

describe('stripControlCharacters', () => {
  it('removes colour, cursor and OSC sequences from app names', () => {
    expect(stripControlCharacters('app\x1b[31m-red\x1b[0m')).toBe('app-red');
    expect(stripControlCharacters('\x1b[2J\x1b[Hclear')).toBe('clear');
    expect(stripControlCharacters('title\x1b]0;pwned\x07 done')).toBe('title done');
    expect(stripControlCharacters('link\x1b]8;;https://evil.example\x1b\\x\x1b]8;;\x1b\\')).toBe(
      'linkx',
    );
  });

  it('removes other control characters but keeps newlines and tabs', () => {
    expect(stripControlCharacters('a\x00b\x07c\x7fd\x9be\n\tf\r')).toBe('abcde\n\tf\r');
  });

  it('leaves ordinary text and unicode alone', () => {
    expect(stripControlCharacters('acme-prod · Frankfurt · ✓')).toBe('acme-prod · Frankfurt · ✓');
  });
});

describe('redactSecrets', () => {
  it('redacts JWTs and bearer tokens wherever they appear', () => {
    expect(redactSecrets(`token ${jwt} rejected`)).toBe('token [redacted-token] rejected');
    expect(redactSecrets('Authorization: bearer abcdefghijklmnop')).toBe(
      'Authorization: bearer [redacted]',
    );
    expect(redactSecrets('Bearer secret.value-here')).toBe('Bearer [redacted]');
  });

  it('redacts OAuth form and JSON fields', () => {
    expect(redactSecrets('grant_type=refresh_token&refresh_token=abc123&x=1')).toBe(
      'grant_type=refresh_token&refresh_token=[redacted]&x=1',
    );
    expect(redactSecrets('{"access_token":"abc","client_secret": "s3cret"}')).toBe(
      '{"access_token":"[redacted]","client_secret": "[redacted]"}',
    );
    expect(redactSecrets('password=hunter2 passcode: 4Z9K1')).toBe(
      'password=[redacted] passcode: [redacted]',
    );
  });

  it('does not touch versions, dates or the word bearer alone', () => {
    const text = 'nodejs 22.12.0 · 2026-09-30T00:00:00Z · bearer';
    expect(redactSecrets(text)).toBe(text);
  });
});

describe('sanitizeOutput', () => {
  it('applies both passes', () => {
    expect(sanitizeOutput(`\x1b[1mCF API 401\x1b[0m bearer ${jwt}`)).toBe(
      'CF API 401 bearer [redacted-token]',
    );
  });
});
