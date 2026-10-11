import { PassThrough, Writable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import {
  TerminalPrompter,
  type TerminalPrompterOptions,
  WizardCancelled,
} from '../../src/guided/prompt.js';

const jwt = `eyJhbGciOiJSUzI1NiJ9.${'eyJzdWIiOiJ1c2VyIn0'.repeat(2)}.c2lnbmF0dXJl`;

function terminal(options: TerminalPrompterOptions = {}) {
  const input = new PassThrough();
  let out = '';
  const output = new Writable({
    write(chunk, _encoding, done) {
      out += String(chunk);
      done();
    },
  });
  const prompter = new TerminalPrompter(input, output, options);
  return { input, prompter, out: () => out };
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 20));

describe('TerminalPrompter', () => {
  it('strips escape sequences and token shapes from everything it prints (SEC-04, SEC-17)', async () => {
    const t = terminal();
    t.prompter.say(`You have access to one org: acme\x1b]0;pwned\x07\x1b[2J ${jwt}.`);
    const answer = t.prompter.ask('Pick \x1b[31mred\x1b[0m');
    t.input.write('yes\n');
    expect(await answer).toBe('yes');
    t.prompter.close();
    expect(t.out()).toContain('You have access to one org: acme [redacted-token].');
    expect(t.out()).toContain('Pick red');
    expect(t.out()).not.toContain('\x1b]0;pwned');
    expect(t.out()).not.toContain('\x1b[2J');
    expect(t.out()).not.toContain('\x1b[31m');
    expect(t.out()).not.toContain(jwt);
  });

  it('rejects a pending question on Ctrl+C, and calls onInterrupt only while idle', async () => {
    let interrupted = 0;
    const busy = terminal({ onInterrupt: () => (interrupted += 1) });
    const pending = busy.prompter.ask('Question');
    busy.input.write('\x03');
    await expect(pending).rejects.toBeInstanceOf(WizardCancelled);
    expect(interrupted).toBe(0);
    busy.prompter.close();

    const idle = terminal({ onInterrupt: () => (interrupted += 1) });
    idle.input.write('\x03');
    await tick();
    expect(interrupted).toBe(1);
    idle.prompter.close();
  });

  it('after a cancel, every further question is refused', async () => {
    const t = terminal();
    t.prompter.close();
    await expect(t.prompter.ask('Again?')).rejects.toBeInstanceOf(WizardCancelled);
  });
});
