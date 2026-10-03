import { createInterface, type Interface } from 'node:readline';
import { Writable } from 'node:stream';

/** Thrown when the user presses Ctrl+C or closes the input. Exit code 0, nothing written. */
export class WizardCancelled extends Error {
  override readonly name = 'WizardCancelled';
  constructor() {
    super('Cancelled. Nothing was written.');
  }
}

export interface AskOptions {
  /** Returned when the user just presses Enter. */
  default?: string;
  /** Do not echo what is typed (passcodes, passwords). */
  hidden?: boolean;
}

/** The questions guided mode asks. Tests script the answers; the CLI uses the terminal. */
export interface Prompter {
  say(text: string): void;
  ask(question: string, options?: AskOptions): Promise<string>;
  /** Shows numbered choices and returns the chosen index. */
  choose(question: string, choices: readonly string[], defaultIndex?: number): Promise<number>;
  confirm(question: string, defaultYes?: boolean): Promise<boolean>;
  close(): void;
}

const MAX_ATTEMPTS = 3;

/** Shared choose/confirm logic on top of ask(). */
export abstract class BasePrompter implements Prompter {
  abstract say(text: string): void;
  abstract ask(question: string, options?: AskOptions): Promise<string>;
  abstract close(): void;

  async choose(
    question: string,
    choices: readonly string[],
    defaultIndex: number | undefined = 0,
  ): Promise<number> {
    this.say(question);
    choices.forEach((choice, i) => this.say(`  ${i + 1}) ${choice}`));
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
      const answer = await this.ask(
        `Enter a number (1-${choices.length})`,
        defaultIndex === undefined ? {} : { default: String(defaultIndex + 1) },
      );
      const n = Number(answer.trim());
      if (Number.isInteger(n) && n >= 1 && n <= choices.length) return n - 1;
      this.say(`Please type a number between 1 and ${choices.length}.`);
    }
    throw new WizardCancelled();
  }

  async confirm(question: string, defaultYes = true): Promise<boolean> {
    const answer = await this.ask(`${question} ${defaultYes ? '[Y/n]' : '[y/N]'}`, {
      default: defaultYes ? 'y' : 'n',
    });
    return /^y(es)?$/i.test(answer.trim());
  }
}

/** Forwards to the real stream unless muted (hidden input). */
class MutableOutput extends Writable {
  muted = false;
  constructor(private readonly target: NodeJS.WritableStream) {
    super();
  }
  override _write(chunk: Buffer | string, _encoding: BufferEncoding, done: () => void): void {
    if (!this.muted) this.target.write(chunk);
    done();
  }
}

/** Interactive prompts on a TTY. */
export class TerminalPrompter extends BasePrompter {
  private readonly output: MutableOutput;
  private readonly rl: Interface;
  private closed = false;
  private pendingReject: ((error: Error) => void) | undefined;

  constructor(
    input: NodeJS.ReadableStream = process.stdin,
    private readonly out: NodeJS.WritableStream = process.stdout,
  ) {
    super();
    this.output = new MutableOutput(out);
    this.rl = createInterface({ input, output: this.output, terminal: true });
    const cancel = () => {
      this.closed = true;
      this.pendingReject?.(new WizardCancelled());
    };
    this.rl.on('SIGINT', cancel);
    this.rl.on('close', cancel);
  }

  say(text: string): void {
    this.out.write(`${text}\n`);
  }

  ask(question: string, options: AskOptions = {}): Promise<string> {
    if (this.closed) return Promise.reject(new WizardCancelled());
    const suffix = options.default && !options.hidden ? ` [${options.default}]` : '';
    return new Promise<string>((resolve, reject) => {
      this.pendingReject = reject;
      if (options.hidden) {
        this.out.write(`${question}: `);
        this.output.muted = true;
      }
      this.rl.question(options.hidden ? '' : `${question}${suffix}: `, (answer) => {
        this.pendingReject = undefined;
        if (options.hidden) {
          this.output.muted = false;
          this.out.write('\n');
        }
        const trimmed = answer.trim();
        resolve(trimmed === '' && options.default !== undefined ? options.default : trimmed);
      });
    });
  }

  close(): void {
    this.closed = true;
    this.rl.close();
  }
}

/** Test double: canned answers, recorded output. */
export class ScriptedPrompter extends BasePrompter {
  readonly transcript: string[] = [];
  constructor(private readonly answers: string[]) {
    super();
  }
  say(text: string): void {
    this.transcript.push(text);
  }
  ask(question: string, options: AskOptions = {}): Promise<string> {
    this.transcript.push(`? ${question}`);
    const answer = this.answers.shift();
    if (answer === undefined) return Promise.reject(new WizardCancelled());
    return Promise.resolve(
      answer === '' && options.default !== undefined ? options.default : answer,
    );
  }
  close(): void {}
}
