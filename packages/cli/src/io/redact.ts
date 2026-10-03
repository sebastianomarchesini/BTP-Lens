/**
 * The last line of defence for everything the CLI prints. Strings that reach
 * the terminal come from the CF API (app, org and space names, error titles)
 * and from error paths that could, through a bug, carry a token. Every write
 * to stdout and stderr passes through `sanitizeOutput`.
 */

/* eslint-disable no-control-regex -- matching control characters is the point */
/** ESC-based sequences: CSI (colours, cursor moves) and OSC (title, clipboard, hyperlinks). */
const ANSI_SEQUENCES = /\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[[(][0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]/g;
/** C0 controls except tab, newline and carriage return; DEL; C1 controls. */
const CONTROL_CHARACTERS = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]/g;
/* eslint-enable no-control-regex */

/** Three base64url segments starting with the JSON header `{"` — a JWT. */
const JWT = /eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]*/g;
/** `bearer <token>` however it got there. */
const BEARER = /\b(bearer)\s+[\w.~+/=-]{8,}/gi;
/** Form fields and JSON members of the OAuth token exchange. */
const OAUTH_FIELDS =
  /\b(refresh_token|access_token|client_secret|password|passcode)(["']?\s*[:=]\s*["']?)[^\s"'&,}]+/gi;

export function stripControlCharacters(text: string): string {
  return text.replace(ANSI_SEQUENCES, '').replace(CONTROL_CHARACTERS, '');
}

export function redactSecrets(text: string): string {
  return text
    .replace(JWT, '[redacted-token]')
    .replace(BEARER, '$1 [redacted]')
    .replace(OAUTH_FIELDS, '$1$2[redacted]');
}

/** Removes terminal escape sequences and anything shaped like a credential. */
export function sanitizeOutput(text: string): string {
  return redactSecrets(stripControlCharacters(text));
}
