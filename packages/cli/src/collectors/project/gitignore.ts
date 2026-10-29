/*
 * A small .gitignore matcher, enough to tell whether a deployment archive
 * is ignored: comments, blank lines, `!` negation, leading `/` anchoring,
 * trailing `/` for directories, `*`, `?`, `**`, character classes, and
 * patterns without a `/` matching at any depth. The last matching pattern
 * wins, a deeper .gitignore wins over a parent one, and a file inside an
 * ignored directory cannot be re-included. `.git/info/exclude` and global
 * excludes are not read (docs/data-sources.md). Patterns are matched with a
 * table-driven algorithm, not a regex, so a hostile pattern cannot make the
 * matcher backtrack exponentially.
 */

export type GlobToken =
  | { kind: 'char'; char: string }
  | { kind: 'any' }
  | { kind: 'star' }
  | { kind: 'globstar' }
  | { kind: 'class'; chars: string; negated: boolean };

export interface GitignoreRule {
  negated: boolean;
  /** Trailing `/`: matches directories only. */
  dirOnly: boolean;
  /** Leading or inner `/`: matches from the .gitignore directory only. */
  anchored: boolean;
  tokens: GlobToken[];
}

export interface GitignoreLayer {
  /** Directory of the .gitignore, `/`-separated and relative to the root; `''` for the root. */
  base: string;
  rules: GitignoreRule[];
}

/** Longer patterns are ignored: git has no such limit, but nothing real comes close. */
const MAX_PATTERN_LENGTH = 1024;
const MAX_RULES = 2000;

export function tokenizeGlob(glob: string): GlobToken[] {
  const tokens: GlobToken[] = [];
  let i = 0;
  while (i < glob.length) {
    const c = glob[i] ?? '';
    if (c === '*') {
      if (glob[i + 1] === '*') {
        // `**` matches across directories; collapse any run of stars into one.
        while (glob[i] === '*') i += 1;
        tokens.push({ kind: 'globstar' });
      } else {
        tokens.push({ kind: 'star' });
        i += 1;
      }
    } else if (c === '?') {
      tokens.push({ kind: 'any' });
      i += 1;
    } else if (c === '[') {
      const close = glob.indexOf(']', i + 2);
      if (close === -1) {
        tokens.push({ kind: 'char', char: '[' });
        i += 1;
      } else {
        const body = glob.slice(i + 1, close);
        const negated = body.startsWith('!');
        tokens.push({ kind: 'class', chars: negated ? body.slice(1) : body, negated });
        i = close + 1;
      }
    } else if (c === '\\' && i + 1 < glob.length) {
      tokens.push({ kind: 'char', char: glob[i + 1] ?? '' });
      i += 2;
    } else {
      tokens.push({ kind: 'char', char: c });
      i += 1;
    }
  }
  return collapseGlobstars(tokens);
}

/**
 * `**` followed by `/` matches any run of directories, so `a/**` + `/**` + `/x`
 * means the same as `a/**` + `/x`: repeated `**` + `/` pairs are dropped. The
 * matcher's cost is tokens × path length, and a hostile pattern of hundreds of
 * `**` + `/` pairs would otherwise pay for every one of them.
 */
function collapseGlobstars(tokens: GlobToken[]): GlobToken[] {
  const out: GlobToken[] = [];
  const isSlash = (token: GlobToken | undefined): boolean =>
    token?.kind === 'char' && token.char === '/';
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (token === undefined) continue;
    const pair = token.kind === 'globstar' && isSlash(tokens[i + 1]);
    const repeated = pair && out.at(-2)?.kind === 'globstar' && isSlash(out.at(-1));
    if (repeated) {
      i += 1;
      continue;
    }
    out.push(token);
  }
  return out;
}

function classMatches(token: Extract<GlobToken, { kind: 'class' }>, c: string): boolean {
  let hit = false;
  const { chars } = token;
  for (let i = 0; i < chars.length; i += 1) {
    const from = chars[i] ?? '';
    if (chars[i + 1] === '-' && i + 2 < chars.length) {
      const to = chars[i + 2] ?? '';
      if (c >= from && c <= to) hit = true;
      i += 2;
    } else if (c === from) hit = true;
  }
  return hit !== token.negated;
}

function tokenMatches(token: GlobToken, c: string): boolean {
  switch (token.kind) {
    case 'char':
      return c === token.char;
    case 'any':
      return c !== '/';
    case 'class':
      return c !== '/' && classMatches(token, c);
    case 'star':
    case 'globstar':
      return false;
  }
}

/**
 * Whether the tokens match the whole path, or, with `anySegment`, the path
 * from any directory boundary on (what an unanchored pattern means). Dynamic
 * programming over (token, position): each cell is computed once, so the
 * cost is the product of the two lengths whatever the pattern, and an
 * unanchored pattern costs one pass, not one per segment: every segment
 * start re-seeds the first token instead of restarting the match.
 */
export function globMatches(tokens: GlobToken[], path: string, anySegment = false): boolean {
  // reachable[j] = the first j tokens can consume the path up to the current position.
  let reachable: boolean[] = new Array<boolean>(tokens.length + 1).fill(false);
  let next: boolean[] = new Array<boolean>(tokens.length + 1).fill(false);
  const closeStars = (row: boolean[], position: number): void => {
    for (let j = 0; j < tokens.length; j += 1) {
      const token = tokens[j];
      if (!row[j] || token === undefined) continue;
      // A `**/` run may also match nothing, including its slash.
      if (token.kind === 'globstar') {
        row[j + 1] = true;
        if (tokens[j + 1]?.kind === 'char' && (tokens[j + 1] as { char: string }).char === '/') {
          row[j + 2] = row[j + 2] || position === 0 || path[position - 1] === '/';
        }
      } else if (token.kind === 'star') row[j + 1] = true;
    }
  };
  reachable[0] = true;
  closeStars(reachable, 0);
  for (let position = 0; position < path.length; position += 1) {
    if (anySegment && position > 0 && path[position - 1] === '/' && !reachable[0]) {
      reachable[0] = true;
      closeStars(reachable, position);
    }
    const c = path[position] ?? '';
    next.fill(false);
    for (let j = 0; j < tokens.length; j += 1) {
      const token = tokens[j];
      if (!reachable[j] || token === undefined) continue;
      if (token.kind === 'globstar') next[j] = true;
      else if (token.kind === 'star') {
        if (c !== '/') next[j] = true;
      } else if (tokenMatches(token, c)) next[j + 1] = true;
    }
    closeStars(next, position + 1);
    [reachable, next] = [next, reachable];
  }
  return reachable[tokens.length] === true;
}

export function parseGitignoreLine(line: string): GitignoreRule | null {
  let pattern = line.replace(/\r$/, '');
  if (pattern.trim() === '' || pattern.startsWith('#')) return null;
  if (pattern.length > MAX_PATTERN_LENGTH) return null;
  // Trailing spaces are ignored unless escaped.
  pattern = pattern.replace(/(?<!\\)\s+$/, '');
  let negated = false;
  if (pattern.startsWith('!')) {
    negated = true;
    pattern = pattern.slice(1);
  }
  let dirOnly = false;
  if (pattern.endsWith('/')) {
    dirOnly = true;
    pattern = pattern.slice(0, -1);
  }
  let anchored = false;
  if (pattern.startsWith('/')) {
    anchored = true;
    pattern = pattern.slice(1);
  } else if (pattern.includes('/')) {
    anchored = true;
  }
  if (pattern === '') return null;
  return { negated, dirOnly, anchored, tokens: tokenizeGlob(pattern) };
}

export function parseGitignore(text: string): GitignoreRule[] {
  const rules: GitignoreRule[] = [];
  for (const line of text.split('\n')) {
    if (rules.length >= MAX_RULES) break;
    const rule = parseGitignoreLine(line);
    if (rule !== null) rules.push(rule);
  }
  return rules;
}

/** An unanchored pattern matches the whole path or any trailing part after a `/`. */
function ruleMatches(rule: GitignoreRule, path: string): boolean {
  return globMatches(rule.tokens, path, !rule.anchored);
}

/** The decision of the last matching rule across the layers, or null when none matches. */
function decide(layers: GitignoreLayer[], path: string, isDir: boolean): boolean | null {
  let decision: boolean | null = null;
  for (const layer of layers) {
    if (layer.base !== '' && !path.startsWith(`${layer.base}/`)) continue;
    const local = layer.base === '' ? path : path.slice(layer.base.length + 1);
    for (const rule of layer.rules) {
      if (rule.dirOnly && !isDir) continue;
      if (ruleMatches(rule, local)) decision = !rule.negated;
    }
  }
  return decision;
}

/**
 * Whether a file is ignored. `layers` are ordered root first; a deeper
 * .gitignore is applied after its parents, so its rules take precedence.
 */
export function isIgnored(layers: GitignoreLayer[], file: string): boolean {
  const segments = file.split('/');
  for (let i = 1; i < segments.length; i += 1) {
    if (decide(layers, segments.slice(0, i).join('/'), true) === true) return true;
  }
  return decide(layers, file, false) === true;
}
