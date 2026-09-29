/**
 * Buildpack names can be git or HTTP URLs, and those URLs sometimes carry
 * credentials (https://user:token@host/repo) or tokens in the query string.
 * Keep only scheme, host and path.
 */
export function redactUrlCredentials(value: string): string {
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return value;
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    // Not parseable: drop anything that looks like userinfo.
    return value.replace(/\/\/[^/@]*@/, '//');
  }
}

/** Collapses whitespace and cuts free text (e.g. buildpack detect output). */
export function truncate(value: string | null | undefined, max = 200): string | null {
  if (value === null || value === undefined) return null;
  const clean = value.replace(/\s+/g, ' ').trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}
