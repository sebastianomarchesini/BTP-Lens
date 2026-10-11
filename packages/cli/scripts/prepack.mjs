// Copies the repository README, LICENSE and NOTICE into the package before
// `npm pack` / `npm publish`, so the npm page and tarball carry them.
//
// The README's relative links and images point at files in the repository
// root. npmjs.com resolves relative links against `repository.directory`
// (packages/cli), where they do not exist, so they are rewritten to absolute
// GitHub URLs pinned to this version's tag.
import { copyFile, readFile, writeFile } from 'node:fs/promises';

const root = new URL('../../../', import.meta.url);
const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const repo = 'https://github.com/sebastianomarchesini/BTP-Lens';
const ref = `v${pkg.version}`;
const blob = (path) => `${repo}/blob/${ref}/${path}`;
const raw = (path) =>
  `https://raw.githubusercontent.com/sebastianomarchesini/BTP-Lens/${ref}/${path}`;

/**
 * Rewrites `![alt](relative)` to raw file URLs and every other `](relative)`
 * (including the link around a badge image) to GitHub blob URLs. Absolute
 * URLs, anchors and mailto links stay as they are.
 */
export function absolutizeLinks(markdown) {
  const relative = /\((?![a-z][a-z0-9+.-]*:|#)([^)\s]+)\)/;
  return markdown
    .replace(
      new RegExp(`!\\[([^\\]]*)\\]${relative.source}`, 'g'),
      (_m, alt, target) => `![${alt}](${raw(target)})`,
    )
    .replace(new RegExp(`\\]${relative.source}`, 'g'), (_m, target) => `](${blob(target)})`);
}

const readme = absolutizeLinks(await readFile(new URL('README.md', root), 'utf8'));
await writeFile(new URL('../README.md', import.meta.url), readme);
for (const file of ['LICENSE', 'NOTICE']) {
  await copyFile(new URL(file, root), new URL(`../${file}`, import.meta.url));
}
// stderr, so `npm pack --json` output stays valid JSON.
console.error(`Copied README.md (links pinned to ${ref}), LICENSE and NOTICE into the package`);
