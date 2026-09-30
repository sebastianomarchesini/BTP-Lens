// Copies the repository README, LICENSE and NOTICE into the package before
// `npm pack` / `npm publish`, so the npm page and tarball carry them.
import { copyFile } from 'node:fs/promises';

for (const file of ['README.md', 'LICENSE', 'NOTICE']) {
  await copyFile(
    new URL(`../../../${file}`, import.meta.url),
    new URL(`../${file}`, import.meta.url),
  );
}
console.log('Copied README.md, LICENSE and NOTICE into the package');
