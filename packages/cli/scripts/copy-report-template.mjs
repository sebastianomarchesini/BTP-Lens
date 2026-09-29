// Copies the UI's single-file report build into the CLI package, so the
// published package can render HTML reports without the UI workspace.
import { copyFile, stat } from 'node:fs/promises';

const source = new URL('../../ui/dist-report/index.html', import.meta.url);
const target = new URL('../dist/report-template.html', import.meta.url);

try {
  await stat(source);
} catch {
  console.error(
    'Missing packages/ui/dist-report/index.html. Run `npm run build -w @btp-lens/ui` first.',
  );
  process.exit(1);
}
await copyFile(source, target);
await copyFile(
  new URL('../../ui/dist-report/THIRD_PARTY_LICENSES.md', import.meta.url),
  new URL('../dist/THIRD_PARTY_LICENSES.md', import.meta.url),
);
console.log('Copied report template to dist/report-template.html');
