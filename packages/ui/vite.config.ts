import { readFile, readdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import react from '@vitejs/plugin-react';
import { type Plugin, defineConfig } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';

const LICENSES_FILE = 'THIRD_PARTY_LICENSES.md';
const DATA_PLACEHOLDER =
  /<script type="application\/json" id="btp-lens-data">\s*<!--BTP_LENS_DATA-->\s*<\/script>/g;

/** Package root of a bundled module id, or undefined for our own code. */
function packageRoot(id: string): string | undefined {
  const marker = '/node_modules/';
  const at = id.replace(/\\/g, '/').lastIndexOf(marker);
  if (at < 0 || id.startsWith('\0')) return undefined;
  const rest = id.slice(at + marker.length).split('/');
  const name = rest[0]?.startsWith('@') ? rest.slice(0, 2).join('/') : rest[0];
  return name ? id.slice(0, at + marker.length) + name : undefined;
}

const LICENSE_NAME = /^licen[cs]e(\.(md|txt))?$/i;
const OVERRIDES = resolve(import.meta.dirname, 'licenses');

async function findLicense(dir: string): Promise<string | undefined> {
  try {
    const file = (await readdir(dir)).find((f) => LICENSE_NAME.test(f));
    return file ? (await readFile(join(dir, file), 'utf8')).trim() : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The package's own license, else a vendored copy from ./licenses; plus the
 * licenses of code it vendors (e.g. victory-vendor/lib-vendor/d3-*).
 */
async function licenseText(root: string, name: string): Promise<string | undefined> {
  const own =
    (await findLicense(root)) ??
    (await readFile(join(OVERRIDES, `${name.replace('/', '__')}.LICENSE`), 'utf8').then(
      (text) => text.trim(),
      () => undefined,
    ));
  const vendored: string[] = [];
  for (const sub of await readdir(join(root, 'lib-vendor')).catch(() => [] as string[])) {
    const text = await findLicense(join(root, 'lib-vendor', sub));
    if (text) vendored.push(`### Vendored ${sub}\n\n${text}`);
  }
  return [own, ...vendored].filter(Boolean).join('\n\n') || undefined;
}

/**
 * Lists every third-party package that ends up in the bundle, with its
 * license text. The report is a standalone file that people share, so the
 * notices (MIT and BSD require them in every copy) travel inside it as a
 * leading HTML comment; the same text ships as THIRD_PARTY_LICENSES.md.
 */
function embedLicenses(): Plugin {
  const roots = new Set<string>();
  let outDir = '';
  return {
    name: 'btp-lens:embed-licenses',
    apply: 'build',
    configResolved(config) {
      outDir = resolve(config.root, config.build.outDir);
    },
    generateBundle: {
      // Before the single-file plugin inlines and removes the chunks.
      order: 'pre',
      handler(_options, bundle) {
        for (const item of Object.values(bundle)) {
          if (item.type !== 'chunk') continue;
          for (const id of item.moduleIds) {
            const root = packageRoot(id);
            if (root) roots.add(root);
          }
        }
      },
    },
    async closeBundle() {
      const sections: string[] = [];
      for (const root of [...roots].sort()) {
        const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')) as {
          name: string;
          version: string;
          license?: string;
        };
        const text =
          (await licenseText(root, pkg.name)) ?? `License: ${pkg.license ?? 'see package'}`;
        sections.push(`## ${pkg.name}@${pkg.version} (${pkg.license ?? 'unknown'})\n\n${text}`);
      }
      const markdown = `# Third-party software in this report\n\n${[...new Set(sections)].join('\n\n')}\n`;
      await writeFile(resolve(outDir, LICENSES_FILE), markdown);
      const htmlPath = resolve(outDir, 'index.html');
      const html = await readFile(htmlPath, 'utf8');
      // The CLI injects the scan data here (packages/cli/src/reporters/html.ts).
      const placeholders = html.match(DATA_PLACEHOLDER)?.length ?? 0;
      if (placeholders !== 1) {
        throw new Error(`Report template must contain one data placeholder, found ${placeholders}`);
      }
      // "--" may not appear inside an HTML comment.
      const comment = `<!--\n${markdown.replace(/--/g, '- -')}-->\n`;
      await writeFile(
        htmlPath,
        html.replace(/^<!doctype html>\n?/i, (doctype) => `${doctype}${comment}`),
      );
    },
  };
}

/**
 * Two targets from one codebase:
 * - `report` (default build): one self-contained HTML file with every script,
 *   style, font and icon inlined. The CLI injects the scan data into it.
 * - `spa`: a normal multi-file build for server mode (v0.3).
 */
export default defineConfig(({ mode }) => {
  const report = mode === 'report';
  return {
    base: './',
    plugins: [
      react(),
      ...(report ? [viteSingleFile({ removeViteModuleLoader: true }), embedLicenses()] : []),
    ],
    build: {
      outDir: report ? 'dist-report' : 'dist',
      emptyOutDir: true,
      chunkSizeWarningLimit: 6000,
      ...(report ? { assetsInlineLimit: Number.MAX_SAFE_INTEGER } : {}),
    },
  };
});
