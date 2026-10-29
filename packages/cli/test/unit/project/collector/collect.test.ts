import { mkdir, mkdtemp, realpath, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { collectProject } from '../../../../src/collectors/project/index.js';
import { MAX_FILE_BYTES } from '../../../../src/collectors/project/read.js';
import { isSafeRelativePath } from '../../../../src/model/paths.js';
import { RawProjectSchema } from '../../../../src/model/raw.js';

const tmp = async () => realpath(await mkdtemp(join(tmpdir(), 'btp-lens-collect-')));

async function file(root: string, rel: string, content: string | Buffer): Promise<void> {
  const abs = join(root, ...rel.split('/'));
  await mkdir(join(abs, '..'), { recursive: true });
  await writeFile(abs, content);
}

const POISON = 'POISON_in_broken_file';

describe('collectProject', () => {
  it('turns every read or parse failure into an unreadable entry and never throws', async () => {
    const root = await tmp();
    await file(root, 'package.json', `{ "name": "acme", "dependencies": { ${POISON} } }`);
    await file(root, '.cdsrc.json', `[ "${POISON}" ]`);
    await file(root, '.cdsrc.yaml', `requires: [${POISON}\n  x: }`);
    await file(root, 'mta.yaml', `- ${POISON}\n`);
    await file(root, 'xs-security.json', `{ ${POISON}`);
    await file(root, 'app/xs-app.json', `"${POISON}"`);
    await file(root, 'srv/bin.cds', Buffer.concat([Buffer.from(POISON), Buffer.from([0, 1, 2])]));
    await file(root, 'db/big.cds', Buffer.alloc(MAX_FILE_BYTES + 1, 0x20));
    await file(root, 'db/data/odd.csv', `${POISON},"unterminated\n`);
    await file(root, 'app/index.html', `<script src="${POISON}`);
    await file(root, 'srv/ok.cds', 'service Ok {}');

    const project = await collectProject(root);
    expect(RawProjectSchema.safeParse(project).success).toBe(true);
    expect(project.unreadable).toEqual([
      { file: '.cdsrc.json', kind: 'json' },
      { file: '.cdsrc.yaml', kind: 'yaml' },
      { file: 'app/xs-app.json', kind: 'json' },
      { file: 'db/big.cds', kind: 'too-large' },
      { file: 'mta.yaml', kind: 'yaml' },
      { file: 'package.json', kind: 'json' },
      { file: 'srv/bin.cds', kind: 'binary' },
      { file: 'xs-security.json', kind: 'json' },
    ]);
    // A CSV with an odd header and an HTML without a bootstrap are read, just empty.
    expect(project.files).toEqual(['app/index.html', 'db/data/odd.csv', 'srv/ok.cds']);
    expect(project.seedData).toEqual([
      {
        file: 'db/data/odd.csv',
        columnCount: 0,
        headerRejected: true,
        rowsChecked: 0,
        sensitiveColumns: [],
      },
    ]);
    expect(project.html).toEqual([]);
    expect(project.packageJson.present).toBe(false);
    expect(project.sourcesRead).toEqual([]);
    expect(project.mta).toBeNull();
    expect(project.cdsFiles.map((f) => f.file)).toEqual(['srv/ok.cds']);
    expect(JSON.stringify(project)).not.toContain(POISON);
    expect(JSON.stringify(project)).not.toContain(root);
  });

  it('merges the cds sources in order and records which were read', async () => {
    const root = await tmp();
    await file(
      root,
      '.cdsrc.yaml',
      'requires:\n  auth:\n    kind: basic\n    users:\n      a: { password: x }\n',
    );
    await file(
      root,
      '.cdsrc.json',
      '{ "requires": { "auth": { "restrict_all_services": true } } }',
    );
    await file(
      root,
      'package.json',
      JSON.stringify({
        name: 'acme',
        cds: { requires: { auth: { '[production]': { kind: 'xsuaa' } } } },
      }),
    );
    const project = await collectProject(root);
    expect(project.sourcesRead).toEqual(['.cdsrc.yaml', '.cdsrc.json', 'package.json']);
    expect(project.cds.effective.development).toEqual({
      authKind: 'basic',
      mockedUsers: 1,
      mockedUsersWithPassword: 1,
      restrictAllServices: true,
      auditLogKind: null,
      auditLogConfigured: false,
    });
    expect(project.cds.effective.production.authKind).toBe('xsuaa');
    expect(project.files).toEqual(['.cdsrc.json', '.cdsrc.yaml', 'package.json']);
  });

  it('lists archives with their .gitignore decision, opening only the .gitignore files on their path', async () => {
    const root = await tmp();
    await file(root, 'package.json', '{}');
    await file(root, '.gitignore', '*.mtar\n');
    await file(root, 'app/.gitignore', '!keep.mtar\n');
    await file(root, 'unrelated/.gitignore', '# POISON_unrelated\n');
    await file(root, 'mta_archives/acme_1.0.0.mtar', Buffer.alloc(64, 0x50));
    await file(root, 'app/keep.mtar', Buffer.alloc(10, 0x50));
    await file(root, 'app/drop.mtar', Buffer.alloc(10, 0x50));
    const project = await collectProject(root);
    expect(project.archives).toEqual([
      { file: 'app/drop.mtar', bytes: 10, ignored: true },
      { file: 'app/keep.mtar', bytes: 10, ignored: false },
      { file: 'mta_archives/acme_1.0.0.mtar', bytes: 64, ignored: true },
    ]);
    expect(project.files).toEqual(['.gitignore', 'app/.gitignore', 'package.json']);
    expect(project.gitIgnore).toEqual({ present: true });
  });

  it('collects descriptors anywhere in the tree and keeps every path relative and safe', async () => {
    const root = await tmp();
    await file(root, 'mta.yaml', 'ID: acme\nmodules:\n  - name: srv\n    path: srv\n');
    await file(root, 'xs-security.json', '{ "scopes": [{ "name": "$XSAPPNAME.a" }] }');
    await file(
      root,
      'app/ui/xs-app.json',
      '{ "routes": [{ "source": "^/(.*)$", "service": "html5-apps-repo-rt" }] }',
    );
    await file(
      root,
      'app/ui/webapp/index.html',
      '<script src="resources/sap-ui-core.js"></script>',
    );
    await file(root, 'db/data/x.csv', 'ID,password\n1,s3cret\n');
    await file(root, 'db/csv/y.csv', 'ID\n1\n');
    await file(root, 'test/data/z.csv', 'ID\n1\n');
    await file(root, 'db/other.csv', 'ID,password\n1,POISON_not_seed\n');
    const project = await collectProject(root);
    expect(project.id).toBe('acme');
    expect(project.xsSecurity.map((x) => x.file)).toEqual(['xs-security.json']);
    expect(project.xsApps.map((x) => x.file)).toEqual(['app/ui/xs-app.json']);
    expect(project.html.map((h) => h.file)).toEqual(['app/ui/webapp/index.html']);
    expect(project.seedData.map((s) => s.file)).toEqual([
      'db/csv/y.csv',
      'db/data/x.csv',
      'test/data/z.csv',
    ]);
    expect(project.seedData[1]?.sensitiveColumns).toEqual([
      { column: 'password', kind: 'secret', rowsMatching: 1 },
    ]);
    const paths = [
      ...project.files,
      ...project.xsSecurity.map((x) => x.file),
      ...project.xsApps.map((x) => x.file),
      ...project.html.map((h) => h.file),
      ...project.seedData.map((s) => s.file),
      ...(project.mta?.modules.map((m) => m.path ?? '') ?? []),
    ];
    expect(paths.every(isSafeRelativePath)).toBe(true);
    expect(JSON.stringify(project)).not.toContain('POISON');
    expect(JSON.stringify(project)).not.toContain('s3cret');
  });

  it('accepts a valid project where every list is empty', async () => {
    const root = await tmp();
    await file(root, '.cdsrc.yaml', 'requires: {}\n');
    const project = await collectProject(root);
    expect(project).toMatchObject({
      sourcesRead: ['.cdsrc.yaml'],
      files: ['.cdsrc.yaml'],
      filesTruncated: false,
      unreadable: [],
      repository: false,
      mta: null,
      xsSecurity: [],
      xsApps: [],
      cdsFiles: [],
      seedData: [],
      archives: [],
      html: [],
    });
  });
});
