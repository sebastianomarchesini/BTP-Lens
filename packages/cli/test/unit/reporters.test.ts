import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { CSV_BOM, renderAppsCsv, renderFindingsCsv, csvCell } from '../../src/reporters/csv.js';
import { DATA_PLACEHOLDER, renderHtml, scriptSafeJson } from '../../src/reporters/html.js';
import { parseFormats } from '../../src/reporters/index.js';
import { toReportData } from '../../src/reporters/reportData.js';
import { renderSarif } from '../../src/reporters/sarif.js';
import { scan } from '../../src/scan.js';
import { scanProject } from '../../src/project.js';
import { type Analyzer, ruleHelpUri } from '../../src/analyzers/types.js';
import { analyze } from '../../src/analyzers/index.js';
import { projectFinding } from '../../src/analyzers/project/support.js';
import { SNAPSHOT_SCHEMA_VERSION, type Snapshot } from '../../src/model/snapshot.js';
import { ACME, acmeFetch } from '../support/acme.js';
import { NOW, PROJECT_COLLECTOR, rawData, rawProject } from '../support/project.js';
import { materializeFixture } from '../support/projectFixture.js';

async function acmeReport() {
  const snapshot = await scan({
    apiUrl: ACME.api,
    org: ACME.org,
    deep: false,
    probeRoutes: true,
    concurrency: 5,
    env: { BTP_LENS_ACCESS_TOKEN: ACME.token },
    fetch: acmeFetch().fetch,
    now: () => ACME.now,
  });
  return toReportData(snapshot);
}

/** A project report with two findings of one rule at two locations. */
function projectReport() {
  const rule: Analyzer = {
    rule: {
      id: 'TEST_RULE',
      title: 'Test rule',
      description: 'A rule for the reporter tests.',
      roles: [],
      owasp: ['A01:2025', 'A07:2025'],
      helpUri: ruleHelpUri('TEST_RULE'),
    },
    requires: ['collect.project'],
    analyze(context) {
      return context.raw.projects.flatMap((project) => [
        projectFinding(context, project, {
          id: 'TEST_RULE',
          title: 'First',
          subject: 'AdminService',
          severity: 'high',
          location: { file: 'srv/services.cds', line: 3 },
          remediation: 'Restrict it.',
          references: [],
        }),
        projectFinding(context, project, {
          id: 'TEST_RULE',
          title: 'Second',
          subject: 'ProcessorService',
          severity: 'high',
          location: { file: 'srv/services.cds' },
          remediation: 'Restrict it.',
          references: [],
        }),
      ]);
    },
  };
  const raw = rawData(rawProject({ id: 'acme-incidents' }));
  const analysis = analyze(raw, NOW, [PROJECT_COLLECTOR], [rule]);
  const snapshot: Snapshot = {
    schemaVersion: SNAPSHOT_SCHEMA_VERSION,
    tool: { name: 'btp-lens', version: '0.0.0' },
    scannedAt: NOW,
    scope: { orgs: [], projects: ['acme-incidents'] },
    options: { deep: false, probeRoutes: false },
    checks: [PROJECT_COLLECTOR, ...analysis.ruleChecks],
    raw,
    apps: analysis.apps,
    findings: analysis.findings,
  };
  return { ...toReportData(snapshot), rules: [rule.rule] };
}

describe('csvCell', () => {
  it('quotes separators, quotes and newlines', () => {
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell('two\nlines')).toBe('"two\nlines"');
  });

  it.each(['=cmd()', '+1', '-1', '@SUM(A1)', '\tx', '\rx'])(
    'neutralizes formula-like cell %j',
    (value) => {
      expect(csvCell(value).replace(/^"/, '').startsWith("'")).toBe(true);
    },
  );

  it('renders objects as JSON and nulls as empty', () => {
    expect(csvCell({ a: 1 })).toBe('"{""a"":1}"');
    expect(csvCell(null)).toBe('');
    expect(csvCell(3)).toBe('3');
  });
});

describe('CSV reports', () => {
  it('writes one row per finding and per app', async () => {
    const data = await acmeReport();
    const findings = renderFindingsCsv(data).slice(CSV_BOM.length).trimEnd().split('\r\n');
    expect(findings[0]).toBe(
      'rule_id,severity,title,org,space,app,app_guid,remediation,references,evidence,owasp,file,line',
    );
    expect(findings).toHaveLength(1 + data.findings.length);
    expect(findings[1]?.endsWith(',A03:2025,,')).toBe(true);
    const apps = renderAppsCsv(data).slice(CSV_BOM.length).trimEnd().split('\r\n');
    expect(apps).toHaveLength(1 + 8);
    expect(apps[0]?.endsWith(',info,kind')).toBe(true);
    expect(apps[1]?.endsWith(',app')).toBe(true);
  });

  it('writes OWASP tags, file and line for project findings, and empty CF columns', () => {
    const data = projectReport();
    const findings = renderFindingsCsv(data).slice(CSV_BOM.length).trimEnd().split('\r\n');
    expect(findings[1]?.endsWith(',A01:2025 A07:2025,srv/services.cds,3')).toBe(true);
    expect(findings[2]?.endsWith(',A01:2025 A07:2025,srv/services.cds,')).toBe(true);
    const apps = renderAppsCsv(data).slice(CSV_BOM.length).trimEnd().split('\r\n');
    expect(apps[1]).toBe(
      'local,project,acme-incidents,project:acme-incidents,,unknown,,,,50,high,0,2,0,0,0,project',
    );
  });

  it('starts with a UTF-8 byte-order mark so that Excel reads non-ASCII names', async () => {
    const data = await acmeReport();
    for (const text of [renderFindingsCsv(data), renderAppsCsv(data)]) {
      expect(text.startsWith(CSV_BOM)).toBe(true);
      expect([...Buffer.from(text, 'utf8').subarray(0, 3)]).toEqual([0xef, 0xbb, 0xbf]);
      expect(text.indexOf(CSV_BOM, 1)).toBe(-1);
    }
  });

  it('drops control characters from cells but keeps tabs and line breaks quoted', () => {
    expect(csvCell('a\x00b\x07c\x7fd')).toBe('abcd');
    expect(csvCell('two\nlines')).toBe('"two\nlines"');
    expect(csvCell('\x1b[31mred')).toBe('[31mred');
  });
});

describe('SARIF report', () => {
  it('is a SARIF 2.1.0 log with rules and located results', async () => {
    const data = await acmeReport();
    const sarif = JSON.parse(renderSarif(data)) as {
      version: string;
      runs: {
        tool: { driver: { name: string; rules: { id: string }[] } };
        results: {
          ruleId: string;
          ruleIndex: number;
          level: string;
          locations: { physicalLocation: { artifactLocation: { uri: string } } }[];
          properties: Record<string, unknown>;
          partialFingerprints: Record<string, string>;
        }[];
      }[];
    };
    expect(sarif.version).toBe('2.1.0');
    const run = sarif.runs[0];
    expect(run?.tool.driver.name).toBe('btp-lens');
    expect(run?.tool.driver.rules.map((r) => r.id)).toContain('APP_NO_RECENT_DEPLOY');
    const legacy = run?.results.find((r) =>
      r.locations[0]?.physicalLocation.artifactLocation.uri.endsWith('/legacy-reporting'),
    );
    expect(legacy).toMatchObject({
      ruleId: 'APP_NO_RECENT_DEPLOY',
      ruleIndex: 0,
      level: 'warning',
      properties: { 'security-severity': '5.5', severity: 'medium' },
    });
    expect(legacy?.locations[0]?.physicalLocation.artifactLocation.uri).toBe(
      'cf/acme-prod/prod/legacy-reporting',
    );
    expect(legacy?.partialFingerprints['btpLensFinding/v1']).toMatch(/^[0-9a-f]{64}$/);
  });

  it('keeps the 0.1 fingerprint for CF findings and tags rules with their OWASP categories', async () => {
    const data = await acmeReport();
    const sarif = JSON.parse(renderSarif(data)) as {
      runs: {
        tool: { driver: { rules: { id: string; properties: { tags: string[] } }[] } };
        results: { properties: { appGuid: string }; partialFingerprints: Record<string, string> }[];
      }[];
    };
    const run = sarif.runs[0]!;
    const result = run.results[0]!;
    const expected = createHash('sha256')
      .update(`APP_NO_RECENT_DEPLOY:${result.properties.appGuid}`)
      .digest('hex');
    expect(result.partialFingerprints).toEqual({
      'btpLensFinding/v1': expected,
      primaryLocationLineHash: expected,
    });
    expect(run.tool.driver.rules[0]?.properties.tags).toEqual([
      'cloud-foundry',
      'btp',
      'owasp/A03:2025',
    ]);
  });

  it('locates project findings by relative file with a base id and gives each a distinct fingerprint', () => {
    const data = projectReport();
    const text = renderSarif(data);
    const sarif = JSON.parse(text) as {
      runs: {
        results: {
          locations: { physicalLocation: Record<string, unknown> }[];
          partialFingerprints: Record<string, string>;
        }[];
      }[];
    };
    const [first, second] = sarif.runs[0]!.results;
    expect(first?.locations[0]?.physicalLocation).toEqual({
      artifactLocation: { uri: 'srv/services.cds', uriBaseId: 'PROJECTROOT' },
      region: { startLine: 3 },
    });
    expect(second?.locations[0]?.physicalLocation).toEqual({
      artifactLocation: { uri: 'srv/services.cds', uriBaseId: 'PROJECTROOT' },
    });
    expect(first?.partialFingerprints['btpLensFinding/v1']).not.toBe(
      second?.partialFingerprints['btpLensFinding/v1'],
    );
    expect(first?.partialFingerprints['btpLensFinding/v1']).toBe(
      createHash('sha256')
        .update('TEST_RULE:project:acme-incidents:srv/services.cds:AdminService')
        .digest('hex'),
    );
    for (const forbidden of [
      'workingDirectory',
      'originalUriBaseIds',
      'file://',
      '/home/',
      '/Users/',
      'C:\\\\',
    ]) {
      expect(text, forbidden).not.toContain(forbidden);
    }
  });

  it('uses a project pseudo-path when a project finding has no file', async () => {
    // A materialized fixture, not process.cwd(): the test must not depend on the
    // working directory vitest runs from, nor on whatever lies in the package tree.
    const fixture = await materializeFixture('clean-cap');
    let snapshot: Snapshot;
    try {
      snapshot = await scanProject({ path: fixture.root, now: () => new Date(NOW) });
    } finally {
      await fixture.cleanup();
    }
    const data = toReportData(snapshot);
    data.findings.push({
      id: 'TEST_RULE',
      severity: 'low',
      title: 'No file',
      app: data.apps[0]!,
      evidence: { subject: 'x' },
      remediation: '',
      references: [],
    });
    const sarif = JSON.parse(renderSarif(data)) as {
      runs: {
        results: {
          ruleId: string;
          locations: { physicalLocation: { artifactLocation: { uri: string } } }[];
        }[];
      }[];
    };
    // The real collector names the project after package.json (clean-cap), not the
    // temporary folder it was materialized into.
    expect(snapshot.scope.projects).toEqual(['clean-cap']);
    const result = sarif.runs[0]?.results.find((r) => r.ruleId === 'TEST_RULE');
    expect(result?.locations[0]?.physicalLocation.artifactLocation.uri).toBe('project/clean-cap');
  });
});

describe('HTML report', () => {
  const template = `<!doctype html><html><head><title>t</title></head><body>${DATA_PLACEHOLDER}<script>const x = "$&";</script></body></html>`;

  it('injects the data exactly once, safely escaped', async () => {
    const data = await acmeReport();
    data.findings[0]!.title = '</script><script>alert(1)</script> $& $1';
    const html = renderHtml(data, template);
    expect(html).not.toContain(DATA_PLACEHOLDER);
    expect(html).not.toContain('</script><script>alert(1)');
    expect(html).toContain('\\u003c/script\\u003e');
    const json = /<script type="application\/json" id="btp-lens-data">(.*?)<\/script>/s.exec(
      html,
    )?.[1];
    const embedded = JSON.parse(json ?? 'null') as {
      summary: { apps: number };
      findings: { title: string }[];
    };
    expect(embedded).toMatchObject({ summary: { apps: 8 } });
    expect(embedded.findings[0]?.title).toBe('</script><script>alert(1)</script> $& $1');
  });

  it('rejects a template without exactly one placeholder', async () => {
    const data = await acmeReport();
    expect(() => renderHtml(data, '<html></html>')).toThrow(/exactly once \(found 0\)/);
    expect(() => renderHtml(data, DATA_PLACEHOLDER + DATA_PLACEHOLDER)).toThrow(/found 2/);
  });

  it('accepts a placeholder that a formatter wrapped over several lines', async () => {
    const data = await acmeReport();
    const wrapped =
      '<body>\n    <script type="application/json" id="btp-lens-data">\n      <!--BTP_LENS_DATA-->\n    </script>\n</body>';
    const html = renderHtml(data, wrapped);
    expect(html).not.toContain('BTP_LENS_DATA');
    expect(html).toMatch(/<script type="application\/json" id="btp-lens-data">\{.*\}<\/script>/s);
  });

  it('escapes JS line separators', () => {
    expect(scriptSafeJson({ s: 'a\u2028b\u2029c' })).toBe('{"s":"a\\u2028b\\u2029c"}');
  });
});

describe('parseFormats', () => {
  it('accepts a comma list and removes duplicates', () => {
    expect(parseFormats('html, JSON,json')).toEqual(['html', 'json']);
  });
  it('rejects unknown formats', () => {
    expect(() => parseFormats('pdf')).toThrow(/Unknown report format "pdf"/);
    expect(() => parseFormats('')).toThrow(/Unknown report format/);
  });
});
