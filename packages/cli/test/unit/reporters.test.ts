import { describe, expect, it } from 'vitest';
import { renderAppsCsv, renderFindingsCsv, csvCell } from '../../src/reporters/csv.js';
import { DATA_PLACEHOLDER, renderHtml, scriptSafeJson } from '../../src/reporters/html.js';
import { parseFormats } from '../../src/reporters/index.js';
import { toReportData } from '../../src/reporters/reportData.js';
import { renderSarif } from '../../src/reporters/sarif.js';
import { scan } from '../../src/scan.js';
import { ACME, acmeFetch } from '../support/acme.js';

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
    const findings = renderFindingsCsv(data).trimEnd().split('\r\n');
    expect(findings[0]).toBe(
      'rule_id,severity,title,org,space,app,app_guid,remediation,references,evidence',
    );
    expect(findings).toHaveLength(1 + data.findings.length);
    const apps = renderAppsCsv(data).trimEnd().split('\r\n');
    expect(apps).toHaveLength(1 + 8);
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
