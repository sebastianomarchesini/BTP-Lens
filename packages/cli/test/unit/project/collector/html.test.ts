import { describe, expect, it } from 'vitest';
import {
  NON_HTTP_SRC,
  isTestPage,
  safeSrc,
  scanHtml,
  versionFormOf,
} from '../../../../src/collectors/project/html.js';

describe('bootstrap detection', () => {
  it('finds a bootstrap by id or by a src ending in sap-ui-core.js, with its line', () => {
    const html = `<!DOCTYPE html>
<html><head>
<script>window.x = 1;</script>
<script id="sap-ui-bootstrap"
  src="https://ui5.example.com/resources/sap-ui-core.js?sap-ui-token=POISON_query#POISON_fragment"
  data-sap-ui-resourceroots='{"POISON_root":"./"}' data-sap-ui-async="true"></script>
<SCRIPT SRC='https://cdn.example.com/1.120/resources/sap-ui-core.js' integrity="sha384-POISON_hash" crossorigin=anonymous></SCRIPT>
<script src=resources/sap-ui-core.js></script>
<script src="other.js" id="not-bootstrap"></script>
</head></html>`;
    const found = scanHtml(html, 'app/webapp/index.html');
    expect(found).toEqual([
      {
        file: 'app/webapp/index.html',
        line: 4,
        src: 'https://ui5.example.com/resources/sap-ui-core.js',
        external: true,
        integrity: false,
        versionForm: 'latest',
        testPage: false,
      },
      {
        file: 'app/webapp/index.html',
        line: 7,
        src: 'https://cdn.example.com/1.120/resources/sap-ui-core.js',
        external: true,
        integrity: true,
        versionForm: 'evergreen',
        testPage: false,
      },
      {
        file: 'app/webapp/index.html',
        line: 8,
        src: 'resources/sap-ui-core.js',
        external: false,
        integrity: false,
        versionForm: 'none',
        testPage: false,
      },
    ]);
    expect(JSON.stringify(found)).not.toContain('POISON');
  });

  it('keeps origin and path only: no userinfo, query or fragment', () => {
    expect(
      safeSrc('https://POISON_user:POISON_pw@cdn.example.com/1.120/resources/sap-ui-core.js'),
    ).toEqual({
      src: 'https://cdn.example.com/1.120/resources/sap-ui-core.js',
      external: true,
    });
    expect(safeSrc('http://h.example.com:8080/x.js?a=POISON#f')).toEqual({
      src: 'http://h.example.com:8080/x.js',
      external: true,
    });
    expect(safeSrc('//cdn.example.com/resources/sap-ui-core.js')).toEqual({
      src: 'https://cdn.example.com/resources/sap-ui-core.js',
      external: true,
    });
    expect(safeSrc('../resources/sap-ui-core.js?v=POISON#x')).toEqual({
      src: '../resources/sap-ui-core.js',
      external: false,
    });
    expect(safeSrc('data:text/javascript,POISON')).toEqual({ src: NON_HTTP_SRC, external: false });
    expect(safeSrc('javascript:POISON()')).toEqual({ src: NON_HTTP_SRC, external: false });
    expect(safeSrc('file:///home/poison-user/sap-ui-core.js')).toEqual({
      src: NON_HTTP_SRC,
      external: false,
    });
    expect(safeSrc('https://[not a url/sap-ui-core.js')).toEqual({
      src: NON_HTTP_SRC,
      external: false,
    });
    expect(safeSrc(`https://h.example.com/${'a'.repeat(300)}`).src).toHaveLength(200);
  });

  it('classifies the version form and test pages', () => {
    expect(versionFormOf('https://ui5.example.com/1.120.3/resources/sap-ui-core.js', true)).toBe(
      'specific',
    );
    expect(versionFormOf('https://ui5.example.com/1.120/resources/sap-ui-core.js', true)).toBe(
      'evergreen',
    );
    expect(versionFormOf('https://ui5.example.com/resources/sap-ui-core.js', true)).toBe('latest');
    expect(versionFormOf('resources/1.120.0/sap-ui-core.js', false)).toBe('none');
    expect(isTestPage('app/webapp/test/flpSandbox.html')).toBe(true);
    expect(isTestPage('app/webapp/test/integration/opaTests.qunit.html')).toBe(true);
    expect(isTestPage('app/webapp/flpSandbox.html')).toBe(true);
    expect(isTestPage('app/webapp/unit.qunit.html')).toBe(true);
    expect(isTestPage('app/webapp/index.html')).toBe(false);
    expect(isTestPage('app/testing/index.html')).toBe(false);
  });

  it('reads attributes with a tokenizer: unquoted values, no values, odd spacing', () => {
    const html = `<script\n\tid = "sap-ui-bootstrap"\n src = resources/sap-ui-core.js integrity async/>`;
    expect(scanHtml(html, 'index.html')).toEqual([
      {
        file: 'index.html',
        line: 1,
        src: 'resources/sap-ui-core.js',
        external: false,
        integrity: true,
        versionForm: 'none',
        testPage: false,
      },
    ]);
    expect(scanHtml('<script id="sap-ui-bootstrap">', 'a.html')[0]?.src).toBe('');
    expect(scanHtml('<scripts src="sap-ui-core.js">', 'a.html')).toEqual([]);
    expect(scanHtml('', 'a.html')).toEqual([]);
  });

  it('finishes hostile input quickly and caps the number of tags', () => {
    const started = Date.now();
    const many = '<script src="x/sap-ui-core.js">'.repeat(5_000);
    expect(scanHtml(many, 'a.html').length).toBeLessThanOrEqual(200);
    const unclosed = `<script id="sap-ui-bootstrap" src="${'a'.repeat(1_000_000)}`;
    expect(scanHtml(unclosed, 'a.html')).toHaveLength(1);
    expect(scanHtml('<script '.repeat(100_000), 'a.html')).toEqual([]);
    expect(Date.now() - started).toBeLessThan(2_000);
  });
});
