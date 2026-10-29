import { QueryClient } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { DATA_ELEMENT_ID } from './data/report';
import projectSample from './test/fixtures/report-project.json';
import sample from './test/fixtures/report.json';

function embed(data: unknown): void {
  const script = document.createElement('script');
  script.type = 'application/json';
  script.id = DATA_ELEMENT_ID;
  script.textContent = typeof data === 'string' ? data : JSON.stringify(data);
  document.body.append(script);
}

function renderAt(hash: string) {
  window.location.hash = hash;
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<App queryClient={queryClient} />);
}

describe('report UI', () => {
  it('shows the key figures on the overview', async () => {
    embed(sample);
    renderAt('#/');
    const kpis = await screen.findByRole('region', { name: 'Key figures' });
    const values = within(kpis)
      .getAllByText(/^(\d+|—)$/)
      .map((el) => el.textContent);
    // Apps scanned, critical + high, idle apps (not checked), EOL runtimes (not checked)
    expect(values).toEqual(['8', '0', '—', '—']);
  });

  it('lists findings grouped by rule with remediation and evidence', async () => {
    embed(sample);
    renderAt('#/findings');
    expect(await screen.findByText('Last deployed 30 months ago')).toBeInTheDocument();
    expect(screen.getAllByRole('article')).toHaveLength(3);
    expect(screen.getAllByText(/cf restage/)).toHaveLength(3);
    expect(screen.getAllByText('ageDays')).toHaveLength(3);
  });

  it('filters findings by severity from the URL', async () => {
    embed(sample);
    renderAt('#/findings?severity=medium');
    expect(await screen.findByText('Last deployed 30 months ago')).toBeInTheDocument();
    expect(screen.getAllByRole('article')).toHaveLength(1);
  });

  it('filters findings by app from the URL', async () => {
    embed(sample);
    const app = sample.apps.find((a) => a.name === 'docs-static');
    renderAt(`#/findings?app=${app?.guid ?? ''}`);
    expect(
      await screen.findByText(/Showing findings for acme-prod \/ dev \/ docs-static/),
    ).toBeInTheDocument();
    expect(screen.getAllByRole('article')).toHaveLength(1);
  });

  it('shows an empty state when a filter matches nothing', async () => {
    embed(sample);
    renderAt('#/findings?severity=critical');
    await screen.findByText('Severity');
    expect(screen.queryAllByRole('article')).toHaveLength(0);
    expect(document.querySelector('[title-text="No findings match the filters"]')).not.toBeNull();
  });

  it('explains when the file holds no scan data', async () => {
    // Outside dev mode there is no sample fallback.
    vi.stubEnv('DEV', false);
    embed('<!--BTP_LENS_DATA-->');
    renderAt('#/');
    await screen.findByRole('main');
    expect(await screen.findByText(/not affiliated with SAP/)).toBeInTheDocument();
    expect(document.querySelector('[title-text="No scan data in this file"]')).not.toBeNull();
  });

  it('shows project key figures on the overview of a project scan', async () => {
    embed(projectSample);
    renderAt('#/');
    const kpis = await screen.findByRole('region', { name: 'Key figures' });
    // Card titles render inside the UI5 shadow DOM; the attribute is what we can see.
    const labels = [...kpis.querySelectorAll('ui5-card-header')].map((el) =>
      el.getAttribute('title-text'),
    );
    expect(labels).toEqual([
      'Projects scanned',
      'Critical and high findings',
      'Services open to all users',
      'Personal data without annotations',
    ]);
    const values = within(kpis)
      .getAllByText(/^(\d+|—)$/)
      .map((el) => el.textContent);
    // Projects scanned, critical + high, services open, entities without annotations
    expect(values).toEqual(['1', '3', '1', '2']);
    expect(document.querySelector('ui5-card-header[title-text="Top risks"]')).not.toBeNull();
    expect(document.querySelector('ui5-card-header[title-text="Top risky apps"]')).toBeNull();
    expect(screen.getByText(/The project acme-incidents was scanned on/)).toBeInTheDocument();
    expect(screen.getByText(/read-only scan of the project files/)).toBeInTheDocument();
    expect(document.querySelector('ui5-shellbar')?.getAttribute('secondary-title')).toMatch(
      /^acme-incidents · /,
    );
  });

  it('counts services, not projects, in the project key figures', async () => {
    const twoServices = structuredClone(projectSample);
    const open = twoServices.findings.find((f) => f.id === 'CAP_SERVICE_NO_RESTRICTION')!;
    const second = structuredClone(open);
    second.evidence.subject = 'ProcessorService';
    twoServices.findings.push(second);
    embed(twoServices);
    renderAt('#/');
    const kpis = await screen.findByRole('region', { name: 'Key figures' });
    // One project, two open services: the card counts the services.
    expect(kpis.querySelector('ui5-card[accessible-name="Projects scanned: 1"]')).not.toBeNull();
    expect(
      kpis.querySelector('ui5-card[accessible-name="Services open to all users: 2"]'),
    ).not.toBeNull();
  });

  it('shows file locations and OWASP tags on the findings of a project scan', async () => {
    embed(projectSample);
    renderAt('#/findings');
    expect(await screen.findByText('srv/services.cds:4')).toBeInTheDocument();
    expect(screen.getAllByRole('article')).toHaveLength(16);
    const locations = [...document.querySelectorAll('code.finding-location')].map(
      (el) => el.textContent,
    );
    // Panels follow the rule order; the line is left out when the rule does not know it.
    expect(locations).toEqual([
      'package.json',
      'package.json',
      'package.json',
      'mta.yaml',
      'db/schema.cds:10',
      'db/schema.cds:22',
      'srv/services.cds:4',
      'srv/services.cds:12',
      'xs-security.json',
      'app/incidents/xs-app.json',
      'app/incidents/xs-app.json',
      'mta_archives/acme-incidents_1.0.0.mtar',
      'db/data/acme.incidents-Customers.csv',
      'app/incidents/webapp/index.html:7',
      'app/incidents/webapp/test/flpSandbox.html:9',
      'app/launchpage.html:6',
    ]);
    const panel = document.querySelector(
      'ui5-panel[header-text="Service is open to every authenticated user (1) · OWASP A01:2025"]',
    );
    expect(panel).not.toBeNull();
    expect(panel?.getAttribute('title')).toBe(
      'OWASP Top 10 (2025): A01:2025 Broken Access Control',
    );
    expect(
      screen.getByText(
        'OWASP Top 10 (2025): A04:2025 Cryptographic Failures; A09:2025 Security Logging and Alerting Failures',
      ),
    ).toBeInTheDocument();
  });

  it('names the project when findings are filtered to it', async () => {
    embed(projectSample);
    renderAt('#/findings?app=project%3Aacme-incidents');
    expect(
      await screen.findByText(/Showing findings for project acme-incidents\./),
    ).toBeInTheDocument();
    expect(screen.getAllByRole('article')).toHaveLength(16);
  });

  it('lists projects without app-only columns or grouping', async () => {
    embed(projectSample);
    renderAt('#/apps');
    expect(await screen.findByText('Projects (1)')).toBeInTheDocument();
    expect(screen.queryByText('Group by')).toBeNull();
    expect(document.querySelector('ui5-tab[text="Projects"]')).not.toBeNull();
    expect(document.querySelector('ui5-tab[text="Apps"]')).toBeNull();
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(
      'Projects · acme-incidents',
    );
  });

  it('keeps the grouping toolbar and the Apps tab for a Cloud Foundry scan', async () => {
    embed(sample);
    renderAt('#/apps');
    expect(await screen.findByText('Apps (8)')).toBeInTheDocument();
    expect(screen.getByText('Group by')).toBeInTheDocument();
    expect(document.querySelector('ui5-tab[text="Apps"]')).not.toBeNull();
  });

  it('shows skipped checks on the overview', async () => {
    const withSkipped = structuredClone(sample);
    withSkipped.checks[1] = {
      ...withSkipped.checks[1]!,
      status: 'skipped',
      reason: 'insufficient role: needs SpaceAuditor',
      reasonCode: 'insufficient_role',
    } as (typeof withSkipped.checks)[number];
    withSkipped.summary.checksSkipped = 1;
    embed(withSkipped);
    renderAt('#/');
    expect(await screen.findByText(/1 check was skipped/)).toBeInTheDocument();
    expect(screen.getByText(/insufficient role: needs SpaceAuditor/)).toBeInTheDocument();
  });
});
