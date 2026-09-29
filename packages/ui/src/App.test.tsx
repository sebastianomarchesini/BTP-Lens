import { QueryClient } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { DATA_ELEMENT_ID } from './data/report';
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
