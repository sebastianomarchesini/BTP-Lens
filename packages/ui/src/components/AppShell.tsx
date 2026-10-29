import '@ui5/webcomponents-icons/dist/dark-mode.js';
import '@ui5/webcomponents-icons/dist/laptop.js';
import '@ui5/webcomponents-icons/dist/light-mode.js';
import '@ui5/webcomponents-icons/dist/palette.js';
import {
  BusyIndicator,
  Menu,
  MenuItem,
  MenuItemGroup,
  ShellBar,
  ShellBarItem,
  Tab,
  TabContainer,
} from '@ui5/webcomponents-react';
import { useEffect, useRef, useState } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router';
import logoUrl from '../assets/icon.png';
import { formatDateTime } from '../data/format';
import { useReport } from '../data/report';
import { isProjectInventory, scopeLabel } from '../data/summary';
import { THEME_MODES, type ThemeMode, useThemeMode } from '../ui5/theme';
import { EmptyState } from './EmptyState';
import { ErrorBoundary } from './ErrorBoundary';

const TABS = [
  { path: '/', label: 'Overview' },
  { path: '/apps', label: 'Apps' },
  { path: '/findings', label: 'Findings' },
] as const;

function isThemeMode(value: string | undefined): value is ThemeMode {
  return THEME_MODES.some((m) => m.mode === value);
}

/**
 * The theme menu lives outside the ShellBar on purpose: a Menu placed as a
 * ShellBar child lands in no slot and renders with no size, so it can never
 * be seen or clicked. The ShellBarItem inside the bar only opens it.
 */
function ThemeMenu({ opener, onClose }: { opener: HTMLElement | null; onClose: () => void }) {
  const [mode, setMode] = useThemeMode();
  return (
    <Menu
      open={opener !== null}
      opener={opener ?? undefined}
      headerText="Theme"
      onClose={onClose}
      onItemClick={(event) => {
        const next = event.detail.item.dataset.mode;
        if (isThemeMode(next)) setMode(next);
      }}
    >
      <MenuItemGroup checkMode="Single">
        {THEME_MODES.map((option) => (
          <MenuItem
            key={option.mode}
            text={option.label}
            icon={option.icon}
            checked={option.mode === mode}
            data-mode={option.mode}
          />
        ))}
      </MenuItemGroup>
    </Menu>
  );
}

export function AppShell() {
  const report = useReport();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const data = report.data ?? null;
  const [themeOpener, setThemeOpener] = useState<HTMLElement | null>(null);
  // A project scan lists projects, not apps, under the same route.
  const tabs = TABS.map((tab) =>
    tab.path === '/apps' && data && isProjectInventory(data.apps)
      ? { ...tab, label: 'Projects' }
      : tab,
  );
  const section = tabs.find((tab) => tab.path === pathname)?.label ?? 'Report';
  const mainRef = useRef<HTMLElement>(null);
  const firstRender = useRef(true);

  // One document title and one page heading per section, and focus moved to the
  // page on navigation: a title change alone is not announced in a single-page app.
  useEffect(() => {
    document.title = `${section} · BTP Lens report`;
  }, [section]);
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    mainRef.current?.focus();
  }, [pathname]);

  let content;
  if (report.isPending) {
    content = <BusyIndicator active delay={300} />;
  } else if (report.isError) {
    content = (
      <EmptyState
        name="NoData"
        title="This report cannot be displayed"
        subtitle={report.error instanceof Error ? report.error.message : 'Unknown error'}
      />
    );
  } else if (data === null) {
    content = (
      <EmptyState
        name="NoData"
        title="No scan data in this file"
        subtitle="Create a report with `btp-lens scan`, or from a snapshot with `btp-lens report --from <snapshot.json>`."
      />
    );
  } else {
    content = (
      <ErrorBoundary resetKey={pathname}>
        <Outlet context={data} />
      </ErrorBoundary>
    );
  }

  return (
    <div className="shell">
      <ShellBar
        primaryTitle="BTP Lens"
        secondaryTitle={
          data ? `${scopeLabel(data.scope)} · ${formatDateTime(data.scannedAt)}` : undefined
        }
        logo={<img src={logoUrl} alt="BTP Lens home" width={32} height={32} />}
        onLogoClick={() => void navigate('/')}
      >
        <ShellBarItem
          icon="palette"
          text="Theme"
          accessibilityAttributes={{ hasPopup: 'menu', expanded: themeOpener !== null }}
          onClick={(event) => setThemeOpener(event.detail.targetRef)}
        />
      </ShellBar>
      <ThemeMenu opener={themeOpener} onClose={() => setThemeOpener(null)} />
      {data && (
        <nav aria-label="Report sections">
          <TabContainer
            collapsed
            onTabSelect={(event) => {
              const path = event.detail.tab.dataset.path;
              if (path && path !== pathname) void navigate(path);
            }}
          >
            {tabs.map((tab) => (
              <Tab
                key={tab.path}
                text={tab.label}
                selected={tab.path === pathname}
                data-path={tab.path}
              />
            ))}
          </TabContainer>
        </nav>
      )}
      <main className="page" ref={mainRef} tabIndex={-1} aria-labelledby="page-title">
        <h1 id="page-title" className="visually-hidden">
          {data ? `${section} · ${scopeLabel(data.scope)}` : section}
        </h1>
        {content}
      </main>
      <footer className="footer">
        {data
          ? `${data.tool.name} ${data.tool.version} · read-only scan of ${data.scope.apiEndpoint ?? 'the project files'} · `
          : ''}
        Independent open-source project, not affiliated with SAP.
      </footer>
    </div>
  );
}
