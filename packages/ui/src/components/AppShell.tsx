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
import { useState } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router';
import logoUrl from '../assets/logo.svg';
import { formatDateTime } from '../data/format';
import { useReport } from '../data/report';
import { THEME_MODES, type ThemeMode, useThemeMode } from '../ui5/theme';
import { EmptyState } from './EmptyState';

const TABS = [
  { path: '/', label: 'Overview' },
  { path: '/apps', label: 'Apps' },
  { path: '/findings', label: 'Findings' },
] as const;

function isThemeMode(value: string | undefined): value is ThemeMode {
  return THEME_MODES.some((m) => m.mode === value);
}

function ThemeMenu() {
  const [mode, setMode] = useThemeMode();
  const [opener, setOpener] = useState<HTMLElement | null>(null);
  return (
    <>
      <ShellBarItem
        icon="palette"
        text="Theme"
        accessibilityAttributes={{ hasPopup: 'menu', expanded: opener !== null }}
        onClick={(event) => setOpener(event.detail.targetRef)}
      />
      <Menu
        open={opener !== null}
        opener={opener}
        headerText="Theme"
        onClose={() => setOpener(null)}
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
    </>
  );
}

export function AppShell() {
  const report = useReport();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const data = report.data ?? null;

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
    content = <Outlet context={data} />;
  }

  return (
    <div className="shell">
      <ShellBar
        primaryTitle="BTP Lens"
        secondaryTitle={
          data ? `${data.scope.orgs.join(', ')} · ${formatDateTime(data.scannedAt)}` : undefined
        }
        logo={<img src={logoUrl} alt="BTP Lens home" width={32} height={32} />}
        onLogoClick={() => void navigate('/')}
      >
        <ThemeMenu />
      </ShellBar>
      {data && (
        <nav aria-label="Report sections">
          <TabContainer
            collapsed
            onTabSelect={(event) => {
              const path = event.detail.tab.dataset.path;
              if (path && path !== pathname) void navigate(path);
            }}
          >
            {TABS.map((tab) => (
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
      <main className="page">{content}</main>
      <footer className="footer">
        {data
          ? `${data.tool.name} ${data.tool.version} · read-only scan of ${data.scope.apiEndpoint} · `
          : ''}
        Independent open-source project, not affiliated with SAP.
      </footer>
    </div>
  );
}
