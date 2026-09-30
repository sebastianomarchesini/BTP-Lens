import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ThemeProvider } from '@ui5/webcomponents-react';
import { HashRouter, Navigate, Route, Routes } from 'react-router';
import { AppShell } from './components/AppShell';
import { Apps } from './pages/Apps';
import { Findings } from './pages/Findings';
import { Overview } from './pages/Overview';

export function App({ queryClient = new QueryClient() }: { queryClient?: QueryClient }) {
  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        {/* Hash routing works from file:// URLs, where the report is opened. */}
        <HashRouter>
          <Routes>
            <Route element={<AppShell />}>
              <Route index element={<Overview />} />
              <Route path="apps" element={<Apps />} />
              <Route path="findings" element={<Findings />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </HashRouter>
      </QueryClientProvider>
    </ThemeProvider>
  );
}
