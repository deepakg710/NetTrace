import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { CaptureProvider } from '../context/CaptureContext';
import { Layout } from '../components/Layout';

import { DashboardPage } from '../features/dashboard/DashboardPage';
import { CapturesPage } from '../features/captures/CapturesPage';
import { PacketsPage } from '../features/packets/PacketsPage';
import { EndpointsPage } from '../features/endpoints/EndpointsPage';
import { FlowsPage } from '../features/flows/FlowsPage';
import { TopologyPage } from '../features/topology/TopologyPage';
import { DNSPage } from '../features/dns/DNSPage';
import { FindingsPage } from '../features/findings/FindingsPage';
import { ReportsPage } from '../features/reports/ReportsPage';
import { SettingsPage } from '../features/settings/SettingsPage';

export const App: React.FC = () => {
  return (
    <CaptureProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<DashboardPage />} />
            <Route path="captures" element={<CapturesPage />} />
            <Route path="packets" element={<PacketsPage />} />
            <Route path="endpoints" element={<EndpointsPage />} />
            <Route path="flows" element={<FlowsPage />} />
            <Route path="topology" element={<TopologyPage />} />
            <Route path="dns" element={<DNSPage />} />
            <Route path="findings" element={<FindingsPage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="settings" element={<SettingsPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </CaptureProvider>
  );
};

export default App;
