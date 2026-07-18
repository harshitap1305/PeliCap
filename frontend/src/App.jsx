import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import PageLayout from './components/layout/PageLayout';
import Sessions from './pages/Sessions';
import Overview from './pages/Overview';
import FlowExplorer from './pages/FlowExplorer';
import PacketExplorer from './pages/PacketExplorer';
import DnsAnalytics from './pages/DnsAnalytics';
import HttpAnalytics from './pages/HttpAnalytics';
import NetworkTopology from './pages/NetworkTopology';
import Alerts from './pages/Alerts';
import AiCopilot from './pages/AiCopilot';
import Settings from './pages/Settings';

function App() {
  return (
    <Router>
      <PageLayout>
        <Routes>
          <Route path="/" element={<Navigate to="/sessions" replace />} />
          <Route path="/sessions" element={<Sessions />} />
          <Route path="/overview" element={<Overview />} />
          <Route path="/flows" element={<FlowExplorer />} />
          <Route path="/packets" element={<PacketExplorer />} />
          <Route path="/dns" element={<DnsAnalytics />} />
          <Route path="/http" element={<HttpAnalytics />} />
          <Route path="/topology" element={<NetworkTopology />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/copilot" element={<AiCopilot />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </PageLayout>
    </Router>
  );
}

export default App;
