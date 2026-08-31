import React, { useState } from 'react';
import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { apiRequest } from './api/client';
import TopBar from './components/TopBar';
import Navigation from './components/Navigation';
import ScopeGateModal from './components/ScopeGateModal';

import DashboardView from './views/DashboardView';
import ScanDetailView from './views/ScanDetailView';
import FindingsView from './views/FindingsView';
import PeopleView from './views/PeopleView';
import ReportView from './views/ReportView';
import ScopesSettingsView from './views/ScopesSettingsView';
import SettingsView from './views/SettingsView';
import IntegrationsView from './views/IntegrationsView';
import DocsView from './views/DocsView';
import LandingPageView from './views/LandingPageView';
import SetupWizard from './views/SetupWizard';
import IamManagementView from './views/IamManagementView';
import ProtectedRoute from './components/auth/ProtectedRoute';
import { useTenant } from './context/TenantContext';

function ConsoleLayout({ children, onOpenNewScan, activeTab, onSelectTab }) {
  return (
    <ProtectedRoute>
      <div className="h-screen w-screen bg-void flex flex-col font-sans text-text-primary overflow-hidden">
        <TopBar
          onOpenNewScan={onOpenNewScan}
          activeTab={activeTab}
          onSelectTab={onSelectTab}
        />
        <div className="flex-1 flex min-h-0 overflow-hidden">
          <Navigation activeTab={activeTab} onSelectTab={onSelectTab} />
          <main className="flex-1 overflow-y-auto p-6 md:p-8 bg-void min-w-0">
            <div className="max-w-7xl mx-auto">{children}</div>
          </main>
        </div>
      </div>
    </ProtectedRoute>
  );
}

export default function App() {
  const navigate = useNavigate();
  const location = useLocation();

  const [selectedScanId, setSelectedScanId] = useState(null);
  const [scopeModalOpen, setScopeModalOpen] = useState(false);
  const { activeTarget, setActiveTarget } = useTenant();

  // Check if system has been initialized
  const { data: setupStatus, isLoading: setupLoading, refetch: refetchSetup } = useQuery({
    queryKey: ['setupStatus'],
    queryFn: () => apiRequest('/setup/status'),
    staleTime: 30000,
  });

  // Extract active tab directly from URL path
  const rootSegment = location.pathname.split('/')[1] || '';
  const activeTab = rootSegment === '' || rootSegment === 'portal' || rootSegment === 'landing' ? 'landing' : rootSegment;

  const handleSelectTab = (tabId) => {
    if (tabId === 'landing' || tabId === 'portal') {
      navigate('/portal');
    } else {
      navigate(`/${tabId}`);
    }
  };

  const handleScanCreated = (scanId, targetDomain) => {
    setSelectedScanId(scanId);
    setActiveTarget(targetDomain);
    navigate(`/scans/${scanId}`);
  };

  const handleSelectScan = (scanId, targetDomain) => {
    setSelectedScanId(scanId);
    setActiveTarget(targetDomain);
    navigate(`/scans/${scanId}`);
  };

  const handleInitiateScanFromLanding = (targetDomain) => {
    setActiveTarget(targetDomain);
    navigate('/dashboard');
    setScopeModalOpen(true);
  };

  // If system is completely uninitialized (first launch), force SetupWizard
  if (!setupLoading && setupStatus && setupStatus.initialized === false) {
    return (
      <SetupWizard
        onSetupComplete={() => {
          refetchSetup();
          navigate('/dashboard');
        }}
      />
    );
  }

  return (
    <>
      <Routes>
        {/* Setup Wizard Route */}
        <Route
          path="/setup"
          element={
            <SetupWizard
              onSetupComplete={() => {
                refetchSetup();
                navigate('/dashboard');
              }}
            />
          }
        />

        {/* Root redirect to Dashboard */}
        <Route path="/" element={<Navigate to="/dashboard" replace />} />

        {/* Intelligence Portal Direct Route */}
        <Route
          path="/portal"
          element={
            <div className="min-h-screen bg-void flex flex-col font-sans text-text-primary">
              <LandingPageView
                onEnterConsole={() => navigate('/dashboard')}
                onInitiateScan={handleInitiateScanFromLanding}
              />
            </div>
          }
        />
        <Route
          path="/landing"
          element={
            <div className="min-h-screen bg-void flex flex-col font-sans text-text-primary">
              <LandingPageView
                onEnterConsole={() => navigate('/dashboard')}
                onInitiateScan={handleInitiateScanFromLanding}
              />
            </div>
          }
        />

        {/* Dashboard View */}
        <Route
          path="/dashboard"
          element={
            <ConsoleLayout
              onOpenNewScan={() => setScopeModalOpen(true)}
              activeTab="dashboard"
              onSelectTab={handleSelectTab}
            >
              <DashboardView
                onOpenNewScan={() => setScopeModalOpen(true)}
                onSelectScan={handleSelectScan}
                onSelectTab={handleSelectTab}
              />
            </ConsoleLayout>
          }
        />

        {/* Scans & Pipeline Views */}
        <Route
          path="/scans"
          element={
            <ConsoleLayout
              onOpenNewScan={() => setScopeModalOpen(true)}
              activeTab="scans"
              onSelectTab={handleSelectTab}
            >
              <ScanDetailView
                scanId={selectedScanId}
                onSelectTab={handleSelectTab}
              />
            </ConsoleLayout>
          }
        />
        <Route
          path="/scans/:scanId"
          element={
            <ConsoleLayout
              onOpenNewScan={() => setScopeModalOpen(true)}
              activeTab="scans"
              onSelectTab={handleSelectTab}
            >
              <ScanDetailView
                scanId={selectedScanId}
                onSelectTab={handleSelectTab}
              />
            </ConsoleLayout>
          }
        />

        {/* Findings View */}
        <Route
          path="/findings"
          element={
            <ConsoleLayout
              onOpenNewScan={() => setScopeModalOpen(true)}
              activeTab="findings"
              onSelectTab={handleSelectTab}
            >
              <FindingsView
                scanId={selectedScanId}
                onSelectTab={handleSelectTab}
              />
            </ConsoleLayout>
          }
        />
        <Route
          path="/findings/:scanId"
          element={
            <ConsoleLayout
              onOpenNewScan={() => setScopeModalOpen(true)}
              activeTab="findings"
              onSelectTab={handleSelectTab}
            >
              <FindingsView
                scanId={selectedScanId}
                onSelectTab={handleSelectTab}
              />
            </ConsoleLayout>
          }
        />

        {/* People OSINT View */}
        <Route
          path="/people"
          element={
            <ConsoleLayout
              onOpenNewScan={() => setScopeModalOpen(true)}
              activeTab="people"
              onSelectTab={handleSelectTab}
            >
              <PeopleView scanId={selectedScanId} />
            </ConsoleLayout>
          }
        />
        <Route
          path="/people/:scanId"
          element={
            <ConsoleLayout
              onOpenNewScan={() => setScopeModalOpen(true)}
              activeTab="people"
              onSelectTab={handleSelectTab}
            >
              <PeopleView scanId={selectedScanId} />
            </ConsoleLayout>
          }
        />

        {/* AI Reports View */}
        <Route
          path="/reports"
          element={
            <ConsoleLayout
              onOpenNewScan={() => setScopeModalOpen(true)}
              activeTab="reports"
              onSelectTab={handleSelectTab}
            >
              <ReportView scanId={selectedScanId} />
            </ConsoleLayout>
          }
        />
        <Route
          path="/reports/:scanId"
          element={
            <ConsoleLayout
              onOpenNewScan={() => setScopeModalOpen(true)}
              activeTab="reports"
              onSelectTab={handleSelectTab}
            >
              <ReportView />
            </ConsoleLayout>
          }
        />

        {/* Target Scopes View */}
        <Route
          path="/scopes"
          element={
            <ConsoleLayout
              onOpenNewScan={() => setScopeModalOpen(true)}
              activeTab="scopes"
              onSelectTab={handleSelectTab}
            >
              <ScopesSettingsView />
            </ConsoleLayout>
          }
        />

        {/* API Integrations View */}
        <Route
          path="/integrations"
          element={
            <ConsoleLayout
              onOpenNewScan={() => setScopeModalOpen(true)}
              activeTab="integrations"
              onSelectTab={handleSelectTab}
            >
              <IntegrationsView />
            </ConsoleLayout>
          }
        />

        {/* Documentation Hub View */}
        <Route
          path="/docs"
          element={
            <ConsoleLayout
              onOpenNewScan={() => setScopeModalOpen(true)}
              activeTab="docs"
              onSelectTab={handleSelectTab}
            >
              <DocsView />
            </ConsoleLayout>
          }
        />

        {/* IAM & Access Control View */}
        <Route
          path="/iam"
          element={
            <ConsoleLayout
              onOpenNewScan={() => setScopeModalOpen(true)}
              activeTab="iam"
              onSelectTab={handleSelectTab}
            >
              <IamManagementView />
            </ConsoleLayout>
          }
        />

        {/* Settings View */}
        <Route
          path="/settings"
          element={
            <ConsoleLayout
              onOpenNewScan={() => setScopeModalOpen(true)}
              activeTab="settings"
              onSelectTab={handleSelectTab}
            >
              <SettingsView onSelectTab={handleSelectTab} />
            </ConsoleLayout>
          }
        />

        {/* Fallback Route */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>

      {/* Scope Gate Modal */}
      <ScopeGateModal
        isOpen={scopeModalOpen}
        onClose={() => setScopeModalOpen(false)}
        onScanCreated={handleScanCreated}
        initialDomain={activeTarget || ''}
      />
    </>
  );
}
