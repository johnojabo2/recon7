import React, { createContext, useContext, useState, useCallback } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { apiRequest } from '../api/client';

const TenantContext = createContext(null);

export function TenantProvider({ children }) {
  const queryClient = useQueryClient();
  const [tenantId, setTenantIdState] = useState(() => {
    return localStorage.getItem('r7_tenant_id') || 'dev-default-tenant';
  });

  const [activeTarget, setActiveTargetState] = useState(() => {
    return localStorage.getItem('r7_active_target') || null;
  });

  const [activeScanId, setActiveScanIdState] = useState(() => {
    return localStorage.getItem('r7_active_scan_id') || null;
  });

  const selectTarget = useCallback((targetDomain, scanId = null) => {
    setActiveTargetState(targetDomain || null);
    setActiveScanIdState(scanId || null);
    if (targetDomain) {
      localStorage.setItem('r7_active_target', targetDomain);
    } else {
      localStorage.removeItem('r7_active_target');
    }
    if (scanId) {
      localStorage.setItem('r7_active_scan_id', scanId);
    } else {
      localStorage.removeItem('r7_active_scan_id');
    }
  }, []);

  const setActiveTarget = useCallback((targetDomain) => {
    selectTarget(targetDomain, null);
  }, [selectTarget]);

  const setActiveScanId = useCallback((scanId) => {
    setActiveScanIdState(scanId || null);
    if (scanId) {
      localStorage.setItem('r7_active_scan_id', scanId);
    } else {
      localStorage.removeItem('r7_active_scan_id');
    }
  }, []);

  const updateTenant = async (id) => {
    if (!id) return;
    setTenantIdState(id);
    localStorage.setItem('r7_tenant_id', id);
    selectTarget(null, null);

    // Persist active tenant switch in backend if authenticated
    try {
      const token = localStorage.getItem('r7_auth_token');
      if (token) {
        const res = await apiRequest(`/auth/switch-tenant/${id}`, { method: 'POST' });
        if (res && res.access_token) {
          localStorage.setItem('r7_auth_token', res.access_token);
        }
      }
    } catch (e) {
      console.warn('Backend tenant switch notification:', e);
    }

    // Invalidate queries so all views immediately refetch with the new workspace ID
    try {
      queryClient.invalidateQueries();
    } catch (e) {}
  };

  return (
    <TenantContext.Provider
      value={{
        tenantId,
        setTenantId: updateTenant,
        activeTarget,
        setActiveTarget,
        activeScanId,
        setActiveScanId,
        selectTarget,
      }}
    >
      {children}
    </TenantContext.Provider>
  );
}

export function useTenant() {
  const context = useContext(TenantContext);
  if (!context) {
    throw new Error('useTenant must be used within a TenantProvider');
  }
  return context;
}

