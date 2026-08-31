import React, { createContext, useContext, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { apiRequest } from '../api/client';

const TenantContext = createContext(null);

export function TenantProvider({ children }) {
  const queryClient = useQueryClient();
  const [tenantId, setTenantId] = useState(() => {
    return localStorage.getItem('r7_tenant_id') || 'dev-default-tenant';
  });

  const [activeTarget, setActiveTarget] = useState(null);

  const updateTenant = async (id) => {
    if (!id) return;
    setTenantId(id);
    localStorage.setItem('r7_tenant_id', id);
    setActiveTarget(null);

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

    // Clear and refetch query cache so all views immediately switch to the new workspace!
    try {
      queryClient.clear();
      queryClient.invalidateQueries();
    } catch (e) {}
  };

  return (
    <TenantContext.Provider value={{ tenantId, setTenantId: updateTenant, activeTarget, setActiveTarget }}>
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
