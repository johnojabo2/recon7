import React, { createContext, useContext, useState, useEffect } from 'react';
import { apiRequest } from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [tenant, setTenant] = useState(null);
  const [token, setToken] = useState(() => localStorage.getItem('r7_auth_token') || null);
  const [loading, setLoading] = useState(true);

  // Restore authenticated session on mount
  useEffect(() => {
    async function restoreSession() {
      const storedToken = localStorage.getItem('r7_auth_token');
      if (!storedToken) {
        setLoading(false);
        return;
      }

      try {
        const data = await apiRequest('/auth/me');
        if (data && data.user) {
          setUser(data.user);
          setTenant(data.tenant);
          const existingTenant = localStorage.getItem('r7_tenant_id');
          const isSystemAdmin = data.user.role === 'system_admin';
          const allowedTenants = data.user.allowed_tenants || [data.user.tenant_id];
          const isAllowed = isSystemAdmin || allowedTenants.includes('*') || allowedTenants.includes(existingTenant);

          if (!existingTenant || !isAllowed) {
            localStorage.setItem('r7_tenant_id', data.tenant?.id || data.user.tenant_id);
          }
        } else {
          logout();
        }
      } catch (err) {
        console.warn('Session expired or invalid, clearing local session.');
        logout();
      } finally {
        setLoading(false);
      }
    }

    restoreSession();
  }, []);

  const login = async (email, password) => {
    const data = await apiRequest('/auth/login', {
      method: 'POST',
      body: { email, password },
    });

    if (data.access_token) {
      setToken(data.access_token);
      localStorage.setItem('r7_auth_token', data.access_token);
      setUser(data.user);
      setTenant(data.tenant);
      
      const existingTenant = localStorage.getItem('r7_tenant_id');
      const isSystemAdmin = data.user.role === 'system_admin';
      const allowedTenants = data.user.allowed_tenants || [data.user.tenant_id];
      const isAllowed = isSystemAdmin || allowedTenants.includes('*') || allowedTenants.includes(existingTenant);

      if (!existingTenant || !isAllowed) {
        localStorage.setItem('r7_tenant_id', data.tenant?.id || data.user.tenant_id);
      }
    }

    return data;
  };

  const register = async ({ fullName, email, password, organizationName }) => {
    const data = await apiRequest('/auth/register', {
      method: 'POST',
      body: {
        full_name: fullName,
        email,
        password,
        organization_name: organizationName || undefined,
      },
    });

    if (data.access_token) {
      setToken(data.access_token);
      localStorage.setItem('r7_auth_token', data.access_token);
      setUser(data.user);
      setTenant(data.tenant);
      if (data.tenant?.id) {
        localStorage.setItem('r7_tenant_id', data.tenant.id);
      }
    }

    return data;
  };

  const setSession = (data) => {
    if (data?.access_token) {
      setToken(data.access_token);
      localStorage.setItem('r7_auth_token', data.access_token);
      if (data.user) {
        setUser(data.user);
      }
      if (data.tenant) {
        setTenant(data.tenant);
        if (data.tenant.id) {
          localStorage.setItem('r7_tenant_id', data.tenant.id);
        }
      }
    }
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    setTenant(null);
    localStorage.removeItem('r7_auth_token');
    localStorage.removeItem('r7_tenant_id');
  };

  const value = {
    user,
    tenant,
    token,
    loading,
    isAuthenticated: Boolean(user && token),
    login,
    register,
    setSession,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
