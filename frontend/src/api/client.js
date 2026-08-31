/**
 * R7 Unified API Client
 * Automatically attaches X-Tenant-ID header to every request.
 */

export async function apiRequest(endpoint, { method = 'GET', body = null, tenantId = null, headers = {} } = {}) {
  const finalHeaders = {
    'Content-Type': 'application/json',
    ...headers,
  };

  const activeTenant = tenantId || localStorage.getItem('r7_tenant_id') || 'dev-default-tenant';
  if (activeTenant) {
    finalHeaders['X-Tenant-ID'] = activeTenant;
  }

  const authToken = localStorage.getItem('r7_auth_token');
  if (authToken) {
    finalHeaders['Authorization'] = `Bearer ${authToken}`;
  }

  const config = {
    method,
    headers: finalHeaders,
  };

  if (body) {
    config.body = JSON.stringify(body);
  }

  // Ensure all API calls route through /api prefix to avoid collision with frontend page routes
  const cleanEndpoint = endpoint.startsWith('/api') || endpoint.startsWith('http')
    ? endpoint
    : `/api${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;

  const response = await fetch(cleanEndpoint, config);

  if (!response.ok) {
    let errorDetail = 'API request failed';
    try {
      const errData = await response.json();
      errorDetail = errData.detail || errorDetail;
    } catch (_) {
      errorDetail = response.statusText || errorDetail;
    }
    const error = new Error(errorDetail);
    error.status = response.status;
    throw error;
  }

  return response.json();
}
