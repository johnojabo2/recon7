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

  const runtimeBaseUrl = window.ENV?.VITE_API_URL || window.ENV?.BACKEND_URL || import.meta.env.VITE_API_URL || '';
  let fullUrl = endpoint;
  if (endpoint.startsWith('http')) {
    fullUrl = endpoint;
  } else if (runtimeBaseUrl && runtimeBaseUrl !== '/api') {
    const cleanBase = runtimeBaseUrl.replace(/\/$/, '');
    const cleanPath = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    fullUrl = `${cleanBase}${cleanPath}`;
  } else {
    fullUrl = endpoint.startsWith('/api')
      ? endpoint
      : `/api${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;
  }

  const response = await fetch(fullUrl, config);

  if (!response.ok) {
    let errorDetail = 'API request failed';
    try {
      const errData = await response.json();
      if (Array.isArray(errData.detail)) {
        // FastAPI / Pydantic validation error array
        errorDetail = errData.detail
          .map((item) => {
            const loc = item.loc ? item.loc[item.loc.length - 1] : '';
            const msg = item.msg || item.message || JSON.stringify(item);
            return loc ? `${loc}: ${msg}` : msg;
          })
          .join('. ');
      } else if (typeof errData.detail === 'string') {
        errorDetail = errData.detail;
      } else if (typeof errData.message === 'string') {
        errorDetail = errData.message;
      } else if (errData.detail) {
        errorDetail = JSON.stringify(errData.detail);
      }
    } catch (_) {
      errorDetail = response.statusText || errorDetail;
    }
    const error = new Error(errorDetail);
    error.status = response.status;
    throw error;
  }

  return response.json();
}
