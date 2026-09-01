import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiRequest } from './client';
import { useTenant } from '../context/TenantContext';

export function useDashboard() {
  const { tenantId } = useTenant();
  return useQuery({
    queryKey: ['dashboard', tenantId],
    queryFn: () => apiRequest('/dashboard', { tenantId }),
    refetchInterval: 5000,
    staleTime: 2000,
  });
}

export function useTenants() {
  return useQuery({
    queryKey: ['tenants'],
    queryFn: () => apiRequest('/tenants'),
  });
}

export function useCreateTenant() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data) => apiRequest('/tenants', { method: 'POST', body: data }),
    onSuccess: (newTenant) => {
      if (newTenant && newTenant.id) {
        queryClient.setQueryData(['tenants'], (old = []) => [newTenant, ...old]);
      }
      queryClient.invalidateQueries({ queryKey: ['tenants'] });
    },
  });
}

export function useScopes() {
  const { tenantId } = useTenant();
  return useQuery({
    queryKey: ['scopes', tenantId],
    queryFn: () => apiRequest('/scopes', { tenantId }),
  });
}

export function useRegisterScope() {
  const { tenantId } = useTenant();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data) => apiRequest('/scopes', { method: 'POST', body: data, tenantId }),
    onSuccess: (newScope) => {
      if (newScope && newScope.id) {
        queryClient.setQueryData(['scopes', tenantId], (old = []) => [newScope, ...old]);
      }
      queryClient.invalidateQueries({ queryKey: ['scopes', tenantId] });
    },
  });
}

export function useCreateScan() {
  const { tenantId } = useTenant();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data) => apiRequest('/scan', { method: 'POST', body: data, tenantId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dashboard', tenantId] });
      queryClient.invalidateQueries({ queryKey: ['scans', tenantId] });
    },
  });
}

export function useScansList(limit = 100) {
  const { tenantId } = useTenant();
  return useQuery({
    queryKey: ['scansList', tenantId, limit],
    queryFn: () => apiRequest(`/scans?limit=${limit}`, { tenantId }),
    refetchInterval: 3000,
  });
}

export function useScanJob(jobId) {
  const { tenantId } = useTenant();
  return useQuery({
    queryKey: ['scanJob', tenantId, jobId],
    queryFn: () => apiRequest(`/scan/${jobId}`, { tenantId }),
    enabled: Boolean(jobId),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      if (status === 'pending' || status === 'running') {
        return 1500; // Poll active scan every 1.5s
      }
      return false; // Stop polling once complete, failed, or cancelled
    },
  });
}

export function useAbortScan() {
  const { tenantId } = useTenant();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (jobId) => apiRequest(`/scan/${jobId}/abort`, { method: 'POST', tenantId }),
    onSuccess: (data, jobId) => {
      queryClient.invalidateQueries({ queryKey: ['scanJob', tenantId, jobId] });
      queryClient.invalidateQueries({ queryKey: ['dashboard', tenantId] });
      queryClient.invalidateQueries({ queryKey: ['scansList', tenantId] });
      queryClient.invalidateQueries({ queryKey: ['scans', tenantId] });
    },
  });
}

export function useScanFindings(jobId, findingType = null) {
  const { tenantId } = useTenant();
  const endpoint = findingType
    ? `/scan/${jobId}/findings?finding_type=${encodeURIComponent(findingType)}`
    : `/scan/${jobId}/findings`;

  return useQuery({
    queryKey: ['scanFindings', tenantId, jobId, findingType],
    queryFn: () => apiRequest(endpoint, { tenantId }),
    enabled: Boolean(jobId),
    refetchInterval: 1500,
  });
}

export function useScanReport(jobId) {
  const { tenantId } = useTenant();
  return useQuery({
    queryKey: ['scanReport', tenantId, jobId],
    queryFn: () => apiRequest(`/scan/${jobId}/report`, { tenantId }),
    enabled: Boolean(jobId),
    retry: 2,
  });
}

export function useScanGraph(jobId, entityTypes = [], minConfidence = 0.0, lens = 'composite') {
  const { tenantId } = useTenant();
  let endpoint = `/scan/${jobId}/graph?min_confidence=${minConfidence}&lens=${encodeURIComponent(lens)}`;
  if (entityTypes && entityTypes.length > 0) {
    entityTypes.forEach((t) => {
      endpoint += `&entity_types=${encodeURIComponent(t)}`;
    });
  }

  return useQuery({
    queryKey: ['scanGraph', tenantId, jobId, entityTypes, minConfidence, lens],
    queryFn: () => apiRequest(endpoint, { tenantId }),
    enabled: Boolean(jobId),
    refetchInterval: (query) => {
      // Poll while graph is still small or scan is progressing
      if ((query.state.data?.nodes_count || 0) < 5) return 2500;
      return 5000;
    },
  });
}

export function useEvidence(jobId, evidenceId) {
  const { tenantId } = useTenant();
  return useQuery({
    queryKey: ['evidence', tenantId, jobId, evidenceId],
    queryFn: () => apiRequest(`/scan/${jobId}/evidence/${evidenceId}`, { tenantId }),
    enabled: Boolean(jobId && evidenceId),
  });
}

export function useScanExposures(jobId) {
  const { tenantId } = useTenant();
  return useQuery({
    queryKey: ['scanExposures', tenantId, jobId],
    queryFn: () => apiRequest(`/scan/${jobId}/exposures`, { tenantId }),
    enabled: Boolean(jobId),
  });
}

export function useScanDocuments(jobId) {
  const { tenantId } = useTenant();
  return useQuery({
    queryKey: ['scanDocuments', tenantId, jobId],
    queryFn: () => apiRequest(`/scan/${jobId}/documents`, { tenantId }),
    enabled: Boolean(jobId),
  });
}

export function useSystemSettings() {
  return useQuery({
    queryKey: ['systemSettings'],
    queryFn: () => apiRequest('/system/settings'),
    staleTime: 10000,
  });
}

export function useIntegrations() {
  const { tenantId } = useTenant();
  return useQuery({
    queryKey: ['integrations', tenantId],
    queryFn: () => apiRequest('/integrations', { tenantId }),
    staleTime: 5000,
  });
}

export function useSaveIntegration() {
  const { tenantId } = useTenant();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data) => apiRequest('/integrations', { method: 'POST', body: data, tenantId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations', tenantId] });
      queryClient.invalidateQueries({ queryKey: ['systemSettings'] });
    },
  });
}

export function useTestIntegration() {
  const { tenantId } = useTenant();
  return useMutation({
    mutationFn: (data) => apiRequest('/integrations/test', { method: 'POST', body: data, tenantId }),
  });
}


