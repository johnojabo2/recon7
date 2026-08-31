import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Users,
  Shield,
  ShieldAlert,
  ShieldCheck,
  UserPlus,
  KeyRound,
  Lock,
  Mail,
  User,
  Building,
  Check,
  X,
  AlertOctagon,
  RefreshCw,
  Search,
  CheckCircle2,
  XCircle,
  Edit2,
  Trash2,
  Layers,
} from 'lucide-react';
import { apiRequest } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { useTenants } from '../api/hooks';
import { LoadingState, EmptyState } from '../components/LoadingState';

export default function IamManagementView() {
  const { user: currentUser } = useAuth();
  const queryClient = useQueryClient();
  const [searchTerm, setSearchTerm] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingUser, setEditingUser] = useState(null);
  const [resettingUser, setResettingUser] = useState(null);

  // Queries
  const { data: users = [], isLoading: usersLoading, refetch } = useQuery({
    queryKey: ['iamUsers'],
    queryFn: () => apiRequest('/iam/users'),
  });

  const { data: tenants = [] } = useTenants();

  // Create User Mutation
  const createUserMutation = useMutation({
    mutationFn: (userData) => apiRequest('/iam/users', { method: 'POST', body: userData }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['iamUsers'] });
      setShowCreateModal(false);
    },
  });

  // Update User Mutation
  const updateUserMutation = useMutation({
    mutationFn: ({ userId, data }) => apiRequest(`/iam/users/${userId}`, { method: 'PUT', body: data }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['iamUsers'] });
      setEditingUser(null);
    },
  });

  // Reset Password Mutation
  const resetPasswordMutation = useMutation({
    mutationFn: ({ userId, newPassword }) =>
      apiRequest(`/iam/users/${userId}/reset-password`, { method: 'POST', body: { new_password: newPassword } }),
    onSuccess: () => {
      setResettingUser(null);
    },
  });

  // Toggle Active/Suspended
  const handleToggleStatus = async (targetUser) => {
    if (targetUser.id === currentUser?.id) {
      alert('You cannot suspend your own active administrator account.');
      return;
    }
    const newStatus = !targetUser.is_active;
    const confirmMsg = newStatus
      ? `Re-activate operator account for ${targetUser.email}?`
      : `Suspend operator account for ${targetUser.email}? They will be immediately blocked from accessing the system.`;

    if (window.confirm(confirmMsg)) {
      updateUserMutation.mutate({ userId: targetUser.id, data: { is_active: newStatus } });
    }
  };

  const filteredUsers = users.filter((u) => {
    const q = searchTerm.toLowerCase();
    return (
      u.email.toLowerCase().includes(q) ||
      (u.full_name && u.full_name.toLowerCase().includes(q)) ||
      u.role.toLowerCase().includes(q)
    );
  });

  if (currentUser?.role !== 'system_admin') {
    return (
      <EmptyState
        title="Access Restricted"
        message="Enterprise IAM and Operator Access Control is restricted to System Administrators."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-6 rounded-lg panel-glass border border-border-dim shadow-panel bg-panel">
        <div>
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-signal" />
            <h1 className="font-display font-bold text-xl text-text-primary">
              Identity & Access Management (IAM)
            </h1>
          </div>
          <p className="text-xs text-text-dim mt-1">
            Provision security personnel, assign role-based access control (RBAC), and partition organization tenant permissions.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 px-3 py-2 rounded-md bg-void border border-border-dim hover:border-cyan-signal/50 text-text-dim hover:text-cyan-signal font-mono text-xs transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-md bg-cyan-signal text-black font-semibold text-xs tracking-wide shadow-glow-cyan-sm hover:brightness-110 active:scale-[0.98] transition-all shrink-0 font-mono"
          >
            <UserPlus className="w-4 h-4" />
            <span>PROVISION OPERATOR</span>
          </button>
        </div>
      </div>

      {/* Filter / Search Bar */}
      <div className="flex items-center gap-3 p-3 rounded-lg panel-glass border border-border-dim bg-panel">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-dim" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Filter operators by name, email, or role..."
            className="w-full pl-9 pr-3 py-1.5 rounded bg-void border border-border-dim focus:border-cyan-signal text-xs font-mono text-text-primary outline-none transition-all"
          />
        </div>
        <div className="text-xs font-mono text-text-dim px-2">
          Total Users: <strong className="text-text-primary">{users.length}</strong>
        </div>
      </div>

      {/* Users Ledger Table */}
      <div className="panel-glass rounded-lg border border-border-dim overflow-hidden shadow-panel bg-panel">
        {usersLoading ? (
          <LoadingState message="Loading IAM user registry..." />
        ) : filteredUsers.length === 0 ? (
          <div className="py-16 text-center text-xs text-text-dim font-mono">
            No operator accounts matched your search criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-border-dim bg-panel-elevated text-text-dim text-[11px] uppercase tracking-wider">
                  <th className="py-3 px-4">Operator / Email</th>
                  <th className="py-3 px-4">Role</th>
                  <th className="py-3 px-4">Authorized Tenants</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Provisioned</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-dim/60">
                {filteredUsers.map((u) => {
                  const isCurrent = u.id === currentUser?.id;
                  const isGlobalAdmin = u.role === 'system_admin' || (u.allowed_tenants && u.allowed_tenants.includes('*'));

                  return (
                    <tr key={u.id} className="hover:bg-panel-subtle transition-colors">
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-2.5">
                          <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold ${
                            u.role === 'system_admin'
                              ? 'bg-magenta-alert/20 text-magenta-alert border border-magenta-alert/40'
                              : 'bg-cyan-signal/10 text-cyan-signal border border-cyan-signal/30'
                          }`}>
                            {u.full_name ? u.full_name.charAt(0).toUpperCase() : u.email.charAt(0).toUpperCase()}
                          </div>
                          <div>
                            <div className="font-semibold text-text-primary flex items-center gap-1.5">
                              <span>{u.full_name || 'Operator'}</span>
                              {isCurrent && (
                                <span className="px-1.5 py-0.2 rounded bg-cyan-signal/15 text-cyan-signal border border-cyan-signal/30 text-[9px] uppercase font-bold">
                                  You
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] text-text-dim select-all">{u.email}</div>
                          </div>
                        </div>
                      </td>

                      <td className="py-3.5 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                          u.role === 'system_admin'
                            ? 'bg-magenta-alert/15 text-magenta-alert border-magenta-alert/40'
                            : u.role === 'operator'
                            ? 'bg-cyan-signal/15 text-cyan-signal border-cyan-signal/40'
                            : 'bg-void text-text-dim border-border-dim'
                        }`}>
                          {u.role.toUpperCase()}
                        </span>
                      </td>

                      <td className="py-3.5 px-4">
                        {isGlobalAdmin ? (
                          <span className="px-2 py-0.5 rounded bg-magenta-alert/10 text-magenta-alert border border-magenta-alert/30 text-[10px] font-bold">
                            ★ ALL TENANTS (GLOBAL)
                          </span>
                        ) : (
                          <div className="flex flex-wrap gap-1 max-w-xs">
                            {u.allowed_tenants && u.allowed_tenants.length > 0 ? (
                              u.allowed_tenants.map((tId, idx) => {
                                const tObj = tenants.find((t) => t.id === tId);
                                return (
                                  <span
                                    key={idx}
                                    className="px-1.5 py-0.5 rounded bg-panel-elevated border border-border-dim text-[10px] text-text-primary truncate max-w-[140px]"
                                    title={tObj ? tObj.name : tId}
                                  >
                                    {tObj ? tObj.name : tId.substring(0, 8)}
                                  </span>
                                );
                              })
                            ) : (
                              <span className="text-text-dim text-[10px]">None Assigned</span>
                            )}
                          </div>
                        )}
                      </td>

                      <td className="py-3.5 px-4">
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                          u.is_active
                            ? 'bg-success-green/15 text-success-green border-success-green/40'
                            : 'bg-void text-text-dim border-border-dim'
                        }`}>
                          {u.is_active ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                          <span>{u.is_active ? 'ACTIVE' : 'SUSPENDED'}</span>
                        </span>
                      </td>

                      <td className="py-3.5 px-4 text-text-dim text-[11px]">
                        <div>{u.created_at ? new Date(u.created_at).toLocaleDateString() : 'N/A'}</div>
                        <div className="text-[9px] text-text-dim/70">by {u.created_by || 'system'}</div>
                      </td>

                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => setEditingUser(u)}
                            className="p-1.5 rounded hover:bg-void text-text-dim hover:text-cyan-signal border border-transparent hover:border-border-dim transition-colors"
                            title="Edit Permissions & Tenants"
                          >
                            <Edit2 className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => setResettingUser(u)}
                            className="p-1.5 rounded hover:bg-void text-text-dim hover:text-amber-400 border border-transparent hover:border-border-dim transition-colors"
                            title="Reset Operator Password"
                          >
                            <KeyRound className="w-3.5 h-3.5" />
                          </button>
                          {!isCurrent && (
                            <button
                              onClick={() => handleToggleStatus(u)}
                              className={`p-1.5 rounded border border-transparent transition-colors ${
                                u.is_active
                                  ? 'hover:bg-magenta-alert/15 text-text-dim hover:text-magenta-alert hover:border-magenta-alert/40'
                                  : 'hover:bg-success-green/15 text-text-dim hover:text-success-green hover:border-success-green/40'
                              }`}
                              title={u.is_active ? 'Suspend Operator' : 'Reactivate Operator'}
                            >
                              {u.is_active ? <XCircle className="w-3.5 h-3.5" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* PROVISION USER MODAL */}
      {showCreateModal && (
        <ProvisionOperatorModal
          tenants={tenants}
          onClose={() => setShowCreateModal(false)}
          onSubmit={(data) => createUserMutation.mutate(data)}
          isLoading={createUserMutation.isPending}
          error={createUserMutation.error}
        />
      )}

      {/* EDIT PERMISSIONS MODAL */}
      {editingUser && (
        <EditPermissionsModal
          user={editingUser}
          currentUser={currentUser}
          tenants={tenants}
          onClose={() => setEditingUser(null)}
          onSubmit={(data) => updateUserMutation.mutate({ userId: editingUser.id, data })}
          isLoading={updateUserMutation.isPending}
          error={updateUserMutation.error}
        />
      )}

      {/* RESET PASSWORD MODAL */}
      {resettingUser && (
        <ResetPasswordModal
          user={resettingUser}
          onClose={() => setResettingUser(null)}
          onSubmit={(newPassword) => resetPasswordMutation.mutate({ userId: resettingUser.id, newPassword })}
          isLoading={resetPasswordMutation.isPending}
          isSuccess={resetPasswordMutation.isSuccess}
        />
      )}
    </div>
  );
}

// ----------------------------------------------------------------------
// Provision Operator Modal
// ----------------------------------------------------------------------
function ProvisionOperatorModal({ tenants, onClose, onSubmit, isLoading, error }) {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('operator');
  const [primaryTenant, setPrimaryTenant] = useState(tenants[0]?.id || '');
  const [selectedTenants, setSelectedTenants] = useState([tenants[0]?.id || '']);

  const handleTenantToggle = (tId) => {
    if (selectedTenants.includes(tId)) {
      if (selectedTenants.length === 1) return; // Must keep at least one
      setSelectedTenants(selectedTenants.filter((id) => id !== tId));
    } else {
      setSelectedTenants([...selectedTenants, tId]);
    }
  };

  const handleGeneratePassword = () => {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*';
    let pwd = '';
    for (let i = 0; i < 16; i++) {
      pwd += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    setPassword(pwd);
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) return;

    onSubmit({
      full_name: fullName.trim() || undefined,
      email: email.trim(),
      password,
      role,
      tenant_id: primaryTenant || tenants[0]?.id,
      allowed_tenants: role === 'system_admin' ? ['*'] : selectedTenants,
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in font-mono">
      <div className="relative w-full max-w-lg rounded-xl panel-glass border border-border-dim p-6 shadow-2xl space-y-5 bg-panel">
        <div className="flex items-center justify-between border-b border-border-dim pb-3">
          <div className="flex items-center gap-2">
            <UserPlus className="w-5 h-5 text-cyan-signal" />
            <h3 className="font-bold text-sm text-text-primary">Provision New Operator</h3>
          </div>
          <button onClick={onClose} className="text-text-dim hover:text-text-primary">
            <X className="w-4 h-4" />
          </button>
        </div>

        {error && (
          <div className="p-3 rounded bg-magenta-alert/15 border border-magenta-alert/40 text-magenta-alert text-xs flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 shrink-0" />
            <span>{error.message || 'Failed to provision operator.'}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-3.5 text-xs">
          <div>
            <label className="block uppercase text-[10px] font-bold text-text-dim mb-1">
              Operator Full Name
            </label>
            <input
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              placeholder="e.g. Alex Rivera"
              className="w-full px-3 py-2 rounded bg-void border border-border-dim focus:border-cyan-signal text-text-primary outline-none"
            />
          </div>

          <div>
            <label className="block uppercase text-[10px] font-bold text-text-dim mb-1">
              Work Email Address *
            </label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="operator@enterprise.com"
              className="w-full px-3 py-2 rounded bg-void border border-border-dim focus:border-cyan-signal text-text-primary outline-none"
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="uppercase text-[10px] font-bold text-text-dim">
                Initial Password *
              </label>
              <button
                type="button"
                onClick={handleGeneratePassword}
                className="text-[10px] text-cyan-signal hover:underline flex items-center gap-1"
              >
                <KeyRound className="w-3 h-3" />
                <span>Generate Random</span>
              </button>
            </div>
            <input
              type="text"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Min 8 characters"
              className="w-full px-3 py-2 rounded bg-void border border-border-dim focus:border-cyan-signal text-text-primary outline-none font-mono"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block uppercase text-[10px] font-bold text-text-dim mb-1">
                System Role
              </label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className="w-full px-3 py-2 rounded bg-void border border-border-dim focus:border-cyan-signal text-text-primary outline-none"
              >
                <option value="operator">OPERATOR (Scans & Recon)</option>
                <option value="auditor">AUDITOR (Read-Only Reports)</option>
                <option value="system_admin">SYSTEM_ADMIN (Master Control)</option>
              </select>
            </div>

            <div>
              <label className="block uppercase text-[10px] font-bold text-text-dim mb-1">
                Primary Organization
              </label>
              <select
                value={primaryTenant}
                onChange={(e) => setPrimaryTenant(e.target.value)}
                className="w-full px-3 py-2 rounded bg-void border border-border-dim focus:border-cyan-signal text-text-primary outline-none"
              >
                {tenants.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Tenant Permission Assignment Checkboxes */}
          {role !== 'system_admin' && (
            <div className="space-y-1.5 pt-1">
              <label className="block uppercase text-[10px] font-bold text-text-dim">
                Authorized Tenant Workspaces (Multi-Tenant RBAC)
              </label>
              <div className="p-2.5 rounded bg-void border border-border-dim space-y-1.5 max-h-32 overflow-y-auto">
                {tenants.map((t) => (
                  <label key={t.id} className="flex items-center gap-2 cursor-pointer text-xs text-text-primary hover:text-cyan-signal">
                    <input
                      type="checkbox"
                      checked={selectedTenants.includes(t.id)}
                      onChange={() => handleTenantToggle(t.id)}
                      className="rounded border-border-dim bg-panel"
                    />
                    <span>{t.name}</span>
                  </label>
                ))}
              </div>
            </div>
          )}

          <div className="pt-3 flex justify-end gap-2 border-t border-border-dim">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded bg-void border border-border-dim text-text-dim hover:text-text-primary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading}
              className="px-4 py-2 rounded bg-cyan-signal text-black font-semibold tracking-wide hover:brightness-110 disabled:opacity-50"
            >
              {isLoading ? 'PROVISIONING...' : 'PROVISION OPERATOR'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------
// Edit Permissions Modal
// ----------------------------------------------------------------------
function EditPermissionsModal({ user, currentUser, tenants, onClose, onSubmit, isLoading, error }) {
  const isSelf = user.id === currentUser?.id;
  const [role, setRole] = useState(user.role);
  const [selectedTenants, setSelectedTenants] = useState(
    user.allowed_tenants && user.allowed_tenants.includes('*')
      ? tenants.map((t) => t.id)
      : user.allowed_tenants || [user.tenant_id]
  );

  const handleTenantToggle = (tId) => {
    if (selectedTenants.includes(tId)) {
      if (selectedTenants.length === 1) return;
      setSelectedTenants(selectedTenants.filter((id) => id !== tId));
    } else {
      setSelectedTenants([...selectedTenants, tId]);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    onSubmit({
      role: isSelf ? 'system_admin' : role,
      allowed_tenants: (isSelf || role === 'system_admin') ? ['*'] : selectedTenants,
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in font-mono">
      <div className="relative w-full max-w-md rounded-xl panel-glass border border-border-dim p-6 shadow-2xl space-y-4 bg-panel">
        <div className="flex items-center justify-between border-b border-border-dim pb-3">
          <div className="flex items-center gap-2">
            <Edit2 className="w-4 h-4 text-cyan-signal" />
            <h3 className="font-bold text-sm text-text-primary">Edit Operator Access</h3>
          </div>
          <button onClick={onClose} className="text-text-dim hover:text-text-primary">
            <X className="w-4 h-4" />
          </button>
        </div>

        {error && (
          <div className="p-3 rounded bg-magenta-alert/15 border border-magenta-alert/40 text-magenta-alert text-xs flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 shrink-0" />
            <span>{error.message || 'Failed to update user permissions.'}</span>
          </div>
        )}

        <div className="text-xs text-text-dim">
          Configuring permissions for <strong className="text-text-primary">{user.email}</strong>
          {isSelf && (
            <span className="ml-2 px-1.5 py-0.2 rounded bg-cyan-signal/15 text-cyan-signal text-[9px] uppercase font-bold">
              Your Account
            </span>
          )}
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block uppercase text-[10px] font-bold text-text-dim mb-1">
              Role Assignment
            </label>
            <select
              value={isSelf ? 'system_admin' : role}
              disabled={isSelf}
              onChange={(e) => setRole(e.target.value)}
              className="w-full px-3 py-2 rounded bg-void border border-border-dim focus:border-cyan-signal text-text-primary outline-none disabled:opacity-75 disabled:cursor-not-allowed"
            >
              <option value="operator">OPERATOR</option>
              <option value="auditor">AUDITOR</option>
              <option value="system_admin">SYSTEM_ADMIN (Master Control)</option>
            </select>
            {isSelf && (
              <p className="text-[10px] text-amber-400 mt-1 font-mono">
                🛡️ Self-demotion locked: You cannot revoke your own Administrator role to prevent lockout.
              </p>
            )}
          </div>

          {!isSelf && role !== 'system_admin' && (
            <div className="space-y-1.5">
              <label className="block uppercase text-[10px] font-bold text-text-dim">
                Permitted Tenant Workspaces
              </label>
              <div className="p-2.5 rounded bg-void border border-border-dim space-y-1.5 max-h-36 overflow-y-auto">
                {tenants.map((t) => (
                  <label key={t.id} className="flex items-center gap-2 cursor-pointer text-xs text-text-primary hover:text-cyan-signal">
                    <input
                      type="checkbox"
                      checked={selectedTenants.includes(t.id)}
                      onChange={() => handleTenantToggle(t.id)}
                      className="rounded border-border-dim bg-panel"
                    />
                    <span>{t.name}</span>
                  </label>
                ))}
              </div>
            </div>
          )}

          <div className="pt-3 flex justify-end gap-2 border-t border-border-dim">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded bg-void border border-border-dim text-text-dim hover:text-text-primary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading}
              className="px-4 py-2 rounded bg-cyan-signal text-black font-semibold hover:brightness-110 disabled:opacity-50"
            >
              {isLoading ? 'SAVING...' : 'SAVE PERMISSIONS'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------
// Reset Password Modal
// ----------------------------------------------------------------------
function ResetPasswordModal({ user, onClose, onSubmit, isLoading, isSuccess }) {
  const [newPassword, setNewPassword] = useState('');

  const handleGenerate = () => {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*';
    let pwd = '';
    for (let i = 0; i < 16; i++) {
      pwd += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    setNewPassword(pwd);
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (newPassword.length < 8) return;
    onSubmit(newPassword);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in font-mono">
      <div className="relative w-full max-w-md rounded-xl panel-glass border border-border-dim p-6 shadow-2xl space-y-4 bg-panel">
        <div className="flex items-center justify-between border-b border-border-dim pb-3">
          <div className="flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-amber-400" />
            <h3 className="font-bold text-sm text-text-primary">Reset Operator Password</h3>
          </div>
          <button onClick={onClose} className="text-text-dim hover:text-text-primary">
            <X className="w-4 h-4" />
          </button>
        </div>

        {isSuccess ? (
          <div className="py-4 text-center space-y-3">
            <CheckCircle2 className="w-10 h-10 text-success-green mx-auto" />
            <p className="text-xs text-text-primary font-bold">
              Password successfully reset for {user.email}!
            </p>
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded bg-cyan-signal text-black font-semibold text-xs"
            >
              Done
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4 text-xs">
            <p className="text-text-dim">
              Provide a new permanent password for <strong className="text-text-primary">{user.email}</strong>.
            </p>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="uppercase text-[10px] font-bold text-text-dim">New Password</label>
                <button
                  type="button"
                  onClick={handleGenerate}
                  className="text-[10px] text-cyan-signal hover:underline"
                >
                  Generate Random
                </button>
              </div>
              <input
                type="text"
                required
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Min 8 characters"
                className="w-full px-3 py-2 rounded bg-void border border-border-dim focus:border-cyan-signal text-text-primary outline-none font-mono"
              />
            </div>

            <div className="pt-3 flex justify-end gap-2 border-t border-border-dim">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 rounded bg-void border border-border-dim text-text-dim hover:text-text-primary"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isLoading || newPassword.length < 8}
                className="px-4 py-2 rounded bg-amber-400 text-black font-semibold hover:brightness-110 disabled:opacity-50"
              >
                {isLoading ? 'RESETTING...' : 'CONFIRM PASSWORD RESET'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
