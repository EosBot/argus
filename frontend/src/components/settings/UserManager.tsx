"use client";

import { useState } from "react";

export type UserRole = "admin" | "investigator" | "viewer";

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  lastActive?: Date;
  status: "active" | "inactive";
}

export interface UserManagerProps {
  users: User[];
  currentUserId: string;
  onAdd?: (user: Omit<User, "id" | "lastActive" | "status">) => Promise<string | void>;
  onUpdate?: (id: string, updates: Partial<User>) => Promise<void>;
  onDelete?: (id: string) => Promise<void>;
}

const ROLE_META: Record<UserRole, { label: string; color: string }> = {
  admin: { label: "Admin", color: "border-red-500/40 text-red-300 bg-red-500/10" },
  investigator: { label: "Investigator", color: "border-blue-500/40 text-blue-300 bg-blue-500/10" },
  viewer: { label: "Viewer", color: "border-zinc-500/40 text-zinc-300 bg-zinc-500/10" },
};

export default function UserManager({
  users,
  currentUserId,
  onAdd,
  onUpdate,
  onDelete,
}: UserManagerProps) {
  const [showAdd, setShowAdd] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [editEmail, setEditEmail] = useState("");
  const [editRole, setEditRole] = useState<UserRole>("investigator");
  const [newName, setNewName] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newRole, setNewRole] = useState<UserRole>("investigator");
  const [saving, setSaving] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [temporaryPassword, setTemporaryPassword] = useState<string | null>(null);

  const handleAdd = async () => {
    if (!newName.trim() || !newEmail.trim()) return;
    setSaving(true);
    setActionError(null);
    try {
      const password = await onAdd?.({ name: newName.trim(), email: newEmail.trim(), role: newRole });
      setTemporaryPassword(password || null);
      setNewName("");
      setNewEmail("");
      setNewRole("investigator");
      setShowAdd(false);
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Não foi possível criar o usuário.");
    } finally {
      setSaving(false);
    }
  };

  const startEdit = (user: User) => {
    setEditingId(user.id);
    setEditName(user.name);
    setEditEmail(user.email);
    setEditRole(user.role);
  };

  const saveEdit = async () => {
    if (!editingId || !editName.trim() || !editEmail.trim()) return;
    setSaving(true);
    setActionError(null);
    try {
      await onUpdate?.(editingId, { name: editName.trim(), email: editEmail.trim(), role: editRole });
      setEditingId(null);
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Não foi possível atualizar o usuário.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-[var(--text-primary)]">
            User Management
          </h3>
          <p className="mt-1 text-xs text-[var(--text-muted)]">
            Role-based access control for team members
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowAdd(!showAdd)}
          className="flex items-center gap-1.5 rounded-md bg-[var(--accent-primary)]/10 px-3 py-1.5 text-xs font-medium text-[var(--accent-primary)] hover:bg-[var(--accent-primary)]/20"
        >
          <span>+</span>
          Add User
        </button>
      </div>

      {temporaryPassword && (
        <div role="status" className="rounded-lg border border-amber-400/40 bg-amber-400/10 p-3">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="text-xs font-semibold text-amber-200">Credencial temporária — exibida uma única vez</p>
              <p className="mt-1 text-[10px] text-amber-100/70">Entregue por um canal seguro e solicite a troca no primeiro acesso.</p>
              <code className="mt-2 block select-all break-all rounded bg-black/30 px-2 py-1.5 font-mono text-xs text-amber-100">{temporaryPassword}</code>
            </div>
            <button type="button" onClick={() => setTemporaryPassword(null)} aria-label="Ocultar senha temporária" className="rounded px-2 py-1 text-xs text-amber-100 hover:bg-amber-300/10">Ocultar</button>
          </div>
        </div>
      )}

      {actionError && <p role="alert" className="rounded-md border border-red-400/30 bg-red-400/10 px-3 py-2 text-xs text-red-300">{actionError}</p>}

      {showAdd && (
        <div className="rounded-lg border border-[var(--accent-primary)]/30 bg-[var(--surface-2)] p-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label htmlFor="new-user-username" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                Username
              </label>
              <input
                id="new-user-username"
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] focus:border-[var(--accent-primary)] focus:outline-none"
                placeholder="john.doe"
                autoFocus
              />
            </div>
            <div>
              <label htmlFor="new-user-email" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                Email
              </label>
              <input
                id="new-user-email"
                type="email"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] focus:border-[var(--accent-primary)] focus:outline-none"
                placeholder="john@example.com"
              />
            </div>
            <div>
              <label htmlFor="new-user-role" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                Role
              </label>
              <select
                id="new-user-role"
                value={newRole}
                onChange={(e) => setNewRole(e.target.value as UserRole)}
                className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] focus:border-[var(--accent-primary)] focus:outline-none"
              >
                <option value="admin">Admin</option>
                <option value="investigator">Investigator</option>
                <option value="viewer">Viewer</option>
              </select>
            </div>
          </div>
          <div className="mt-3 flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setShowAdd(false)}
              className="rounded-md px-3 py-1.5 text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)]"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => void handleAdd()}
              disabled={saving || !newName.trim() || !newEmail.trim()}
              className="rounded-md bg-[var(--accent-primary)] px-3 py-1.5 text-xs font-medium text-[var(--text-on-accent)] hover:bg-[var(--accent-primary-dim)] disabled:opacity-50"
            >
              {saving ? "Creating…" : "Add User"}
            </button>
          </div>
        </div>
      )}

      <div className="space-y-1">
        {users.map((user) => {
          const role = ROLE_META[user.role];
          const isCurrentUser = user.id === currentUserId;
          const isEditing = editingId === user.id;

          if (isEditing) {
            return (
              <div
                key={user.id}
                className="rounded-lg border border-[var(--accent-primary)]/30 bg-[var(--surface-2)] p-3"
              >
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label htmlFor={`edit-user-name-${user.id}`} className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">Name</label>
                    <input
                      id={`edit-user-name-${user.id}`}
                      type="text"
                      value={editName}
                      onChange={(e) => setEditName(e.target.value)}
                      className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] focus:border-[var(--accent-primary)] focus:outline-none"
                    />
                  </div>
                  <div>
                    <label htmlFor={`edit-user-email-${user.id}`} className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">Email</label>
                    <input
                      id={`edit-user-email-${user.id}`}
                      type="email"
                      value={editEmail}
                      onChange={(e) => setEditEmail(e.target.value)}
                      className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] focus:border-[var(--accent-primary)] focus:outline-none"
                    />
                  </div>
                  <div>
                    <label htmlFor={`edit-user-role-${user.id}`} className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">Role</label>
                    <select
                      id={`edit-user-role-${user.id}`}
                      value={editRole}
                      onChange={(e) => setEditRole(e.target.value as UserRole)}
                      className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] focus:border-[var(--accent-primary)] focus:outline-none"
                    >
                      <option value="admin">Admin</option>
                      <option value="investigator">Investigator</option>
                      <option value="viewer">Viewer</option>
                    </select>
                  </div>
                </div>
                <div className="mt-3 flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setEditingId(null)}
                    className="rounded-md px-3 py-1.5 text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={() => void saveEdit()}
                    disabled={saving || !editName.trim() || !editEmail.trim()}
                    className="rounded-md bg-[var(--accent-primary)] px-3 py-1.5 text-xs font-medium text-[var(--text-on-accent)] hover:bg-[var(--accent-primary-dim)] disabled:opacity-50"
                  >
                    {saving ? "Saving…" : "Save"}
                  </button>
                </div>
              </div>
            );
          }

          return (
            <div
              key={user.id}
              className="flex items-center gap-3 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-2)] p-3"
            >
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-[var(--surface-3)] text-xs font-bold text-[var(--text-primary)]">
                {user.name.charAt(0).toUpperCase()}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-[var(--text-primary)]">
                    {user.name}
                  </span>
                  {isCurrentUser && (
                    <span className="text-[10px] text-[var(--accent-primary)]">(you)</span>
                  )}
                </div>
                <span className="text-[10px] text-[var(--text-muted)]">{user.email}</span>
              </div>
              <span className={`rounded-full border px-2 py-0.5 text-[10px] ${role.color}`}>
                {role.label}
              </span>
              <span
                className={`h-2 w-2 rounded-full ${
                  user.status === "active" ? "bg-emerald-400" : "bg-zinc-500"
                }`}
              />
              {!isCurrentUser && (
                <div className="flex gap-1">
                  <button
                    type="button"
                    onClick={() => startEdit(user)}
                    aria-label={`Editar usuário ${user.name}`}
                    className="rounded p-1 text-[var(--text-muted)] hover:bg-[var(--surface-3)] hover:text-[var(--text-primary)]"
                  >
                    <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.5">
                      <path d="M11.5 1.5l3 3L5 14H2v-3L11.5 1.5z" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      if (window.confirm(`Excluir o usuário ${user.name}? Esta ação não pode ser desfeita.`)) {
                        setSaving(true);
                        setActionError(null);
                        void onDelete?.(user.id).catch((cause) => {
                          setActionError(cause instanceof Error ? cause.message : "Não foi possível excluir o usuário.");
                        }).finally(() => setSaving(false));
                      }
                    }}
                    disabled={saving}
                    aria-label={`Excluir usuário ${user.name}`}
                    className="rounded p-1 text-red-400 hover:bg-red-400/10"
                  >
                    <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.5">
                      <path d="M2 4h12M5.333 4V2.667a1.333 1.333 0 011.334-1.334h2.666a1.333 1.333 0 011.334 1.334V4m2 0v8a1.333 1.333 0 01-1.334 1.334H4.667A1.333 1.333 0 013.333 12V4h9.334z" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </button>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
