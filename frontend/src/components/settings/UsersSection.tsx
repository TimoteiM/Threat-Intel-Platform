"use client";

/**
 * Adding and managing people, for administrators.
 *
 * A generated password is shown once, in the same spirit as a new API key: the
 * server stores only an scrypt hash, so there is no second chance to read it.
 * That is why it appears in a panel that has to be dismissed rather than a
 * toast that disappears on its own.
 *
 * The refusals from this API are worth reading rather than swallowing —
 * "cannot deactivate the only administrator" tells you what to do next — so
 * the server's own message is what gets shown.
 */

import React, { useCallback, useEffect, useState } from "react";
import * as api from "@/lib/api";
import { Banner } from "./AccountSection";
import { detailOf, fieldStyle, labelStyle, primaryButtonStyle, smallButtonStyle } from "./accessStyles";

export default function UsersSection() {
  const [users, setUsers] = useState<api.PlatformUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<{ username: string; password: string } | null>(null);
  const [adding, setAdding] = useState(false);

  const [username, setUsername] = useState("");
  const [role, setRole] = useState("analyst");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setUsers((await api.listUsers()).items);
      setError(null);
    } catch (err) {
      setError(detailOf(err, "Could not load the user list."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const act = async (run: () => Promise<unknown>, failure: string) => {
    setError(null);
    try {
      await run();
      await load();
    } catch (err) {
      setError(detailOf(err, failure));
    }
  };

  const create = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const created = await api.createUser({
        username: username.trim(),
        role,
        email: email.trim() || undefined,
        display_name: displayName.trim() || undefined,
      });
      if (created.password) setIssued({ username: created.username, password: created.password });
      setUsername("");
      setEmail("");
      setDisplayName("");
      setRole("analyst");
      setAdding(false);
      await load();
    } catch (err) {
      setError(detailOf(err, "Could not create that user."));
    } finally {
      setBusy(false);
    }
  };

  if (loading) return <p style={{ color: "var(--text-dim)", fontSize: 13 }}>Loading users…</p>;

  return (
    <div style={{ display: "grid", gap: 16 }}>
      {error && <Banner tone="danger">{error}</Banner>}

      {issued && (
        <div
          style={{
            border: "1px solid var(--status-warning)",
            borderRadius: "var(--radius)",
            padding: "12px 14px",
            display: "grid",
            gap: 8,
          }}
        >
          <strong style={{ fontSize: 13, color: "var(--text)" }}>
            Password for {issued.username}
          </strong>
          <code
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: 15,
              color: "var(--status-warning)",
              letterSpacing: 0.5,
              userSelect: "all",
              wordBreak: "break-all",
            }}
          >
            {issued.password}
          </code>
          <p style={{ fontSize: 11, color: "var(--text-dim)", margin: 0 }}>
            Give this to them now — only a hash is stored, so it cannot be shown again. They will be
            asked to change it when they first sign in.
          </p>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              type="button"
              onClick={() => navigator.clipboard?.writeText(issued.password)}
              style={smallButtonStyle()}
            >
              Copy
            </button>
            <button type="button" onClick={() => setIssued(null)} style={smallButtonStyle()}>
              Done
            </button>
          </div>
        </div>
      )}

      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
          <thead>
            <tr style={{ textAlign: "left", color: "var(--text-muted)", fontSize: 11 }}>
              <Th>User</Th>
              <Th>Role</Th>
              <Th>Signs in with</Th>
              <Th>Status</Th>
              <Th>Last sign-in</Th>
              <Th align="right">Actions</Th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id} style={{ borderTop: "1px solid var(--border)" }}>
                <Td>
                  <div style={{ color: "var(--text)", fontWeight: 600 }}>{user.username}</div>
                  {(user.display_name || user.email) && (
                    <div style={{ color: "var(--text-muted)", fontSize: 11 }}>
                      {user.display_name && user.email
                        ? `${user.display_name} · ${user.email}`
                        : user.display_name || user.email}
                    </div>
                  )}
                </Td>
                <Td>
                  <select
                    value={user.role}
                    onChange={(e) =>
                      act(() => api.updateUser(user.id, { role: e.target.value }), "Could not change that role.")
                    }
                    style={{ ...fieldStyle, padding: "4px 6px", fontSize: 12 }}
                    aria-label={`Role for ${user.username}`}
                  >
                    <option value="analyst">Analyst</option>
                    <option value="admin">Administrator</option>
                  </select>
                </Td>
                <Td>{user.auth_provider === "microsoft" ? "Microsoft" : "Password"}</Td>
                <Td>
                  <span style={{ color: user.active ? "var(--status-success)" : "var(--text-muted)" }}>
                    {user.active ? "Active" : "Disabled"}
                  </span>
                  {user.must_change_password && (
                    <div style={{ color: "var(--status-warning)", fontSize: 11 }}>
                      must change password
                    </div>
                  )}
                </Td>
                <Td>{formatWhen(user.last_login_at)}</Td>
                <Td align="right">
                  <div style={{ display: "flex", gap: 6, justifyContent: "flex-end", flexWrap: "wrap" }}>
                    <button
                      type="button"
                      onClick={() =>
                        act(
                          () => api.updateUser(user.id, { active: !user.active }),
                          "Could not change that account.",
                        )
                      }
                      style={smallButtonStyle()}
                    >
                      {user.active ? "Disable" : "Enable"}
                    </button>
                    {user.auth_provider !== "microsoft" && (
                      <button
                        type="button"
                        onClick={() =>
                          act(async () => {
                            const reset = await api.resetUserPassword(user.id);
                            if (reset.password) {
                              setIssued({ username: reset.username, password: reset.password });
                            }
                          }, "Could not reset that password.")
                        }
                        style={smallButtonStyle()}
                      >
                        Reset password
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => {
                        if (window.confirm(`Remove ${user.username}? This cannot be undone.`)) {
                          act(() => api.deleteUser(user.id), "Could not remove that user.");
                        }
                      }}
                      style={smallButtonStyle("danger")}
                    >
                      Remove
                    </button>
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {adding ? (
        <form
          onSubmit={create}
          style={{
            display: "grid",
            gap: 12,
            maxWidth: 420,
            borderTop: "1px solid var(--border)",
            paddingTop: 16,
          }}
        >
          <div style={{ display: "grid", gap: 6 }}>
            <label htmlFor="new-username" style={labelStyle}>Username</label>
            <input
              id="new-username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              maxLength={64}
              autoFocus
              style={fieldStyle}
            />
          </div>
          <div style={{ display: "grid", gap: 6 }}>
            <label htmlFor="new-display-name" style={labelStyle}>Full name (optional)</label>
            <input
              id="new-display-name"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              maxLength={120}
              style={fieldStyle}
            />
          </div>
          <div style={{ display: "grid", gap: 6 }}>
            <label htmlFor="new-email" style={labelStyle}>Email (optional)</label>
            <input
              id="new-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              maxLength={320}
              style={fieldStyle}
            />
            <span style={{ color: "var(--text-muted)", fontSize: 11 }}>
              Matching their work address links this account when Microsoft sign-in is switched on,
              rather than creating a second one.
            </span>
          </div>
          <div style={{ display: "grid", gap: 6 }}>
            <label htmlFor="new-role" style={labelStyle}>Role</label>
            <select id="new-role" value={role} onChange={(e) => setRole(e.target.value)} style={fieldStyle}>
              <option value="analyst">Analyst — use the platform</option>
              <option value="admin">Administrator — also manage users and keys</option>
            </select>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button type="submit" disabled={busy} style={primaryButtonStyle(busy)}>
              {busy ? "Creating…" : "Create user"}
            </button>
            <button type="button" onClick={() => setAdding(false)} style={smallButtonStyle()}>
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <button type="button" onClick={() => setAdding(true)} style={primaryButtonStyle(false)}>
          Add a user
        </button>
      )}
    </div>
  );
}

function Th({ children, align }: { children: React.ReactNode; align?: "right" }) {
  return (
    <th style={{ padding: "0 10px 8px", fontWeight: 600, textAlign: align || "left" }}>{children}</th>
  );
}

function Td({ children, align }: { children: React.ReactNode; align?: "right" }) {
  return (
    <td style={{ padding: "10px", color: "var(--text-secondary)", verticalAlign: "top", textAlign: align || "left" }}>
      {children}
    </td>
  );
}

function formatWhen(value?: string | null): string {
  if (!value) return "Never";
  const when = new Date(value);
  return Number.isNaN(when.getTime()) ? "—" : when.toLocaleString();
}
