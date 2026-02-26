"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  listClients,
  createClient,
  updateClient,
  deleteClient,
} from "@/lib/api";
import { CLASSIFICATION_CONFIG } from "@/lib/constants";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function timeAgo(dateStr?: string): string {
  if (!dateStr) return "—";
  const diff = Date.now() - new Date(dateStr).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function parseCsvInput(raw: string): string[] {
  return raw.split(",").map((s) => s.trim()).filter(Boolean);
}

// ─── Page ─────────────────────────────────────────────────────────────────────

const PAGE_LIMIT = 25;

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#f87171",
  high:     "#fb923c",
  medium:   "#fbbf24",
  low:      "#60a5fa",
};

export default function ClientsPage() {
  const router = useRouter();
  const [clients, setClients] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string | undefined>(undefined);
  const [showAdd, setShowAdd] = useState(false);

  // Add form
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [aliases, setAliases] = useState("");
  const [brandKeywords, setBrandKeywords] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [notes, setNotes] = useState("");
  const [adding, setAdding] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listClients({
        limit: PAGE_LIMIT,
        offset: page * PAGE_LIMIT,
        search: search || undefined,
        status: statusFilter,
      });
      setClients(data.items || []);
      setTotal(data.total || 0);
    } catch {
      setClients([]);
    } finally {
      setLoading(false);
    }
  }, [page, search, statusFilter]);

  useEffect(() => { load(); }, [load]);

  const handleAdd = async () => {
    if (!name.trim() || !domain.trim()) return;
    setAdding(true);
    try {
      await createClient({
        name: name.trim(),
        domain: domain.trim(),
        aliases: parseCsvInput(aliases),
        brand_keywords: parseCsvInput(brandKeywords),
        contact_email: contactEmail.trim() || undefined,
        notes: notes.trim() || undefined,
      });
      setName(""); setDomain(""); setAliases(""); setBrandKeywords("");
      setContactEmail(""); setNotes("");
      setShowAdd(false);
      setPage(0); load();
    } catch (e: any) {
      alert(`Failed to add client: ${e.message}`);
    } finally {
      setAdding(false);
    }
  };

  const handleToggleStatus = async (c: any) => {
    const newStatus = c.status === "active" ? "paused" : "active";
    try {
      await updateClient(c.id, { status: newStatus });
      load();
    } catch (e: any) {
      alert(`Failed: ${e.message}`);
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Delete client "${name}" and all their alerts?`)) return;
    try {
      await deleteClient(id);
      load();
    } catch (e: any) {
      alert(`Failed: ${e.message}`);
    }
  };

  const card: React.CSSProperties = {
    background: "var(--bg-card)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius-lg)",
    padding: 20,
  };

  const inputBase: React.CSSProperties = {
    width: "100%",
    padding: "10px 14px",
    background: "var(--bg-input)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius)",
    color: "var(--text)",
    fontSize: 13,
    fontFamily: "var(--font-mono)",
    outline: "none",
  };

  const totalPages = Math.ceil(total / PAGE_LIMIT);

  return (
    <div style={{ maxWidth: 1100, margin: "0 auto", padding: "32px 24px", paddingBottom: 60 }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, fontFamily: "var(--font-sans)", color: "var(--text)", margin: 0 }}>
            Clients
          </h1>
          <div style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-sans)", marginTop: 3 }}>
            Registered client organizations — monitor domains and brand keywords
          </div>
        </div>
        <button
          onClick={() => setShowAdd(!showAdd)}
          style={{
            padding: "10px 20px",
            background: showAdd ? "var(--bg-elevated)" : "linear-gradient(135deg, #60a5fa, #818cf8)",
            border: "none",
            borderRadius: "var(--radius)",
            color: showAdd ? "var(--text-dim)" : "#fff",
            fontSize: 13,
            fontWeight: 600,
            fontFamily: "var(--font-sans)",
            cursor: "pointer",
          }}
        >
          {showAdd ? "Cancel" : "+ Add Client"}
        </button>
      </div>

      {/* Add form */}
      {showAdd && (
        <div style={{ ...card, marginBottom: 24, border: "1px solid var(--accent)" }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: "var(--text-dim)", fontFamily: "var(--font-sans)", marginBottom: 14, letterSpacing: "0.04em", textTransform: "uppercase" }}>
            New Client
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div>
              <label style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)", display: "block", marginBottom: 4 }}>Organization Name *</label>
              <input style={inputBase} value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Corporation" />
            </div>
            <div>
              <label style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)", display: "block", marginBottom: 4 }}>Primary Domain *</label>
              <input style={inputBase} value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="acme.com" />
            </div>
            <div>
              <label style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)", display: "block", marginBottom: 4 }}>Aliases (comma-separated)</label>
              <input style={inputBase} value={aliases} onChange={(e) => setAliases(e.target.value)} placeholder="acme.org, acme.net" />
            </div>
            <div>
              <label style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)", display: "block", marginBottom: 4 }}>Brand Keywords (comma-separated)</label>
              <input style={inputBase} value={brandKeywords} onChange={(e) => setBrandKeywords(e.target.value)} placeholder="acme, acmecorp" />
            </div>
            <div>
              <label style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)", display: "block", marginBottom: 4 }}>Contact Email</label>
              <input style={inputBase} value={contactEmail} onChange={(e) => setContactEmail(e.target.value)} placeholder="soc@acme.com" type="email" />
            </div>
            <div>
              <label style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)", display: "block", marginBottom: 4 }}>Notes</label>
              <input style={inputBase} value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Optional notes..." />
            </div>
          </div>
          <button
            onClick={handleAdd}
            disabled={!name.trim() || !domain.trim() || adding}
            style={{
              marginTop: 14,
              padding: "10px 24px",
              background: (!name.trim() || !domain.trim() || adding) ? "var(--bg-elevated)" : "linear-gradient(135deg, #60a5fa, #818cf8)",
              border: "none",
              borderRadius: "var(--radius)",
              color: (!name.trim() || !domain.trim() || adding) ? "var(--text-muted)" : "#fff",
              fontSize: 13,
              fontWeight: 600,
              fontFamily: "var(--font-sans)",
              cursor: (!name.trim() || !domain.trim() || adding) ? "not-allowed" : "pointer",
            }}
          >
            {adding ? "Adding..." : "Add Client"}
          </button>
        </div>
      )}

      {/* Filters */}
      <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
        <input
          style={{ ...inputBase, maxWidth: 300 }}
          placeholder="Search by name or domain..."
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(0); }}
        />
        <select
          value={statusFilter ?? ""}
          onChange={(e) => { setStatusFilter(e.target.value || undefined); setPage(0); }}
          style={{ ...inputBase, maxWidth: 140, cursor: "pointer" }}
        >
          <option value="">All statuses</option>
          <option value="active">Active</option>
          <option value="paused">Paused</option>
        </select>
      </div>

      {/* Client list */}
      <div style={{ ...card }}>
        {loading ? (
          <div style={{ textAlign: "center", padding: 40, color: "var(--text-muted)", fontSize: 13, fontFamily: "var(--font-sans)" }}>
            Loading...
          </div>
        ) : clients.length === 0 ? (
          <div style={{ textAlign: "center", padding: 48 }}>
            <div style={{ fontSize: 32, marginBottom: 12 }}>🏢</div>
            <div style={{ fontSize: 14, color: "var(--text-dim)", fontFamily: "var(--font-sans)", fontWeight: 600 }}>No clients registered</div>
            <div style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-sans)", marginTop: 6 }}>
              Add client organizations to monitor their domains and brand keywords
            </div>
          </div>
        ) : (
          <div>
            {/* Table header */}
            <div style={{
              display: "grid",
              gridTemplateColumns: "1fr 180px 100px 100px 130px 160px",
              gap: 12,
              padding: "8px 14px",
              borderBottom: "1px solid var(--border)",
              fontSize: 10,
              color: "var(--text-muted)",
              fontFamily: "var(--font-sans)",
              fontWeight: 700,
              letterSpacing: "0.06em",
              textTransform: "uppercase",
            }}>
              <div>Client</div>
              <div>Domain</div>
              <div>Keywords</div>
              <div>Alerts</div>
              <div>Last Alert</div>
              <div>Actions</div>
            </div>

            {clients.map((c) => (
              <div
                key={c.id}
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 180px 100px 100px 130px 160px",
                  gap: 12,
                  padding: "14px 14px",
                  borderBottom: "1px solid var(--border-subtle, var(--border))",
                  alignItems: "center",
                  transition: "background 0.15s",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-elevated)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                {/* Name + status */}
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span
                      style={{ fontSize: 13, fontWeight: 600, color: "var(--text)", fontFamily: "var(--font-sans)", cursor: "pointer" }}
                      onClick={() => router.push(`/clients/${c.id}`)}
                    >
                      {c.name}
                    </span>
                    <span style={{
                      fontSize: 9,
                      fontWeight: 700,
                      padding: "2px 7px",
                      borderRadius: 999,
                      background: c.status === "active" ? "rgba(52,211,153,0.15)" : "rgba(148,163,184,0.15)",
                      color: c.status === "active" ? "#34d399" : "#94a3b8",
                      fontFamily: "var(--font-sans)",
                    }}>
                      {c.status.toUpperCase()}
                    </span>
                  </div>
                  {c.aliases?.length > 0 && (
                    <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2, fontFamily: "var(--font-mono)" }}>
                      +{c.aliases.length} alias{c.aliases.length > 1 ? "es" : ""}
                    </div>
                  )}
                </div>

                {/* Domain */}
                <div style={{ fontSize: 12, color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
                  {c.domain}
                </div>

                {/* Brand keywords count */}
                <div style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                  {c.brand_keywords?.length || 0} kw
                </div>

                {/* Alert count */}
                <div>
                  {c.alert_count > 0 ? (
                    <span
                      style={{
                        fontSize: 12,
                        fontWeight: 700,
                        color: SEVERITY_COLORS.critical,
                        fontFamily: "var(--font-mono)",
                        cursor: "pointer",
                      }}
                      onClick={() => router.push(`/clients/${c.id}?tab=alerts`)}
                    >
                      {c.alert_count} ⚠
                    </span>
                  ) : (
                    <span style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>—</span>
                  )}
                </div>

                {/* Last alert */}
                <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)" }}>
                  {timeAgo(c.last_alert_at)}
                </div>

                {/* Actions */}
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  <button
                    onClick={() => router.push(`/clients/${c.id}`)}
                    style={actionBtn("#60a5fa")}
                  >
                    View
                  </button>
                  <button
                    onClick={() => handleToggleStatus(c)}
                    style={actionBtn(c.status === "active" ? "#fbbf24" : "#34d399")}
                  >
                    {c.status === "active" ? "Pause" : "Resume"}
                  </button>
                  <button
                    onClick={() => handleDelete(c.id, c.name)}
                    style={actionBtn("#f87171")}
                  >
                    Del
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div style={{ display: "flex", gap: 8, justifyContent: "center", marginTop: 20 }}>
          {Array.from({ length: totalPages }, (_, i) => (
            <button
              key={i}
              onClick={() => setPage(i)}
              style={{
                padding: "6px 14px",
                background: i === page ? "var(--accent)" : "var(--bg-elevated)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                color: i === page ? "#fff" : "var(--text-dim)",
                fontSize: 12,
                fontFamily: "var(--font-sans)",
                cursor: "pointer",
              }}
            >
              {i + 1}
            </button>
          ))}
        </div>
      )}

      <div style={{ textAlign: "right", fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-sans)", marginTop: 10 }}>
        {total} client{total !== 1 ? "s" : ""} total
      </div>
    </div>
  );
}

function actionBtn(color: string): React.CSSProperties {
  return {
    padding: "4px 10px",
    background: "transparent",
    border: `1px solid ${color}33`,
    borderRadius: "var(--radius-sm)",
    color,
    fontSize: 11,
    fontFamily: "var(--font-sans)",
    fontWeight: 600,
    cursor: "pointer",
  };
}
