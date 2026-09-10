"use client";

/**
 * The application frame: a fixed rail, and a content column that carries the
 * page.
 *
 * This is the only component that knows the sidebar's collapsed state. Pages
 * render into `.app-shell__main` unchanged, exactly as they did when the
 * navigation was a top bar.
 */

import React, { useEffect, useState } from "react";
import Sidebar, { readCollapsed, writeCollapsed } from "@/components/layout/Sidebar";
import Footer from "@/components/layout/Footer";
import RouteProgress from "@/components/layout/RouteProgress";

/** Below this, a 220px rail costs more room than it earns. */
const NARROW_VIEWPORT = 1100;
const STORAGE_KEY = "ta.sidebar.collapsed";

export default function AppShell({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);

  // Server-rendered markup is always the expanded rail, so the stored choice
  // is applied on mount rather than during render — reading localStorage in a
  // state initialiser would make the server and client disagree.
  useEffect(() => {
    let stored: string | null = null;
    try {
      stored = window.localStorage.getItem(STORAGE_KEY);
    } catch {
      /* blocked site data: fall through to the width default */
    }
    if (stored === null) {
      setCollapsed(window.innerWidth < NARROW_VIEWPORT);
      return;
    }
    setCollapsed(readCollapsed());
  }, []);

  const toggle = () => {
    setCollapsed((previous) => {
      writeCollapsed(!previous);
      return !previous;
    });
  };

  return (
    <div className={`app-shell${collapsed ? " app-shell--collapsed" : ""}`}>
      <Sidebar collapsed={collapsed} onToggle={toggle} />
      <div className="app-shell__content">
        <RouteProgress />
        <main className="app-shell__main">{children}</main>
        <Footer />
      </div>
    </div>
  );
}
