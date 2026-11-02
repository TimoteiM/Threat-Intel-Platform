"use client";

/**
 * Who is signed in, in the sidebar footer, and the way out.
 *
 * It used to be a single truncated pill sharing a row with the collapse
 * toggle, the alerts bell and the version badge — legible only if you already
 * knew to look. It is now a proper account block: initials, name, role, and a
 * sign-out button, with the whole block linking to the account page.
 *
 * It renders nothing at all when nobody is signed in. During the `monitor`
 * rollout the platform still answers unauthenticated callers, and a name and a
 * "sign out" button for a session that does not exist would be a lie about the
 * state of the system.
 */

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import * as api from "@/lib/api";

export default function SessionControl({ collapsed }: { collapsed: boolean }) {
  const router = useRouter();
  const [me, setMe] = useState<api.Me | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .getMe()
      .then((who) => {
        if (!cancelled) setMe(who);
      })
      .catch(() => {
        /* a 401 here just means nobody is signed in; the page reports outages */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const signOut = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      router.replace("/login");
      router.refresh();
    }
  }, [router]);

  if (!me || me.kind !== "user") return null;

  const name = me.display_name || me.username || "Signed in";
  const role = api.roleLabel(me.role);
  const needsPassword = Boolean(me.must_change_password);
  const subtitle = needsPassword ? "Password change needed" : role;

  return (
    <div className="app-account">
      <Link
        href="/settings#account"
        className="app-account__who"
        title={`Signed in as ${name} — ${role}${needsPassword ? ". Password change needed." : ""}`}
      >
        <span
          className={`app-account__avatar${needsPassword ? " app-account__avatar--attention" : ""}`}
          aria-hidden="true"
        >
          {initialsOf(name)}
        </span>
        {!collapsed && (
          <span className="app-account__text">
            <span className="app-account__name">{name}</span>
            <span
              className={`app-account__role${needsPassword ? " app-account__role--attention" : ""}`}
            >
              {subtitle}
            </span>
          </span>
        )}
      </Link>

      <button
        type="button"
        onClick={signOut}
        className="app-account__signout"
        title="Sign out"
        aria-label={`Sign out of ${name}`}
      >
        <svg viewBox="0 0 24 24" aria-hidden="true" className="app-sidebar__icon">
          <path d="M15 4h3.5A1.5 1.5 0 0 1 20 5.5v13a1.5 1.5 0 0 1-1.5 1.5H15" />
          <path d="M10 8 6 12l4 4M6 12h9" />
        </svg>
      </button>
    </div>
  );
}

/**
 * Initials for the avatar.
 *
 * Two letters from a real name, one from a single-word username. Built from
 * the name actually shown, so the circle and the label never disagree.
 */
function initialsOf(name: string): string {
  const words = name.trim().split(/[\s._-]+/).filter(Boolean);
  if (words.length === 0) return "?";
  if (words.length === 1) return words[0].slice(0, 1).toUpperCase();
  return (words[0][0] + words[words.length - 1][0]).toUpperCase();
}
