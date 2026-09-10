"use client";

/**
 * Primary navigation.
 *
 * Thirteen destinations in a horizontal bar forced every label to fight for
 * width, and gave no room to say what a destination *is*. Down the left they
 * get a full label, an icon, and a section heading that tells the analyst
 * which part of the job they are in.
 *
 * The rail is `position: fixed`, and `.app-shell__content` carries a matching
 * `margin-left`, so no page body knows the sidebar exists — the whole app
 * still renders into `.app-shell__main` exactly as it did under the top bar.
 */

import React from "react";
import { usePathname } from "next/navigation";
import {
  APP_BRAND,
  APP_NAV_LINKS,
  APP_NAV_SECTIONS,
  APP_SUBTITLE,
  APP_VERSION,
  type AppNavLink,
} from "@/lib/constants";
import BrandMark from "@/components/layout/BrandMark";
import CorrelationAlerts from "@/components/layout/CorrelationAlerts";
import NavIcon from "@/components/layout/NavIcons";

const STORAGE_KEY = "ta.sidebar.collapsed";

export default function Sidebar({
  collapsed,
  onToggle,
}: {
  collapsed: boolean;
  onToggle: () => void;
}) {
  const pathname = usePathname();
  const links = APP_NAV_LINKS as readonly AppNavLink[];

  return (
    <aside
      className={`app-sidebar${collapsed ? " app-sidebar--collapsed" : ""}`}
      aria-label="Primary"
    >
      <div className="app-sidebar__head">
        <a
          href="/"
          className="app-brand"
          aria-label={APP_BRAND}
          title={collapsed ? APP_BRAND : undefined}
        >
          <BrandMark />
          {!collapsed && (
            <div className="app-brand__copy">
              <div className="app-brand__title">{APP_BRAND}</div>
              <div className="app-brand__subtitle">{APP_SUBTITLE}</div>
            </div>
          )}
        </a>
      </div>

      <nav className="app-sidebar__nav">
        {APP_NAV_SECTIONS.map((section) => {
          const items = links.filter((link) => link.group === section.id);
          if (!items.length) return null;
          return (
            <div className="app-sidebar__section" key={section.id}>
              <div className="app-sidebar__caption" aria-hidden={collapsed || undefined}>
                {section.title}
              </div>
              {items.map((link) => {
                const active = isActive(pathname, link.href);
                return (
                  <a
                    key={link.href}
                    href={link.href}
                    className={`app-sidebar__link${active ? " app-sidebar__link--active" : ""}`}
                    aria-current={active ? "page" : undefined}
                    title={collapsed ? link.label : undefined}
                  >
                    {link.icon ? <NavIcon name={link.icon} /> : null}
                    <span className="app-sidebar__label">{link.label}</span>
                  </a>
                );
              })}
            </div>
          );
        })}
      </nav>

      <div className="app-sidebar__foot">
        <button
          type="button"
          className="app-sidebar__toggle"
          onClick={onToggle}
          aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
          title={collapsed ? "Expand navigation" : "Collapse navigation"}
        >
          <svg className="app-sidebar__icon" viewBox="0 0 24 24" aria-hidden="true">
            <path d={collapsed ? "m9 6 6 6-6 6" : "m15 6-6 6 6 6"} />
          </svg>
        </button>
        <CorrelationAlerts />
        <span className="app-sidebar__version">{APP_VERSION}</span>
      </div>
    </aside>
  );
}

/** Read the persisted collapse state without a flash of the wrong width. */
export function readCollapsed(): boolean {
  try {
    return window.localStorage.getItem(STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

export function writeCollapsed(value: boolean) {
  try {
    window.localStorage.setItem(STORAGE_KEY, value ? "1" : "0");
  } catch {
    /* private browsing, blocked site data — the rail just forgets. */
  }
}

function isActive(pathname: string | null, href: string): boolean {
  if (!pathname) return false;
  if (href === "/") return pathname === "/";
  return pathname === href || pathname.startsWith(`${href}/`);
}
