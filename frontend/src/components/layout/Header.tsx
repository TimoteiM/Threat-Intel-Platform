"use client";

import React from "react";
import { usePathname } from "next/navigation";
import { APP_BRAND, APP_NAV_LINKS, APP_SUBTITLE, APP_VERSION, type AppNavLink } from "@/lib/constants";
import BrandMark from "@/components/layout/BrandMark";
import CorrelationAlerts from "@/components/layout/CorrelationAlerts";

// Thirteen links in one flat row reads as noise, not navigation — this groups
// them into the clusters an analyst actually thinks in (the daily workflow,
// what's being watched, what comes in as raw text, everything else), with a
// hairline between clusters instead of nothing standing between any two.
export default function Header() {
  const pathname = usePathname();
  const groups = groupLinks(APP_NAV_LINKS as readonly AppNavLink[]);

  return (
    <header className="app-header">
      <div className="app-header__inner">
        <a href="/" className="app-brand" aria-label={APP_BRAND}>
          <BrandMark />
          <div className="app-brand__copy">
            <div className="app-brand__title">{APP_BRAND}</div>
            <div className="app-brand__subtitle">{APP_SUBTITLE}</div>
          </div>
        </a>

        <nav className="app-nav" aria-label="Primary">
          {groups.map((group, index) => (
            <React.Fragment key={group[0]?.href ?? index}>
              {index > 0 ? <span className="app-nav__divider" aria-hidden="true" /> : null}
              <div className="app-nav__group">
                {group.map((link) => (
                  <NavLink key={link.href} href={link.href} active={isActive(pathname, link.href)}>
                    {link.label}
                  </NavLink>
                ))}
              </div>
            </React.Fragment>
          ))}
          <span className="app-nav__divider" aria-hidden="true" />
          <CorrelationAlerts />
          <span className="app-nav__badge">{APP_VERSION}</span>
        </nav>
      </div>
    </header>
  );
}

function groupLinks(links: readonly AppNavLink[]): AppNavLink[][] {
  const order: NonNullable<AppNavLink["group"]>[] = ["work", "monitor", "intake", "reach", "system"];
  return order
    .map((group) => links.filter((link) => link.group === group))
    .filter((group) => group.length > 0);
}

function isActive(pathname: string | null, href: string): boolean {
  if (!pathname) return false;
  if (href === "/") return pathname === "/";
  return pathname === href || pathname.startsWith(`${href}/`);
}

function NavLink({ href, active, children }: { href: string; active: boolean; children: React.ReactNode }) {
  return (
    <a
      href={href}
      className={`app-nav__link${active ? " app-nav__link--active" : ""}`}
      aria-current={active ? "page" : undefined}
    >
      {children}
    </a>
  );
}
