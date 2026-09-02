"use client";

import React from "react";
import { APP_BRAND, APP_NAV_LINKS, APP_SUBTITLE, APP_VERSION } from "@/lib/constants";
import BrandMark from "@/components/layout/BrandMark";
import CorrelationAlerts from "@/components/layout/CorrelationAlerts";

export default function Header() {
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
          {APP_NAV_LINKS.map((link) => (
            <NavLink key={link.href} href={link.href}>
              {link.label}
            </NavLink>
          ))}
          <CorrelationAlerts />
          <span className="app-nav__badge">{APP_VERSION}</span>
        </nav>
      </div>
    </header>
  );
}

function NavLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a href={href} className="app-nav__link">
      {children}
    </a>
  );
}
