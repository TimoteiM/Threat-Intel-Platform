"use client";

import React from "react";
import {
  APP_BRAND,
  APP_FOOTER_LINK_GROUPS,
  APP_SUBTITLE,
  APP_VERSION,
} from "@/lib/constants";
import BrandMark from "@/components/layout/BrandMark";

const YEAR = 2026;

export default function Footer() {
  return (
    <footer className="app-footer">
      <div className="app-footer__inner">
        <div className="app-footer__grid">
          <div className="app-footer__brand">
            <div className="app-brand" aria-label={APP_BRAND}>
              <BrandMark />
              <div className="app-brand__copy">
                <div className="app-brand__title">{APP_BRAND}</div>
                <div className="app-brand__subtitle">{APP_SUBTITLE}</div>
              </div>
            </div>

            <p className="app-footer__description">
              Evidence-based analysis with ATT&CK mapping, layered intelligence,
              and a console-first experience for analysts and operators.
            </p>
          </div>

          <div className="app-footer__columns">
            {APP_FOOTER_LINK_GROUPS.map((group) => (
              <FooterColumn key={group.title} title={group.title}>
                {group.links.map((link) =>
                  "external" in link && link.external ? (
                    <FooterExternalLink key={link.href} href={link.href}>
                      {link.label}
                    </FooterExternalLink>
                  ) : (
                    <FooterLink key={link.href} href={link.href}>
                      {link.label}
                    </FooterLink>
                  )
                )}
              </FooterColumn>
            ))}
          </div>
        </div>

        <div className="app-footer__divider" />

        <div className="app-footer__bottom">
          <span className="app-footer__meta">
            &copy; {YEAR} {APP_BRAND} - Timotei Moscaliuc. All rights reserved.
          </span>

          <div className="app-footer__badges">
            <Badge>AI Powered</Badge>
            <Badge>Evidence Based</Badge>
            <Badge>ATT&CK Ready</Badge>
            <span className="app-footer__pill">{APP_VERSION}</span>
          </div>
        </div>
      </div>
    </footer>
  );
}

function FooterColumn({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="app-footer__column">
      <div className="app-footer__columnTitle">{title}</div>
      {children}
    </div>
  );
}

function FooterLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a href={href} className="app-footer__link">
      {children}
    </a>
  );
}

function FooterExternalLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a href={href} className="app-footer__link" target="_blank" rel="noreferrer">
      {children}
    </a>
  );
}

function Badge({ children }: { children: React.ReactNode }) {
  return <span className="app-footer__pill">{children}</span>;
}
