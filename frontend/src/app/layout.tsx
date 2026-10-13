import type { Metadata } from "next";
import "@/styles/globals.css";
import AppShell from "@/components/layout/AppShell";
import SettingsPreferencesProvider from "@/components/settings/SettingsPreferencesProvider";
import ThemeScript from "@/components/settings/ThemeScript";
import BuildStampClient from "@/components/layout/BuildStampClient";
import { APP_BRAND, APP_SUBTITLE } from "@/lib/constants";

export const metadata: Metadata = {
  title: {
    default: APP_BRAND,
    template: `%s | ${APP_BRAND}`,
  },
  description: APP_SUBTITLE,
};

/**
 * Which build the browser is running.
 *
 * Its backend counterpart is `/health`'s `code` block. Both exist because on
 * 2026-10-12 a day of backend work was pushed, correct and not serving, and
 * nothing could say so: every filesystem check reported the source, never the
 * running thing. The frontend half closes the other direction — if a page
 * shows the wrong thing, this says in one glance whether the browser is even
 * running the build you made, before anyone starts eliminating layers.
 *
 * The meta tag here and the console line in `BuildStampClient` are a pair,
 * not redundancy: this one arrives with the HTML, that one is compiled into
 * the JS bundle. If they disagree, the HTML is fresh and the bundle is
 * cached — the same comparison as API against worker, one layer up.
 */
function BuildStamp() {
  const fingerprint = process.env.NEXT_PUBLIC_BUILD_FINGERPRINT || "unavailable: not set at build time";
  const files = process.env.NEXT_PUBLIC_BUILD_FILES || "0";
  return (
    <>
      <meta name="x-build-fingerprint" content={fingerprint} />
      <meta name="x-build-files" content={files} />
    </>
  );
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <BuildStamp />
      </head>
      <body>
        <ThemeScript />
        <BuildStampClient />
        <SettingsPreferencesProvider>
          <AppShell>{children}</AppShell>
        </SettingsPreferencesProvider>
      </body>
    </html>
  );
}
