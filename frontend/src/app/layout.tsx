import type { Metadata } from "next";
import "@/styles/globals.css";
import AppShell from "@/components/layout/AppShell";
import SettingsPreferencesProvider from "@/components/settings/SettingsPreferencesProvider";
import ThemeScript from "@/components/settings/ThemeScript";
import { APP_BRAND, APP_SUBTITLE } from "@/lib/constants";

export const metadata: Metadata = {
  title: {
    default: APP_BRAND,
    template: `%s | ${APP_BRAND}`,
  },
  description: APP_SUBTITLE,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <ThemeScript />
        <SettingsPreferencesProvider>
          <AppShell>{children}</AppShell>
        </SettingsPreferencesProvider>
      </body>
    </html>
  );
}
