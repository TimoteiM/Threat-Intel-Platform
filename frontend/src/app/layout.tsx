import type { Metadata } from "next";
import "@/styles/globals.css";
import Header from "@/components/layout/Header";
import Footer from "@/components/layout/Footer";
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
      <body className="app-shell">
        <ThemeScript />
        <SettingsPreferencesProvider>
          <Header />
          <main className="app-shell__main">{children}</main>
          <Footer />
        </SettingsPreferencesProvider>
      </body>
    </html>
  );
}
