"use client";

import React from "react";

import {
  applyThemeToDocument,
  DEFAULT_SETTINGS,
  readStoredSettings,
  type ThemePreference,
  type UserSettings,
  writeStoredSettings,
} from "@/lib/settings";

type SettingsContextValue = {
  settings: UserSettings;
  effectiveTheme: "dark" | "light";
  setTheme: (theme: ThemePreference) => void;
  updateSettings: (patch: Partial<UserSettings>) => void;
};

const SettingsContext = React.createContext<SettingsContextValue | null>(null);

export default function SettingsPreferencesProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  const [settings, setSettings] = React.useState<UserSettings>(DEFAULT_SETTINGS);
  const [effectiveTheme, setEffectiveTheme] = React.useState<"dark" | "light">("dark");

  React.useEffect(() => {
    const stored = readStoredSettings();
    setSettings(stored);
    setEffectiveTheme(applyThemeToDocument(stored.theme));
  }, []);

  React.useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    if (settings.theme !== "system") {
      return;
    }

    const mediaQuery = window.matchMedia("(prefers-color-scheme: light)");
    const syncTheme = () => setEffectiveTheme(applyThemeToDocument("system"));
    syncTheme();

    if (typeof mediaQuery.addEventListener === "function") {
      mediaQuery.addEventListener("change", syncTheme);
      return () => mediaQuery.removeEventListener("change", syncTheme);
    }

    mediaQuery.addListener(syncTheme);
    return () => mediaQuery.removeListener(syncTheme);
  }, [settings.theme]);

  const updateSettings = React.useCallback((patch: Partial<UserSettings>) => {
    setSettings((current) => {
      const next = { ...current, ...patch };
      writeStoredSettings(next);
      setEffectiveTheme(applyThemeToDocument(next.theme));
      return next;
    });
  }, []);

  const setTheme = React.useCallback(
    (theme: ThemePreference) => {
      updateSettings({ theme });
    },
    [updateSettings],
  );

  const value = React.useMemo(
    () => ({
      settings,
      effectiveTheme,
      setTheme,
      updateSettings,
    }),
    [effectiveTheme, setTheme, settings, updateSettings],
  );

  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>;
}

export function useSettingsPreferences() {
  const context = React.useContext(SettingsContext);
  if (!context) {
    throw new Error("useSettingsPreferences must be used within SettingsPreferencesProvider");
  }
  return context;
}
