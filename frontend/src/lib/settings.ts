export type ThemePreference = "dark" | "light" | "system";
export type ListDensity = "comfortable" | "compact";

export interface UserSettings {
  theme: ThemePreference;
  investigationAutoRefresh: boolean;
  duplicateCheckWarning: boolean;
  listDensity: ListDensity;
  apiHealthAutoRefresh: boolean;
}

export const SETTINGS_STORAGE_KEY = "threat-analyzer.settings";

export const DEFAULT_SETTINGS: UserSettings = {
  theme: "dark",
  investigationAutoRefresh: true,
  duplicateCheckWarning: true,
  listDensity: "comfortable",
  apiHealthAutoRefresh: true,
};

export function isThemePreference(value: unknown): value is ThemePreference {
  return value === "dark" || value === "light" || value === "system";
}

export function isListDensity(value: unknown): value is ListDensity {
  return value === "comfortable" || value === "compact";
}

export function sanitizeSettings(value: unknown): UserSettings {
  if (!value || typeof value !== "object") {
    return { ...DEFAULT_SETTINGS };
  }

  const candidate = value as Partial<UserSettings>;
  return {
    theme: isThemePreference(candidate.theme) ? candidate.theme : DEFAULT_SETTINGS.theme,
    investigationAutoRefresh:
      typeof candidate.investigationAutoRefresh === "boolean"
        ? candidate.investigationAutoRefresh
        : DEFAULT_SETTINGS.investigationAutoRefresh,
    duplicateCheckWarning:
      typeof candidate.duplicateCheckWarning === "boolean"
        ? candidate.duplicateCheckWarning
        : DEFAULT_SETTINGS.duplicateCheckWarning,
    listDensity: isListDensity(candidate.listDensity) ? candidate.listDensity : DEFAULT_SETTINGS.listDensity,
    apiHealthAutoRefresh:
      typeof candidate.apiHealthAutoRefresh === "boolean"
        ? candidate.apiHealthAutoRefresh
        : DEFAULT_SETTINGS.apiHealthAutoRefresh,
  };
}

export function readStoredSettings(): UserSettings {
  if (typeof window === "undefined") {
    return { ...DEFAULT_SETTINGS };
  }

  try {
    const raw = window.localStorage.getItem(SETTINGS_STORAGE_KEY);
    if (!raw) {
      return { ...DEFAULT_SETTINGS };
    }
    return sanitizeSettings(JSON.parse(raw));
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export function writeStoredSettings(settings: UserSettings): void {
  if (typeof window === "undefined") {
    return;
  }

  window.localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(settings));
}

export function resolveEffectiveTheme(theme: ThemePreference): "dark" | "light" {
  if (theme === "dark" || theme === "light") {
    return theme;
  }
  if (typeof window !== "undefined" && window.matchMedia("(prefers-color-scheme: light)").matches) {
    return "light";
  }
  return "dark";
}

export function applyThemeToDocument(theme: ThemePreference): "dark" | "light" {
  const effectiveTheme = resolveEffectiveTheme(theme);
  if (typeof document !== "undefined") {
    document.documentElement.setAttribute("data-theme", effectiveTheme);
    document.documentElement.style.colorScheme = effectiveTheme;
  }
  return effectiveTheme;
}
