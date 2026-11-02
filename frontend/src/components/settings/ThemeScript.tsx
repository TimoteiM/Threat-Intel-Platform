import { DEFAULT_SETTINGS, SETTINGS_STORAGE_KEY } from "@/lib/settings";

function buildThemeInitScript(): string {
  return `
    (() => {
      const storageKey = ${JSON.stringify(SETTINGS_STORAGE_KEY)};
      const defaultTheme = ${JSON.stringify(DEFAULT_SETTINGS.theme)};
      try {
        const raw = window.localStorage.getItem(storageKey);
        const parsed = raw ? JSON.parse(raw) : {};
        const preference = parsed && typeof parsed.theme === "string" ? parsed.theme : defaultTheme;
        const effective =
          preference === "system"
            ? (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")
            : (preference === "light" ? "light" : "dark");
        document.documentElement.setAttribute("data-theme", effective);
        document.documentElement.style.colorScheme = effective;
      } catch {
        document.documentElement.setAttribute("data-theme", defaultTheme);
        document.documentElement.style.colorScheme = defaultTheme;
      }
    })();
  `;
}

export default function ThemeScript() {
  return <script dangerouslySetInnerHTML={{ __html: buildThemeInitScript() }} />;
}
