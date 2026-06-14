"use client";

const COOKIE_NAME = "lemurpouch_theme";
const COOKIE_MAX_AGE = 60 * 60 * 24 * 365;

type Theme = "light" | "dark";

function readCurrentTheme(): Theme {
  const attr = document.documentElement.getAttribute("data-theme");
  if (attr === "light" || attr === "dark") return attr;
  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

export function ThemeToggle() {
  const handleClick = () => {
    const next: Theme = readCurrentTheme() === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    const secure = window.location.protocol === "https:" ? "; Secure" : "";
    document.cookie = `${COOKIE_NAME}=${next}; path=/; max-age=${COOKIE_MAX_AGE}; SameSite=Lax${secure}`;
  };

  return (
    <button
      type="button"
      onClick={handleClick}
      aria-label="Toggle color theme"
      title="Toggle color theme"
      className="inline-flex h-10 w-10 items-center justify-center rounded-xl border border-border bg-background-elevated text-foreground-muted transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-pouch focus-visible:ring-offset-2 focus-visible:ring-offset-background"
    >
      <svg
        viewBox="0 0 24 24"
        className="theme-icon-moon h-5 w-5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden
      >
        <path d="M21 12.5A8.5 8.5 0 1 1 11.5 3a6.5 6.5 0 0 0 9.5 9.5z" />
      </svg>
      <svg
        viewBox="0 0 24 24"
        className="theme-icon-sun h-5 w-5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden
      >
        <circle cx="12" cy="12" r="4" />
        <path d="M12 3v2M12 19v2M5 12H3M21 12h-2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M5.6 18.4 7 17M17 7l1.4-1.4" />
      </svg>
    </button>
  );
}
