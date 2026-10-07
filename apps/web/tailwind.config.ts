import type { Config } from "tailwindcss";

/** All colours resolve to CSS variables (see src/styles.css) so light/dark themes swap at runtime. */
const token = (name: string) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        canvas: token("canvas"),
        surface: { DEFAULT: token("surface"), 2: token("surface-2"), 3: token("surface-3") },
        line: { DEFAULT: token("border"), strong: token("border-strong") },
        fg: { DEFAULT: token("fg"), muted: token("fg-muted"), subtle: token("fg-subtle"), inverse: token("fg-inverse") },
        heading: token("heading"),
        topbar: { DEFAULT: token("topbar"), fg: token("topbar-fg"), muted: token("topbar-muted"), hover: token("topbar-hover") },
        rail: { DEFAULT: token("rail"), active: token("rail-active"), fg: token("rail-fg") },
        brand: { DEFAULT: token("brand"), soft: token("brand-soft") },
        primary: { DEFAULT: token("primary"), hover: token("primary-hover"), soft: token("primary-soft") },
        healthy: { DEFAULT: token("healthy"), soft: token("healthy-soft") },
        sev: {
          critical: token("sev-critical"),
          high: token("sev-high"),
          medium: token("sev-medium"),
          low: token("sev-low"),
          info: token("sev-info"),
        },
      },
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        display: ["Montserrat", "Inter", "ui-sans-serif", "system-ui", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      fontSize: {
        "2xs": ["10px", "14px"],
        xs: ["11px", "16px"],
        sm: ["12px", "17px"],
        base: ["13px", "19px"],
        md: ["14px", "20px"],
        lg: ["16px", "22px"],
        xl: ["18px", "24px"],
        "2xl": ["22px", "28px"],
        "3xl": ["26px", "32px"],
      },
      boxShadow: {
        card: "0 1px 2px rgb(15 23 42 / 0.04)",
        pop: "0 10px 30px -10px rgb(15 23 42 / 0.35), 0 2px 6px rgb(15 23 42 / 0.08)",
      },
      keyframes: {
        "slide-in-right": { from: { transform: "translateX(100%)" }, to: { transform: "translateX(0)" } },
        "fade-in": { from: { opacity: "0" }, to: { opacity: "1" } },
        shimmer: { "100%": { transform: "translateX(100%)" } },
      },
      animation: {
        "slide-in-right": "slide-in-right 180ms ease-out",
        "fade-in": "fade-in 120ms ease-out",
      },
    },
  },
  plugins: [],
} satisfies Config;
