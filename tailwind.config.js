/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Base UI surfaces
        vault: {
          bg: "#F0F4F8",        // Soft blue-grey background (not harsh white)
          surface: "#FFFFFF",   // Card surfaces
          sidebar: "#1E2A3A",   // Deep navy sidebar (authority + trust)
          border: "#D1DCE8",    // Subtle blue-tinted borders
        },

        // Primary brand / interactive
        primary: {
          DEFAULT: "#2563EB",   // Strong blue — action buttons, links
          light: "#EFF6FF",     // Hover backgrounds
          dark: "#1D4ED8",      // Pressed / active states
        },

        // Classification badge colors (critical for a vault!)
        badge: {
          public: "#059669",       // Emerald green — safe, open
          internal: "#2563EB",     // Blue — internal use
          confidential: "#D97706", // Amber — caution
          restricted: "#DC2626",   // Red — danger, locked down
        },

        // Text hierarchy
        text: {
          primary: "#0F172A",    // Near-black for titles
          secondary: "#475569",  // Slate for metadata/labels
          muted: "#94A3B8",      // Placeholder / disabled
          inverse: "#F8FAFC",    // Text on dark sidebar
        },

        // Status / feedback
        success: "#10B981",
        warning: "#F59E0B",
        danger: "#EF4444",
      },
    },
  },
  plugins: [],
}