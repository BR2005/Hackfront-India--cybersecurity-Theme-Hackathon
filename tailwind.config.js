/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#0a0a0c",
        panel: "#16161a",
        "panel-lighter": "#1e1e24",
        primary: "#0ea5e9",
        critical: "#ef4444",
        high: "#f97316",
        medium: "#eab308",
        healthy: "#22c55e",
      }
    },
  },
  plugins: [],
}
