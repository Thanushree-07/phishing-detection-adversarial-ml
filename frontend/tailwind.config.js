/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#11161C",
        panel: "#171D26",
        panel2: "#1C2330",
        border: "#262E3A",
        text: {
          primary: "#E7EBF0",
          muted: "#8993A4",
          faint: "#5B6475",
        },
        danger: "#E2574C",
        safe: "#4CAE8C",
        amber: "#E8A33D",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
}
