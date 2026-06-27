/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./pages/**/*.{js,jsx,ts,tsx}",
    "./components/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg:      "#0b0e14",
        surface: "#121622",
        surface2:"#0e111a",
        line:    "#1f2835",
        ink:     "#e6eef7",
        muted:   "#a6b6cb",
        mono:    "#d7e7ff",
        accent:  "#74e8a1",
      },
      fontFamily: {
        ui:   ["Inter","ui-sans-serif","system-ui","-apple-system","Segoe UI","Roboto","Arial"],
        mono: ["ui-monospace","SFMono-Regular","Menlo","Consolas","Liberation Mono","monospace"],
      },
    },
  },
  plugins: [],
};
