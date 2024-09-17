import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Helvetica', 'Arial', 'sans-serif'],
        title: ['Poppins', 'sans-serif'],
        body: ['Roboto', 'sans-serif'],
      },
      fontSize: {
        'navbar-title': ['1.25rem', '1.75rem'],
        'hero-title': ['3rem', '3.5rem'],
        'body-text': ['1rem', '1.5rem'],
      }
    },
  },
  plugins: [],
};
export default config;
