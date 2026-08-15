import type { Metadata } from "next";
import { ThemeProvider } from "../components/ThemeProvider";
import "../styles/tokens.css";
import "./globals.css";
import "xterm/css/xterm.css";

export const metadata: Metadata = {
  title: "ARGUS 2.0",
  description: "Investigação Autônoma de Dark Web e OSINT",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="pt-BR" suppressHydrationWarning>
      <body>
        <ThemeProvider>
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
