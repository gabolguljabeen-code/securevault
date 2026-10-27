import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SecureVault — Local File Encryption",
  description: "Encrypt and decrypt files locally in your browser with AES-256-GCM.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
