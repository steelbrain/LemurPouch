import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  metadataBase: new URL("https://lemurpouch.com"),
  title: "LemurPouch — LAN file sharing, simplified",
  description:
    "End-to-end encrypted file sharing that works on the most restrictive networks.",
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "any" },
      { url: "/favicon-16.png", type: "image/png", sizes: "16x16" },
      { url: "/favicon-32.png", type: "image/png", sizes: "32x32" },
      { url: "/favicon-48.png", type: "image/png", sizes: "48x48" },
    ],
    apple: [{ url: "/apple-touch-icon.png", sizes: "180x180" }],
  },
  openGraph: {
    title: "LemurPouch — LAN file sharing, simplified",
    description:
      "End-to-end encrypted file sharing that works on the most restrictive networks.",
    images: [
      {
        url: "/og-image.png",
        width: 1672,
        height: 941,
        alt: "LemurPouch — end-to-end encrypted file sharing that never leaves your network",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "LemurPouch — LAN file sharing, simplified",
    description:
      "End-to-end encrypted file sharing that works on the most restrictive networks.",
    images: ["/og-image.png"],
  },
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#0f1117" },
  ],
};

const THEME_INIT_SCRIPT = `(function(){try{var m=document.cookie.match(/(?:^|;\\s*)lemurpouch_theme=(light|dark)/);if(m)document.documentElement.setAttribute('data-theme',m[1]);}catch(e){}})();`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
      suppressHydrationWarning
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
      </head>
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
