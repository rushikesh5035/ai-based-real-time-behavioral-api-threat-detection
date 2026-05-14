import type { Metadata } from "next"
import "./globals.css"
import Providers from "@/components/providers"

export const metadata: Metadata = {
  title: "API Security Dashboard — Real-Time Threat Detection",
  description: "Monitor ML predictions, automated responses, and suspicious API traffic in real-time",
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" className="dark h-full antialiased">
      <body className="min-h-full flex flex-col">
        <Providers>{children}</Providers>
      </body>
    </html>
  )
}
