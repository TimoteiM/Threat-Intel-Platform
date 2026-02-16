import "@/styles/globals.css";
import Header from "@/components/layout/Header";

export const metadata = {
  title: "Threat Investigator",
  description: "Domain threat investigation platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Header />
        <main style={{ maxWidth: 1320, margin: "0 auto", padding: "0 24px" }}>
          {children}
        </main>
      </body>
    </html>
  );
}




