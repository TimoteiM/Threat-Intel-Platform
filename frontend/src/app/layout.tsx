import "@/styles/globals.css";
import Header from "@/components/layout/Header";
import Footer from "@/components/layout/Footer";

export const metadata = {
  title: "Threat Investigator",
  description: "Domain threat investigation platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ display: "flex", flexDirection: "column", minHeight: "100vh" }}>
        <Header />
        <main style={{ flex: 1, maxWidth: 1320, margin: "0 auto", padding: "0 24px", width: "100%" }}>
          {children}
        </main>
        <Footer />
      </body>
    </html>
  );
}




