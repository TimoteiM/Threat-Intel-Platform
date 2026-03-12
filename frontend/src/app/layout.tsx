import "@/styles/globals.css";
import Header from "@/components/layout/Header";
import Footer from "@/components/layout/Footer";

export const metadata = {
  title: "Threat Investigator",
  description: "Domain threat investigation platform",
};

const APP_MAX_WIDTH = 1920;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ display: "flex", flexDirection: "column", minHeight: "100vh" }}>
        <Header />
        <main style={{ flex: 1, maxWidth: APP_MAX_WIDTH, margin: "0 auto", padding: "0 16px", width: "100%" }}>
          {children}
        </main>
        <Footer />
      </body>
    </html>
  );
}



