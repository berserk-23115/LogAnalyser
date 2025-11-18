import Navbar from "@/components/navbar";
import Hero from "@/components/Hero";
import ProblemStatement from "@/components/ProblemStatement";
import Features from "@/components/Features";
import Demo from "@/components/Demo";
import Team from "@/components/Team";
import Footer from "@/components/Footer";

export default function Home() {
  return (
    <div className="min-h-screen bg-white dark:bg-black">
      <Navbar />
      <main>
        <Hero />
        <ProblemStatement />
        <Features />
        {/* <Demo /> */}
        <Team />
      </main>
      <Footer />
    </div>
  );
}
