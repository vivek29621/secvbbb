import type { AppProps } from "next/app";
import Nav from "@/components/Nav";
import "@/styles/globals.css";

export default function App({ Component, pageProps }: AppProps) {
  return (
    <div className="min-h-screen bg-slate-50">
      <Nav />
      <main className="mx-auto w-full max-w-6xl px-4 pb-28 pt-10 sm:px-6 lg:px-8">
        <Component {...pageProps} />
      </main>
      <footer className="border-t border-slate-200/80 bg-white/60 py-8">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
          <p className="text-xs leading-5 text-slate-500">
            <span className="font-semibold text-slate-700">Authorized use only.</span> VulnAgent
            performs passive checks plus, when you confirm authorization, light active probing. Only
            scan websites you own or have explicit permission to test. Findings are advisory — always
            verify before acting. Not a substitute for a professional penetration test.
          </p>
          <p className="mt-2 text-xs text-slate-400">
            VulnAgent · open source · powered by Google AI
          </p>
        </div>
      </footer>
    </div>
  );
}
