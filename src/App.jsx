/* API Security Atlas — shell + section orchestration. */

import Section01_Auth from './sections/01-authentication.jsx';
import Section02_Authz from './sections/02-authorization.jsx';
import Section03_Attacks from './sections/03-attacks.jsx';
import Section04_Defense from './sections/04-defense.jsx';

const SECTIONS = [
  { id: 'authentication', label: '01 · Authentication',  comp: Section01_Auth },
  { id: 'authorization',  label: '02 · Authorization',   comp: Section02_Authz },
  { id: 'attacks',        label: '03 · Attack surfaces', comp: Section03_Attacks },
  { id: 'defense',        label: '04 · Defense in depth',comp: Section04_Defense },
];

function Header() {
  return (
    <div className="border-b border-zinc-800 bg-zinc-950 sticky top-0 z-50 backdrop-blur">
      <div className="max-w-5xl mx-auto px-6 py-3 flex items-baseline gap-4">
        <a href="#top" className="text-cyan-300 text-[22px] leading-none"
          style={{ fontFamily: 'serif' }}>⛨</a>
        <div className="flex-1">
          <div className="text-zinc-100 text-[14px] font-semibold leading-tight"
            style={{ fontFamily: 'Bricolage Grotesque, sans-serif' }}>
            API Security
          </div>
          <div className="text-zinc-500 text-[10.5px] tracking-[0.25em] uppercase"
            style={{ fontFamily: 'JetBrains Mono, monospace' }}>
            Atlas · B. Symbolic
          </div>
        </div>
        <a href="https://atlases.vercel.app"
          className="text-zinc-500 hover:text-cyan-300 text-[11px] tracking-[0.2em] uppercase"
          style={{ fontFamily: 'JetBrains Mono, monospace' }}>
          ← all atlases
        </a>
      </div>
    </div>
  );
}

function Hero() {
  return (
    <div id="top" className="border-b border-zinc-800 bg-gradient-to-b from-zinc-950 to-zinc-900">
      <div className="max-w-5xl mx-auto px-6 py-16">
        <div className="text-cyan-300 text-[11px] tracking-[0.4em] uppercase mb-4"
          style={{ fontFamily: 'JetBrains Mono, monospace' }}>
          atlas eighteen · ⛨
        </div>
        <h1 className="text-zinc-50 text-[42px] leading-[1.05] mb-4"
          style={{ fontFamily: 'Bricolage Grotesque, sans-serif', fontWeight: 700 }}>
          API Security
        </h1>
        <p className="text-zinc-400 text-[16px] max-w-2xl leading-relaxed"
          style={{ fontFamily: 'Manrope, sans-serif' }}>
          The threats your API faces and the patterns that stop them. Authentication — who are you.
          Authorization — what can you do. The attack surface — where things go wrong. Defense in depth —
          the layers that catch what the layers above missed. Four interactive sections; each shows you
          how an attack works and how to stop it.
        </p>
      </div>
    </div>
  );
}

function TOC() {
  return (
    <div className="max-w-5xl mx-auto px-6 mt-10">
      <div className="border border-zinc-800 p-5">
        <div className="text-cyan-300 text-[10px] tracking-[0.3em] uppercase mb-3"
          style={{ fontFamily: 'JetBrains Mono, monospace' }}>
          contents
        </div>
        <div className="space-y-1.5">
          {SECTIONS.map(s => (
            <a key={s.id} href={`#${s.id}`}
              className="block text-zinc-300 hover:text-cyan-300 text-[14px] transition-colors"
              style={{ fontFamily: 'Bricolage Grotesque, sans-serif' }}>
              {s.label}
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}

function Footer() {
  return (
    <div className="border-t border-zinc-800 mt-20 py-10">
      <div className="max-w-5xl mx-auto px-6 text-center">
        <div className="text-zinc-500 text-[11px] tracking-[0.3em] uppercase mb-2"
          style={{ fontFamily: 'JetBrains Mono, monospace' }}>
          end of atlas
        </div>
        <div className="text-zinc-600 text-[12px]">
          ⛨ · API Security · B. Symbolic ·{' '}
          <a href="https://atlases.vercel.app" className="hover:text-cyan-300">atlases.vercel.app</a>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <Header />
      <Hero />
      <TOC />
      <div className="max-w-5xl mx-auto px-6">
        {SECTIONS.map(s => {
          const Comp = s.comp;
          return (
            <div key={s.id} id={s.id} className="scroll-mt-16">
              <Comp />
            </div>
          );
        })}
      </div>
      <Footer />
    </div>
  );
}
