/* Shared primitives — security-atlas. Cyan-300 primary, orange-400 accent. */

import { useState } from 'react';
import { AlertTriangle, CheckCircle2, Info, XCircle, Lightbulb, ShieldAlert } from 'lucide-react';

export function Kbd({ children }) {
  return (
    <code className="px-1.5 py-0.5 text-[12.5px] bg-zinc-800/70 text-cyan-300 border border-zinc-700"
      style={{ fontFamily: 'JetBrains Mono, monospace' }}>
      {children}
    </code>
  );
}

export function H2({ num, children }) {
  return (
    <h2 className="text-zinc-100 mt-12 mb-4 flex items-baseline gap-3"
      style={{ fontFamily: 'Bricolage Grotesque, sans-serif', fontWeight: 600, fontSize: '22px' }}>
      <span className="text-cyan-300 text-[12px] tracking-[0.25em] uppercase shrink-0"
        style={{ fontFamily: 'JetBrains Mono, monospace' }}>
        {num}
      </span>
      <span>{children}</span>
    </h2>
  );
}

export function P({ children }) {
  return (
    <p className="text-zinc-300 text-[15px] leading-relaxed my-3 max-w-prose"
      style={{ fontFamily: 'Manrope, sans-serif' }}>
      {children}
    </p>
  );
}

export function Code({ id, lang = 'json', children }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    if (typeof children !== 'string') return;
    navigator.clipboard.writeText(children).catch(e => console.warn('copy failed:', e?.message));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div className="my-4 border border-zinc-800">
      <div className="flex items-center justify-between bg-zinc-950 px-3 py-1.5 border-b border-zinc-800 text-[10px] uppercase tracking-[0.2em] text-zinc-500"
        style={{ fontFamily: 'JetBrains Mono, monospace' }}>
        <span>{lang}{id ? ` · ${id}` : ''}</span>
        <button onClick={copy} className="hover:text-cyan-300 transition-colors">
          {copied ? 'copied' : 'copy'}
        </button>
      </div>
      <pre className="px-3 py-2.5 text-[12.5px] text-zinc-100 overflow-x-auto leading-relaxed"
        style={{ fontFamily: 'JetBrains Mono, monospace' }}>
        <code>{children}</code>
      </pre>
    </div>
  );
}

const CALLOUT_STYLES = {
  tip:    { icon: Lightbulb,    accent: 'text-orange-400', border: 'border-orange-400/40', bg: 'bg-orange-400/5' },
  warn:   { icon: AlertTriangle,accent: 'text-orange-400', border: 'border-orange-400/40', bg: 'bg-orange-400/5' },
  info:   { icon: Info,         accent: 'text-cyan-300',   border: 'border-cyan-300/40',   bg: 'bg-cyan-300/5' },
  win:    { icon: CheckCircle2, accent: 'text-cyan-300',   border: 'border-cyan-300/40',   bg: 'bg-cyan-300/5' },
  dont:   { icon: XCircle,      accent: 'text-rose-400',   border: 'border-rose-400/40',   bg: 'bg-rose-400/5' },
  danger: { icon: ShieldAlert,  accent: 'text-rose-400',   border: 'border-rose-400/50',   bg: 'bg-rose-400/10' },
};

export function Callout({ kind = 'info', title, children }) {
  const cfg = CALLOUT_STYLES[kind] || CALLOUT_STYLES.info;
  const Icon = cfg.icon;
  return (
    <div className={`my-4 border ${cfg.border} ${cfg.bg} p-4`}>
      {title && (
        <div className={`flex items-center gap-2 mb-2 ${cfg.accent} text-[11px] tracking-[0.2em] uppercase`}
          style={{ fontFamily: 'JetBrains Mono, monospace' }}>
          <Icon size={13} strokeWidth={2.5} />
          <span>{title}</span>
        </div>
      )}
      <div className="text-zinc-200 text-[14px] leading-relaxed">{children}</div>
    </div>
  );
}

export function SectionLabel({ children }) {
  return (
    <div className="my-8 text-cyan-300 text-[10px] tracking-[0.4em] uppercase border-b border-zinc-800 pb-2"
      style={{ fontFamily: 'JetBrains Mono, monospace' }}>
      ── {children} ──
    </div>
  );
}
