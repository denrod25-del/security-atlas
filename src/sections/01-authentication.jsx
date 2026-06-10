/* Section 01 â€” Authentication.
 *
 * Prose + interactive JWT Decoder & Analyzer.
 *
 * The decoder accepts pasted tokens or pre-loaded examples covering
 * each major class of JWT issue: valid token, alg:none attack, expired,
 * leaky payload, missing expiration. Auto-decode shows header/payload/
 * signature; analysis panel scores algorithm choice, expiration claims,
 * sensitive data in the payload, and issuer/audience presence.
 *
 * Notable: the decoder does NOT verify signatures. The point is teaching
 * what's IN a token, not enforcing trust. That distinction matters and
 * we surface it in the UI.
 */

import { useState, useMemo } from 'react';
import { Sparkles, ShieldCheck, ShieldAlert, AlertTriangle, Eye } from 'lucide-react';
import { Code, Callout, H2, P, Kbd, SectionLabel } from '../components/primitives.jsx';

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// JWT encoder/decoder utilities
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function b64urlEncode(str) {
  return btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function b64urlDecode(str) {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  try {
    const binary = atob(s);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  } catch {
    throw new Error('Invalid base64url');
  }
}

function makeJwt(header, payload, sig = 'demoSignatureNotValid_xxxxxxxxxxxxxxxxxxxxxxxxxxxx') {
  return `${b64urlEncode(JSON.stringify(header))}.${b64urlEncode(JSON.stringify(payload))}.${sig}`;
}

function decodeJwt(token) {
  const parts = token.trim().split('.');
  if (parts.length !== 3) {
    return { error: 'A JWT has three parts separated by dots (header.payload.signature). This input has ' + parts.length + '.' };
  }
  try {
    const header = JSON.parse(b64urlDecode(parts[0]));
    const payload = JSON.parse(b64urlDecode(parts[1]));
    return { header, payload, signature: parts[2] };
  } catch (e) {
    return { error: 'Could not decode: ' + e.message };
  }
}

const NOW_SEC = Math.floor(Date.now() / 1000);

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Pre-loaded example tokens â€” each demonstrates a class of issue
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const EXAMPLES = [
  {
    id: 'valid',
    label: 'Valid token',
    description: 'A normal, well-formed token from a real auth server.',
    token: makeJwt(
      { alg: 'HS256', typ: 'JWT' },
      { sub: 'user_42', name: 'Cle', iss: 'auth.example.com', aud: 'api.example.com', iat: NOW_SEC, exp: NOW_SEC + 3600 }
    ),
  },
  {
    id: 'none',
    label: '"alg: none" attack',
    description: 'The classic JWT vulnerability. Servers that trust the "alg" claim from the token will skip signature verification entirely.',
    token: makeJwt(
      { alg: 'none', typ: 'JWT' },
      { sub: 'user_42', name: 'admin', role: 'admin', exp: NOW_SEC + 3600 },
      ''
    ),
  },
  {
    id: 'expired',
    label: 'Expired token',
    description: 'Looks valid until you check the expiration claim. Some servers forget to check.',
    token: makeJwt(
      { alg: 'HS256', typ: 'JWT' },
      { sub: 'user_42', name: 'Cle', iat: NOW_SEC - 7200, exp: NOW_SEC - 3600 }
    ),
  },
  {
    id: 'leaky',
    label: 'Sensitive data in payload',
    description: 'JWT payloads are base64-encoded, NOT encrypted. Anyone with the token can read every field.',
    token: makeJwt(
      { alg: 'HS256', typ: 'JWT' },
      { sub: 'user_42', email: 'cle@x.com', password_hash: '5f4dcc3b5aa765d61d8327deb882cf99', ssn_last4: '4242', exp: NOW_SEC + 3600 }
    ),
  },
  {
    id: 'no-exp',
    label: 'No expiration',
    description: 'A token that lives forever. If it leaks once, it leaks for good.',
    token: makeJwt(
      { alg: 'HS256', typ: 'JWT' },
      { sub: 'user_42', name: 'Cle', iat: NOW_SEC }
    ),
  },
];

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Security analysis
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const SECURE_ALGS = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'EdDSA'];
const REDFLAG_KEYS = ['password', 'pwd', 'secret', 'ssn', 'credit_card', 'creditcard', 'cc_number', 'private_key', 'apikey', 'api_key', 'pin'];

function analyze(decoded) {
  if (decoded.error) return { issues: [], passes: [] };
  const issues = [];
  const passes = [];

  // Algorithm
  const alg = decoded.header?.alg;
  if (alg === 'none' || alg === 'None' || alg === 'NONE') {
    issues.push({ severity: 'critical', text: 'Algorithm is "none". This token is unsigned. If your server trusts the "alg" field from the token, it will accept ANY forged payload. Always reject "none" before parsing the rest.' });
  } else if (alg && SECURE_ALGS.includes(alg)) {
    passes.push({ text: `Algorithm: ${alg}. Standard and secure when the signing key is properly managed.` });
  } else if (alg) {
    issues.push({ severity: 'medium', text: `Algorithm "${alg}" is unusual. Verify your server actually supports it and is not falling back to weaker handling.` });
  } else {
    issues.push({ severity: 'high', text: 'No algorithm declared.' });
  }

  // Expiration
  if (typeof decoded.payload?.exp === 'number') {
    const remaining = decoded.payload.exp - NOW_SEC;
    if (remaining < 0) {
      const ago = Math.abs(remaining);
      const text = ago > 3600
        ? `${Math.floor(ago / 3600)}h ${Math.floor((ago % 3600) / 60)}m ago`
        : `${Math.floor(ago / 60)}m ${ago % 60}s ago`;
      issues.push({ severity: 'high', text: `Token expired ${text}. A correct server rejects it. A buggy server may still accept it â€” check your "exp" handling.` });
    } else {
      const text = remaining > 3600
        ? `${Math.floor(remaining / 3600)}h ${Math.floor((remaining % 3600) / 60)}m`
        : `${Math.floor(remaining / 60)}m`;
      passes.push({ text: `Expires in ${text}. Short-lived tokens reduce damage if leaked.` });
    }
  } else {
    issues.push({ severity: 'high', text: 'No "exp" claim. The token never expires. Leaked once â†’ leaked forever. Always include exp; pick a short window (15 minutes is common) and rely on refresh tokens for longer sessions.' });
  }

  // Sensitive data in payload
  if (decoded.payload) {
    const keys = Object.keys(decoded.payload).map(k => k.toLowerCase());
    const found = REDFLAG_KEYS.filter(rf => keys.some(k => k.includes(rf)));
    if (found.length > 0) {
      issues.push({ severity: 'critical', text: `Payload contains sensitive field(s): ${found.join(', ')}. JWT payloads are base64-encoded, NOT encrypted â€” anyone with the token can read every field. Never put passwords, secrets, or unmasked PII in a JWT.` });
    }
  }

  // Issuer / audience
  if (decoded.payload && !decoded.payload.iss) {
    issues.push({ severity: 'low', text: 'No "iss" (issuer) claim. Makes it harder to know if the token came from the right auth server.' });
  } else if (decoded.payload?.iss) {
    passes.push({ text: `Issuer: ${decoded.payload.iss}. Servers should validate this matches the expected auth provider.` });
  }
  if (decoded.payload && !decoded.payload.aud) {
    issues.push({ severity: 'low', text: 'No "aud" (audience) claim. A token meant for service A could be replayed against service B if both share a secret.' });
  } else if (decoded.payload?.aud) {
    passes.push({ text: `Audience: ${decoded.payload.aud}. Servers should reject tokens whose aud does not match this service.` });
  }

  return { issues, passes };
}

const SEVERITY_STYLES = {
  critical: { border: 'border-rose-400', bg: 'bg-rose-400/10', text: 'text-rose-300', icon: ShieldAlert },
  high:     { border: 'border-orange-400', bg: 'bg-orange-400/10', text: 'text-orange-300', icon: AlertTriangle },
  medium:   { border: 'border-orange-400/60', bg: 'bg-orange-400/5', text: 'text-orange-300', icon: AlertTriangle },
  low:      { border: 'border-zinc-700', bg: 'bg-zinc-800/40', text: 'text-zinc-400', icon: AlertTriangle },
};

function IssueRow({ issue }) {
  const cfg = SEVERITY_STYLES[issue.severity];
  const Icon = cfg.icon;
  return (
    <div className={`border ${cfg.border} ${cfg.bg} p-3 flex gap-3`}>
      <Icon size={16} className={`${cfg.text} shrink-0 mt-0.5`} />
      <div className="flex-1 text-[13px] text-zinc-200 leading-relaxed">
        <span className={`${cfg.text} text-[10px] uppercase tracking-[0.2em] font-semibold mr-2`}
          style={{ fontFamily: 'JetBrains Mono, monospace' }}>
          {issue.severity}
        </span>
        {issue.text}
      </div>
    </div>
  );
}

function PassRow({ pass }) {
  return (
    <div className="border border-cyan-300/30 bg-cyan-300/5 p-3 flex gap-3">
      <ShieldCheck size={16} className="text-cyan-300 shrink-0 mt-0.5" />
      <div className="flex-1 text-[13px] text-zinc-300 leading-relaxed">{pass.text}</div>
    </div>
  );
}

function JwtDecoder() {
  const [token, setToken] = useState(EXAMPLES[0].token);
  const decoded = useMemo(() => decodeJwt(token), [token]);
  const analysis = useMemo(() => analyze(decoded), [decoded]);

  return (
    <div className="my-6 border border-cyan-300/30 bg-zinc-900/40">
      <div className="flex items-center justify-between bg-zinc-950 px-4 py-2.5 border-b border-cyan-300/30">
        <div className="flex items-center gap-2">
          <Sparkles size={14} className="text-cyan-300" />
          <span className="text-cyan-300 text-[11px] tracking-[0.25em] uppercase font-semibold"
            style={{ fontFamily: 'JetBrains Mono, monospace' }}>
            interactive Â· jwt decoder &amp; analyzer
          </span>
        </div>
      </div>

      <div className="p-4">
        {/* Example pickers */}
        <div className="text-zinc-500 text-[9.5px] tracking-[0.25em] uppercase mb-2"
          style={{ fontFamily: 'JetBrains Mono, monospace' }}>
          example tokens â€” click to load
        </div>
        <div className="flex flex-wrap gap-1.5 mb-4">
          {EXAMPLES.map(e => (
            <button key={e.id} onClick={() => setToken(e.token)}
              className={`px-2.5 py-1 border text-[11.5px] transition-colors ${
                token === e.token
                  ? 'border-cyan-300 bg-cyan-300/15 text-cyan-200'
                  : 'border-zinc-700 text-zinc-400 hover:border-cyan-300/50 hover:text-zinc-200'
              }`}
              style={{ fontFamily: 'JetBrains Mono, monospace' }}>
              {e.label}
            </button>
          ))}
        </div>

        {/* Description of selected example */}
        {(() => {
          const matched = EXAMPLES.find(e => e.token === token);
          return matched ? (
            <div className="text-zinc-400 text-[13px] leading-relaxed mb-3 italic">{matched.description}</div>
          ) : null;
        })()}

        {/* Token input */}
        <div className="text-zinc-500 text-[9.5px] tracking-[0.25em] uppercase mb-1.5"
          style={{ fontFamily: 'JetBrains Mono, monospace' }}>
          token
        </div>
        <textarea
          value={token}
          onChange={(e) => setToken(e.target.value)}
          rows={3}
          className="w-full bg-zinc-950 border border-zinc-800 text-zinc-100 text-[11.5px] p-2.5 focus:outline-none focus:border-cyan-300/60 resize-y"
          style={{ fontFamily: 'JetBrains Mono, monospace' }}
        />

        {decoded.error ? (
          <div className="mt-3 border border-rose-400/40 bg-rose-400/5 p-3 text-[13px] text-rose-300">
            {decoded.error}
          </div>
        ) : (
          <>
            {/* Decoded parts */}
            <div className="grid md:grid-cols-3 gap-3 mt-4">
              <div className="border border-zinc-800">
                <div className="bg-zinc-950 px-3 py-1.5 border-b border-zinc-800 text-[10px] uppercase tracking-[0.2em] text-cyan-300"
                  style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                  header
                </div>
                <pre className="px-3 py-2.5 text-[11.5px] text-zinc-200 overflow-x-auto leading-relaxed"
                  style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                  <code>{JSON.stringify(decoded.header, null, 2)}</code>
                </pre>
              </div>
              <div className="border border-zinc-800">
                <div className="bg-zinc-950 px-3 py-1.5 border-b border-zinc-800 text-[10px] uppercase tracking-[0.2em] text-orange-400"
                  style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                  payload
                </div>
                <pre className="px-3 py-2.5 text-[11.5px] text-zinc-200 overflow-x-auto leading-relaxed"
                  style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                  <code>{JSON.stringify(decoded.payload, null, 2)}</code>
                </pre>
              </div>
              <div className="border border-zinc-800">
                <div className="bg-zinc-950 px-3 py-1.5 border-b border-zinc-800 text-[10px] uppercase tracking-[0.2em] text-zinc-500"
                  style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                  signature
                </div>
                <pre className="px-3 py-2.5 text-[11.5px] text-zinc-400 overflow-x-auto leading-relaxed break-all"
                  style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                  <code>{decoded.signature || '(empty)'}</code>
                </pre>
                <div className="text-[10px] text-zinc-500 px-3 pb-2 italic"
                  style={{ fontFamily: 'Manrope, sans-serif' }}>
                  not verified by this tool
                </div>
              </div>
            </div>

            {/* Analysis */}
            <div className="mt-4">
              <div className="flex items-center gap-2 mb-2">
                <Eye size={12} className="text-cyan-300" />
                <span className="text-cyan-300 text-[10px] tracking-[0.25em] uppercase font-semibold"
                  style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                  analysis
                </span>
              </div>
              <div className="space-y-2">
                {analysis.issues.map((iss, i) => <IssueRow key={'i' + i} issue={iss} />)}
                {analysis.passes.map((p, i) => <PassRow key={'p' + i} pass={p} />)}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Section content
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

export default function Section01_Auth() {
  return (
    <>
      <SectionLabel>section 01</SectionLabel>
      <h2 className="text-zinc-50 text-[28px] leading-tight mb-3"
        style={{ fontFamily: 'Bricolage Grotesque, sans-serif', fontWeight: 600 }}>
        Authentication â€” who are you?
      </h2>
      <P>
        Every API call carries an implicit question: who is calling? Authentication is the answer.
        Done well, it identifies the caller cryptographically and confidently â€” every request is
        either from someone you know, or rejected. Done badly, you ship an API where anyone can
        impersonate anyone, and the only thing standing between an attacker and your data is hope.
      </P>
      <P>
        This section covers the four authentication mechanisms you will encounter in 99% of real
        APIs, then drills the one that confuses everyone: JWT.
      </P>

      <H2 num="â—‡ 01">The four authentication mechanisms</H2>
      <Code id="auth-methods" lang="text">{`METHOD        WHAT'S SENT                                  WHO USES IT
â”€â”€â”€â”€â”€â”€        â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€                                  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
API key       Authorization: Bearer sk_test_abc123...      Server-to-server, simple APIs (Stripe, OpenAI)
Bearer token  Authorization: Bearer eyJhbGc...             User sessions after login (most modern web APIs)
Basic auth    Authorization: Basic base64(user:pass)       Legacy systems, internal tools
OAuth         Bearer token obtained via OAuth flow         Third-party integrations (Google, GitHub login)`}</Code>
      <P>
        They all end up doing the same thing: putting credentials in the <Kbd>Authorization</Kbd>{' '}
        header. The difference is what those credentials ARE and how they were obtained.
      </P>

      <H2 num="â—‡ 02">Where credentials go â€” and where they don't</H2>
      <P>
        The <Kbd>Authorization</Kbd> header is the only correct place for secrets. Anywhere else
        leaks:
      </P>
      <ul className="text-zinc-300 text-[15px] leading-relaxed my-3 list-disc pl-6 space-y-1.5 max-w-prose">
        <li><strong className="text-rose-400">In the URL</strong> (<Kbd>?api_key=...</Kbd>) â€” URLs end up in server logs, browser history, Referer headers, and bug-tracker tickets. The secret leaks every time the URL is shared.</li>
        <li><strong className="text-rose-400">In a cookie without Secure + HttpOnly + SameSite</strong> â€” vulnerable to theft via XSS or accidental transmission over HTTP.</li>
        <li><strong className="text-rose-400">In the request body for a GET</strong> â€” same logging problem; some clients/proxies will not even send it.</li>
        <li><strong className="text-rose-400">In a custom header you invented</strong> â€” fine if you must, but standard Bearer tokens work with every tool. Diverge only when you have to.</li>
      </ul>

      <Callout kind="danger" title="THE CARDINAL RULE â€” TLS, ALWAYS">
        Every authentication scheme above is broken trivially if you transmit it over plain HTTP.
        The credentials are visible to anyone on the same network â€” coffee shop wifi, your ISP,
        any router in between. <Kbd>https://</Kbd> on every endpoint, in dev and production. Modern
        platforms (Vercel, Cloudflare, AWS) make this free. Never accept anything else.
      </Callout>

      <H2 num="â—‡ 03">JWT â€” the format that won</H2>
      <P>
        JWT (JSON Web Token, pronounced "jot") is how most modern web APIs represent the bearer
        token. After a user logs in with their password, the server issues a JWT; the client sends
        it on every subsequent request; the server verifies it cryptographically and trusts the
        claims inside.
      </P>
      <P>
        A JWT looks like three base64-encoded chunks separated by dots:
      </P>
      <Code id="jwt-shape" lang="text">{`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9     â† header
.
eyJzdWIiOiJ1c2VyXzQyIiwibmFtZSI6IkNsZSJ9 â† payload (claims)
.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQss â† signature`}</Code>
      <P>
        Decoded:
      </P>
      <Code id="jwt-decoded" lang="json">{`// header
{ "alg": "HS256", "typ": "JWT" }

// payload (these are called "claims")
{
  "sub": "user_42",            // subject â€” who this token is about
  "name": "Cle",
  "iss": "auth.example.com",   // issuer â€” who created the token
  "aud": "api.example.com",    // audience â€” who should accept it
  "iat": 1735000000,           // issued at
  "exp": 1735003600            // expires
}

// signature â€” proves the token came from the issuer`}</Code>

      <H2 num="â—‡ 04">The big JWT mistake â€” payloads are not secret</H2>
      <P>
        The payload is base64-encoded. That is NOT encryption. Anyone with the token can paste
        it into <Kbd>jwt.io</Kbd> (or the decoder below) and read every claim. NEVER put passwords,
        password hashes, SSNs, full credit card numbers, or other sensitive data in a JWT payload.
        The cryptographic signature only verifies the payload was not tampered with â€” it does not
        hide what is inside.
      </P>
      <Callout kind="warn" title="WHAT BELONGS IN A JWT PAYLOAD">
        Identifiers (user ID, role, tenant), short metadata (issued at, expires at), and references
        to other data (a session ID you can look up). NOT actual secrets, NOT large profile blobs,
        NOT anything you would not want a casual attacker to read. If you need to ship sensitive
        data alongside a token, encrypt it separately and send the encrypted blob â€” or just send
        an opaque session ID and look the data up server-side.
      </Callout>

      <H2 num="â—‡ 05">JWT failure modes â€” and how attackers exploit them</H2>
      <P>
        Three JWT-specific bugs come up over and over in real bug bounty reports:
      </P>
      <ol className="text-zinc-300 text-[15px] leading-relaxed my-3 list-decimal pl-6 space-y-2 max-w-prose">
        <li>
          <strong className="text-rose-400">"alg: none" acceptance.</strong> The JWT spec includes
          an algorithm called <Kbd>none</Kbd>, meaning "no signature." Some libraries, when handed
          a token with <Kbd>alg: none</Kbd>, will skip verification and trust the payload as-is.
          Attacker forges a token with <Kbd>{`{"alg": "none"}`}</Kbd> and any claims they want;
          server accepts it. Fix: hardcode the algorithms you accept; never read <Kbd>alg</Kbd>{' '}
          from the token to decide how to verify it.
        </li>
        <li>
          <strong className="text-rose-400">Algorithm confusion.</strong> A server expecting RS256
          (asymmetric â€” different keys to sign and verify) is tricked into using HS256 (symmetric).
          Attacker forges a token signed with the server's PUBLIC key (which is, well, public);
          server uses that public key as a symmetric secret to verify; verification passes. Fix:
          same as above â€” pin the algorithm; never trust the <Kbd>alg</Kbd> header.
        </li>
        <li>
          <strong className="text-rose-400">Missing expiration check.</strong> Server validates the
          signature but forgets to check <Kbd>exp</Kbd>. A stolen token works forever. Fix: always
          check <Kbd>exp</Kbd>; use a JWT library that does it by default (most modern ones do).
        </li>
      </ol>

      <H2 num="â—‡ 06">Token lifetime â€” short access, longer refresh</H2>
      <P>
        The longer a token is valid, the more damage a leak does. Modern systems use a pair:
      </P>
      <ul className="text-zinc-300 text-[15px] leading-relaxed my-3 list-disc pl-6 space-y-2 max-w-prose">
        <li><strong className="text-cyan-300">Access token (JWT, short-lived).</strong> 5-15 minutes typical. Used on every API request. If leaked, the damage window is small.</li>
        <li><strong className="text-cyan-300">Refresh token (opaque, longer-lived).</strong> Days or weeks. Used only against a specific "issue a new access token" endpoint. Stored more carefully (httpOnly cookie or secure store). When access tokens expire, the client uses the refresh token to silently get a new one. Refresh tokens can be revoked server-side; that is their power.</li>
      </ul>

      <SectionLabel>practice</SectionLabel>
      <H2 num="â—‡ 07">Decode a JWT and see what it actually contains</H2>
      <P>
        Pre-loaded examples cover the main classes of JWT issue. Click through them. Watch the
        analysis panel call out each problem and explain why it matters. Or paste your own token
        (from a development environment â€” never paste a real production token into ANY web tool).
      </P>

      <JwtDecoder />

      <H2 num="â—‡ 08">Hardening checklist for authentication</H2>
      <ul className="text-zinc-300 text-[15px] leading-relaxed my-3 list-disc pl-6 space-y-1.5 max-w-prose">
        <li>âœ“ TLS on every endpoint, always</li>
        <li>âœ“ Credentials in <Kbd>Authorization</Kbd> header only; never in URLs or query strings</li>
        <li>âœ“ Use a battle-tested JWT library; never implement signature verification yourself</li>
        <li>âœ“ Hardcode the allowed algorithms server-side; never read <Kbd>alg</Kbd> from the token</li>
        <li>âœ“ Always check <Kbd>exp</Kbd>; reject expired tokens</li>
        <li>âœ“ Validate <Kbd>iss</Kbd> (issuer) and <Kbd>aud</Kbd> (audience) claims against expected values</li>
        <li>âœ“ Short access-token lifetimes (15 min); separate longer-lived refresh tokens</li>
        <li>âœ“ Use sufficiently strong signing keys; rotate them on a schedule and immediately on suspicion of compromise</li>
        <li>âœ“ Never put sensitive data in the payload</li>
        <li>âœ“ Rate-limit your auth endpoints aggressively â€” login is the #1 brute-force target</li>
      </ul>
      <Callout kind="info" title="WHAT'S NEXT">
        Authentication identifies the caller. Section 02 covers what the caller is allowed to DO
        once they are identified â€” authorization, OAuth flows, and the principle of least privilege.
      </Callout>
    </>
  );
}

