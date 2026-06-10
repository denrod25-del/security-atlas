/* Section 04 — Defense in depth. Closing section.
 *
 * Prose + Security Headers Auditor.
 *
 * The auditor: three scenarios at increasing security maturity. Student
 * examines response headers from each and ticks off which security headers
 * are missing. Per-header feedback teaches what each one defends against.
 *
 * Closes with the atlas-wide wrap pointing at Atlas 19 (Production APIs).
 *
 * All long descriptive strings use backticks to avoid the apostrophe-in-
 * single-quote parse traps from section 03.
 */

import { useState, useMemo } from 'react';
import { Sparkles, Check, X, RotateCcw, ShieldCheck, ShieldAlert } from 'lucide-react';
import { Code, Callout, H2, P, Kbd, SectionLabel } from '../components/primitives.jsx';

// ───────────────────────────────────────────────────────────────────────
// Security Headers Auditor interactive
// ───────────────────────────────────────────────────────────────────────

const HEADER_CATALOG = [
  {
    name: 'Strict-Transport-Security',
    prevents: `Forces browsers to use HTTPS for your domain for a defined duration. Without it, the first request to your site is HTTP (before the redirect to HTTPS), and an on-path attacker can MITM that first request — strip TLS, redirect to a fake site. HSTS tells the browser "never speak HTTP to this domain again."`,
  },
  {
    name: 'Content-Security-Policy',
    prevents: `Tells browsers which sources are allowed for scripts, styles, and other resources. Without CSP, an XSS injection that gets inline JavaScript onto your page executes with full privileges. With a strict CSP, even successful injections are largely neutralized — the injected script gets blocked by the policy before it runs.`,
  },
  {
    name: 'X-Content-Type-Options',
    prevents: `Tells browsers to trust the Content-Type you sent and NOT to guess (sniff). Without nosniff, a browser can decide a response is actually JavaScript or HTML even if you said application/json — turning an innocent-looking endpoint into an XSS vector if an attacker controls part of the response.`,
  },
  {
    name: 'X-Frame-Options',
    prevents: `Prevents other pages from embedding yours in an iframe. Defends against clickjacking — where an attacker loads your real page in a transparent iframe over a decoy, then tricks users into clicking buttons on YOUR page without realizing. (Modern alternative: frame-ancestors directive in CSP.)`,
  },
  {
    name: 'Referrer-Policy',
    prevents: `Controls what URL info gets sent in the Referer header when users click links from your site. Without it, full URLs leak — including sensitive query parameters like password reset tokens. The safe default value is strict-origin-when-cross-origin.`,
  },
  {
    name: 'Permissions-Policy',
    prevents: `Disables browser features your page does not use — camera, microphone, geolocation, USB, payment. Defense in depth: if an attacker gets script execution on your page, they cannot suddenly request camera access. Increasingly important as browsers expose more powerful APIs.`,
  },
  {
    name: 'Cross-Origin-Opener-Policy',
    prevents: `Isolates your page from other origins. Without COOP, a popup window (yours or someone else's) can access your window object via window.opener. With COOP set to same-origin, those cross-origin references get nulled — preventing some cross-site leakage attacks.`,
  },
];

const SCENARIOS = [
  {
    id: 'bare',
    label: 'Scenario 1 · Bare API server',
    blurb: `A freshly-deployed Express server with no security configuration. Default headers only.`,
    response: `HTTP/1.1 200 OK
Server: nginx/1.18.0
Content-Type: application/json
Content-Length: 482
Date: Sun, 08 Jun 2026 12:00:00 GMT
X-Powered-By: Express`,
    present: new Set(),
  },
  {
    id: 'helmet',
    label: 'Scenario 2 · After adding helmet',
    blurb: `The team installed helmet middleware. It added several defaults but does not configure a CSP automatically.`,
    response: `HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 482
Date: Sun, 08 Jun 2026 12:00:00 GMT
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
X-DNS-Prefetch-Control: off`,
    present: new Set(['Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']),
  },
  {
    id: 'mature',
    label: 'Scenario 3 · Mature production server',
    blurb: `A well-configured production setup. One specific header still tends to get forgotten because it is newer than the others.`,
    response: `HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 482
Date: Sun, 08 Jun 2026 12:00:00 GMT
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Cross-Origin-Opener-Policy: same-origin
Cache-Control: no-store`,
    present: new Set(['Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']),
  },
];

function HeadersAuditor() {
  const [idx, setIdx] = useState(0);
  const [selected, setSelected] = useState(() => Object.fromEntries(SCENARIOS.map(s => [s.id, new Set()])));
  const [submitted, setSubmitted] = useState({});

  const scenario = SCENARIOS[idx];
  const sel = selected[scenario.id];
  const isSubmitted = !!submitted[scenario.id];

  const toggle = (name) => {
    if (isSubmitted) return;
    const next = new Set(sel);
    if (next.has(name)) next.delete(name);
    else next.add(name);
    setSelected(prev => ({ ...prev, [scenario.id]: next }));
  };

  const submit = () => setSubmitted(prev => ({ ...prev, [scenario.id]: true }));

  const reset = () => {
    setSelected(prev => ({ ...prev, [scenario.id]: new Set() }));
    setSubmitted(prev => ({ ...prev, [scenario.id]: false }));
  };

  const feedback = useMemo(() => {
    if (!isSubmitted) return null;
    const rows = HEADER_CATALOG.map(h => {
      const isPresent = scenario.present.has(h.name);
      const isPicked = sel.has(h.name);
      let verdict;
      if (isPicked && !isPresent) verdict = 'tp';
      else if (!isPicked && isPresent) verdict = 'tn';
      else if (isPicked && isPresent) verdict = 'fp';
      else verdict = 'fn';
      return { header: h, isPresent, isPicked, verdict };
    });
    const correct = rows.filter(r => r.verdict === 'tp' || r.verdict === 'tn').length;
    return { rows, correct, total: rows.length };
  }, [isSubmitted, sel, scenario]);

  return (
    <div className="my-6 border border-cyan-300/30 bg-zinc-900/40">
      <div className="flex items-center justify-between bg-zinc-950 px-4 py-2.5 border-b border-cyan-300/30">
        <div className="flex items-center gap-2">
          <Sparkles size={14} className="text-cyan-300" />
          <span className="text-cyan-300 text-[11px] tracking-[0.25em] uppercase font-semibold"
            style={{ fontFamily: 'JetBrains Mono, monospace' }}>
            interactive · security headers auditor
          </span>
        </div>
      </div>

      <div className="p-4">
        <div className="flex flex-wrap gap-1.5 mb-4">
          {SCENARIOS.map((s, i) => (
            <button key={s.id} onClick={() => setIdx(i)}
              className={`px-3 py-1.5 border text-[11.5px] transition-colors ${
                i === idx
                  ? 'border-cyan-300 bg-cyan-300/15 text-cyan-200'
                  : 'border-zinc-700 text-zinc-400 hover:border-cyan-300/50 hover:text-zinc-200'
              }`}
              style={{ fontFamily: 'JetBrains Mono, monospace' }}>
              {s.label}
            </button>
          ))}
        </div>

        <div className="mb-4 text-zinc-400 text-[13px] leading-relaxed italic">
          {scenario.blurb}
        </div>

        <div className="mb-4">
          <div className="text-zinc-500 text-[9.5px] tracking-[0.25em] uppercase mb-1.5"
            style={{ fontFamily: 'JetBrains Mono, monospace' }}>
            response headers
          </div>
          <pre className="bg-zinc-950/60 border border-zinc-800 p-3 text-[12px] text-zinc-200 overflow-x-auto leading-relaxed"
            style={{ fontFamily: 'JetBrains Mono, monospace' }}>
            <code>{scenario.response}</code>
          </pre>
        </div>

        <div className="mb-4">
          <div className="text-zinc-500 text-[9.5px] tracking-[0.25em] uppercase mb-2"
            style={{ fontFamily: 'JetBrains Mono, monospace' }}>
            which security headers are MISSING? (select all that apply)
          </div>
          <div className="grid sm:grid-cols-2 gap-1.5">
            {HEADER_CATALOG.map(h => {
              const picked = sel.has(h.name);
              const fbRow = feedback?.rows.find(r => r.header.name === h.name);
              let cls = 'border-zinc-700 text-zinc-300 hover:border-cyan-300/50';
              if (isSubmitted && fbRow) {
                if (fbRow.verdict === 'tp') cls = 'border-cyan-300 bg-cyan-300/15 text-cyan-200';
                else if (fbRow.verdict === 'tn') cls = 'border-zinc-700 text-zinc-500';
                else if (fbRow.verdict === 'fp') cls = 'border-rose-400/60 bg-rose-400/10 text-rose-300';
                else if (fbRow.verdict === 'fn') cls = 'border-orange-400/60 bg-orange-400/10 text-orange-300';
              } else if (picked) {
                cls = 'border-orange-400 bg-orange-400/15 text-orange-200';
              }
              return (
                <button key={h.name} onClick={() => toggle(h.name)}
                  disabled={isSubmitted}
                  className={`px-2.5 py-1.5 border text-left transition-colors flex items-center gap-2 ${cls}`}
                  style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                  <span className={`w-3 h-3 border ${picked ? 'border-current' : 'border-zinc-600'} flex items-center justify-center text-[10px] shrink-0`}>
                    {picked && <Check size={9} strokeWidth={3} />}
                  </span>
                  <span className="text-[11.5px]">{h.name}</span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex gap-2 mb-4">
          {!isSubmitted ? (
            <button onClick={submit}
              className="px-4 py-2 border border-cyan-300 bg-cyan-300/10 text-cyan-200 hover:bg-cyan-300/20 transition-colors text-[12px] tracking-[0.2em] uppercase font-semibold"
              style={{ fontFamily: 'JetBrains Mono, monospace' }}>
              audit
            </button>
          ) : (
            <button onClick={reset}
              className="px-4 py-2 border border-zinc-700 text-zinc-400 hover:border-cyan-300/50 hover:text-zinc-200 transition-colors text-[12px] tracking-[0.2em] uppercase font-semibold flex items-center gap-2"
              style={{ fontFamily: 'JetBrains Mono, monospace' }}>
              <RotateCcw size={11} /> reset this scenario
            </button>
          )}
        </div>

        {feedback && (
          <div className="space-y-3">
            <div className={`border p-3 ${
              feedback.correct === feedback.total
                ? 'border-cyan-300 bg-cyan-300/10'
                : 'border-orange-400/40 bg-orange-400/5'
            }`}>
              <div className={`text-[11px] tracking-[0.25em] uppercase font-semibold mb-1 ${
                feedback.correct === feedback.total ? 'text-cyan-300' : 'text-orange-400'
              }`} style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                {feedback.correct === feedback.total ? '✓ perfect audit' : `${feedback.correct} of ${feedback.total} correct`}
              </div>
              <div className="text-zinc-300 text-[12.5px] leading-relaxed">
                {feedback.correct === feedback.total
                  ? `You classified every header correctly. The cyan highlights below show each missing header and what attack it prevents.`
                  : `Per-header breakdown below. Orange = you missed a missing header. Rose = you flagged one that was already there.`}
              </div>
            </div>

            <div className="space-y-2">
              {feedback.rows.map(row => {
                const { header, verdict } = row;
                let icon, color, label;
                if (verdict === 'tp')      { icon = ShieldCheck; color = 'text-cyan-300';    label = `correctly flagged as missing`; }
                else if (verdict === 'tn') { icon = ShieldCheck; color = 'text-cyan-300/60'; label = `correctly left alone (already present)`; }
                else if (verdict === 'fp') { icon = X;           color = 'text-rose-400';    label = `you flagged this — but it WAS present`; }
                else                       { icon = ShieldAlert; color = 'text-orange-400';  label = `you missed this — was NOT present`; }
                const Icon = icon;
                return (
                  <div key={header.name} className="border border-zinc-800 bg-zinc-900/40 p-3">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <Icon size={13} className={color} />
                      <span className="text-zinc-100 text-[13px] font-semibold"
                        style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                        {header.name}
                      </span>
                      <span className={`text-[10px] tracking-[0.2em] uppercase ${color}`}
                        style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                        {label}
                      </span>
                    </div>
                    {(verdict === 'tp' || verdict === 'fn') && (
                      <div className="text-zinc-300 text-[12.5px] leading-relaxed pl-5">
                        {header.prevents}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ───────────────────────────────────────────────────────────────────────
// Section content
// ───────────────────────────────────────────────────────────────────────

export default function Section04_Defense() {
  return (
    <>
      <SectionLabel>section 04</SectionLabel>
      <h2 className="text-zinc-50 text-[28px] leading-tight mb-3"
        style={{ fontFamily: 'Bricolage Grotesque, sans-serif', fontWeight: 600 }}>
        Defense in depth — layered security
      </h2>
      <P>
        Sections 01-03 were about specific defenses against specific attacks. This section is about
        the philosophy that ties them together: defense in depth. Assume any single defense will fail.
        Layer many cheap defenses so the next one catches what the last one missed. By the time
        an attacker has bypassed three or four layers, they have spent enough effort that you have
        likely noticed and stopped them.
      </P>

      <H2 num="◇ 01">The layered-defense mindset</H2>
      <P>Real production security looks like this:</P>
      <Code id="defense-layers" lang="text">{`LAYER                  WHAT IT DOES                              FAILS IF
─────                  ────────────                              ────────
TLS                    Encrypts traffic in flight                Certificates expire or get stolen
WAF / CDN              Blocks obvious attacks at the edge        Novel attack the WAF has never seen
Rate limiting          Slows credential stuffing / DDoS          Distributed attack across IPs
Authentication         Identifies the caller                     Stolen credentials or token leak
Authorization          Permits only allowed actions               BOLA or privilege-escalation bug
Input validation       Rejects malformed / hostile data          Validation gap, novel payload
Output encoding        Escapes content before serving            Encoding mismatch, sneaky payload
Security headers       Browsers enforce additional rules         Headers missing or misconfigured
Audit logging          Records what happened                     Logs not monitored, retention too short
Monitoring & alerting  Detects anomalies and pages humans         False-positive fatigue, blind spots`}</Code>
      <P>
        No single layer is sufficient. Every one of those rows has been the failure point in a real
        production breach. The point of defense in depth is that you do not have to perfect any
        single layer — you only have to make sure they collectively catch the things that matter.
      </P>

      <H2 num="◇ 02">TLS — table stakes</H2>
      <P>
        Encrypt everything in transit. Every endpoint, every environment, every internal service.
        Modern certificate automation (Let&apos;s Encrypt, AWS Certificate Manager, Cloudflare) makes
        this free and effortless. There is no remaining excuse for any HTTP endpoint in 2026.
      </P>
      <P>Beyond the basics:</P>
      <ul className="text-zinc-300 text-[15px] leading-relaxed my-3 list-disc pl-6 space-y-1.5 max-w-prose">
        <li>TLS 1.2 minimum; TLS 1.3 preferred. Disable 1.0 and 1.1.</li>
        <li>Strong cipher suites only. Modern defaults from Mozilla&apos;s SSL configurator are safe.</li>
        <li>Certificate auto-renewal monitored — expired certs become outages, fast.</li>
        <li>Internal service-to-service traffic also gets TLS (mutual TLS / mTLS in higher-security envs).</li>
        <li>HSTS header (covered in the auditor below) tells browsers to enforce HTTPS automatically.</li>
      </ul>

      <H2 num="◇ 03">Security headers — making browsers enforce your policies</H2>
      <P>
        HTTP response headers let you tell browsers how to handle your content. Used together, they
        catch entire classes of attack at the browser layer — even when bugs slip through your
        application code. The auditor below walks through the seven headers that matter most.
      </P>
      <P>
        The common pattern: install a library that sets sensible defaults (helmet for Express,
        django-csp / SecureHeaders for Django, Secure for FastAPI), then add or strengthen a few
        specific headers for your app. The library covers the basics; CSP is the one you almost
        always need to customize, because the right policy is unique to your app.
      </P>

      <H2 num="◇ 04">CORS — what it actually is</H2>
      <P>
        CORS (Cross-Origin Resource Sharing) is the browser feature that decides which other origins
        can call your API from a web page. It is widely misunderstood. Two key clarifications:
      </P>
      <Callout kind="info" title="CORS IS BROWSER-ENFORCED, NOT SERVER-ENFORCED">
        CORS is not a security control over your API. It is a security control the browser applies
        to JavaScript running on web pages. A determined attacker using curl or a custom client
        completely ignores CORS — your API still serves the response. CORS protects browser users
        from malicious websites; it does NOT protect your API from determined attackers. Your
        authentication and authorization layers are what protect the API itself.
      </Callout>
      <P>Common configuration mistakes:</P>
      <ul className="text-zinc-300 text-[15px] leading-relaxed my-3 list-disc pl-6 space-y-1.5 max-w-prose">
        <li><strong className="text-rose-400"><Kbd>Access-Control-Allow-Origin: *</Kbd> combined with credentials</strong> — browsers will refuse the response, but the misconfiguration suggests a misunderstanding. Specific origins or none.</li>
        <li><strong className="text-rose-400">Reflecting the Origin header back without validation</strong> — effectively the same as <Kbd>*</Kbd>, just less obvious. Always validate the origin against an allowlist before echoing it.</li>
        <li><strong className="text-rose-400">Allowing all methods + all headers + credentials</strong> — equivalent to disabling CORS, useful only in dev.</li>
      </ul>

      <H2 num="◇ 05">Secret rotation as a practice</H2>
      <P>
        Section 03 covered where secrets belong (env vars, secrets managers). This is the operational
        partner: rotating them on a schedule, and immediately on suspicion of compromise. The
        rotation runbook is the security control; the secrecy is the speed bump in front of it.
      </P>
      <P>A real rotation runbook lists, for each secret:</P>
      <ol className="text-zinc-300 text-[15px] leading-relaxed my-3 list-decimal pl-6 space-y-1.5 max-w-prose">
        <li>Where the secret is stored authoritatively (the source of truth)</li>
        <li>Every system that reads it (and how to update each one)</li>
        <li>The exact commands to generate a new value</li>
        <li>The exact commands to update each consumer</li>
        <li>How to verify the new value is working</li>
        <li>How to revoke the old value (or whether it auto-expires)</li>
        <li>Estimated time to complete the rotation start to finish</li>
      </ol>
      <P>
        Test the runbook quarterly. The rotation you have never practiced is the one that takes six
        hours and an outage when you need it most.
      </P>

      <H2 num="◇ 06">Logging and monitoring — you cannot defend what you cannot see</H2>
      <P>
        Every authentication attempt, every authorization decision on a sensitive endpoint, every
        rate-limit trigger, every 5xx error — log it. Not as a debugging tool; as an evidence trail.
        When something happens, the logs are the only way to know who, what, when, and how. Without
        them, post-incident response degrades to guessing.
      </P>
      <P>What to log:</P>
      <ul className="text-zinc-300 text-[15px] leading-relaxed my-3 list-disc pl-6 space-y-1.5 max-w-prose">
        <li>User ID (or anonymous request ID) for every protected request</li>
        <li>Endpoint, method, response status, response time</li>
        <li>Outcome of authentication decisions (success / failure / reason)</li>
        <li>Outcome of authorization checks on sensitive resources</li>
        <li>Source IP — but be deliberate about PII handling per your privacy policy</li>
        <li>Request ID propagated through downstream calls (distributed tracing)</li>
      </ul>
      <P>
        What NOT to log: passwords, full credit card numbers, tokens, full request bodies of sensitive
        endpoints. Sanitize on the way INTO the log line, not as a post-processing step that you might
        forget on some code path.
      </P>
      <Callout kind="tip" title="ALERT ON ANOMALIES, NOT STATIC THRESHOLDS">
        A static threshold (alert on more than 100 failed logins per minute) generates noise during
        normal busy periods and misses sophisticated attacks that stay just below. Anomaly-based
        monitoring (today is 10x yesterday for this user) catches real attacks earlier and silences
        the noise. Most cloud monitoring tools have this built in; use it.
      </Callout>

      <SectionLabel>practice</SectionLabel>
      <H2 num="◇ 07">Audit response headers across three scenarios</H2>
      <P>
        Three response-header snapshots: bare server, after-helmet, mature production. For each, tick
        which security headers are missing. The audit feedback tells you which ones you got right and —
        more importantly — what attack each missing header would have prevented.
      </P>

      <HeadersAuditor />

      <H2 num="◇ 08">What lives outside your application</H2>
      <P>
        Most of the layers in the diagram at the top of this section live outside your application
        code. A short tour:
      </P>
      <ul className="text-zinc-300 text-[15px] leading-relaxed my-3 list-disc pl-6 space-y-2 max-w-prose">
        <li>
          <strong className="text-cyan-300">CDN / edge proxy</strong> — Cloudflare, Fastly, CloudFront.
          Serves cached content; blocks obvious bots; provides DDoS absorption. Free tier covers most
          small-to-medium APIs and would have prevented several famous outages.
        </li>
        <li>
          <strong className="text-cyan-300">WAF (Web Application Firewall)</strong> — pattern matching
          on requests to block known attack signatures (SQL injection probes, common exploits). Cheap;
          imperfect; useful as one layer.
        </li>
        <li>
          <strong className="text-cyan-300">Bot management</strong> — separating real users from
          automated traffic. Increasingly important for login, signup, and anything credential-
          stuffing targets.
        </li>
        <li>
          <strong className="text-cyan-300">DDoS protection</strong> — usually part of the CDN.
          Volumetric attacks hit the CDN, not your origin.
        </li>
        <li>
          <strong className="text-cyan-300">Secrets manager</strong> — AWS Secrets Manager, HashiCorp
          Vault, GCP Secret Manager. Rotates credentials automatically; audit-logs every read; gives
          you the operational hooks for the runbook described above.
        </li>
      </ul>

      <H2 num="◇ 09">The hardening checklist — full</H2>
      <ul className="text-zinc-300 text-[15px] leading-relaxed my-3 list-disc pl-6 space-y-1.5 max-w-prose">
        <li>✓ TLS on every endpoint; HSTS to enforce it; certificates auto-renewing</li>
        <li>✓ Security headers configured (the seven from the auditor above)</li>
        <li>✓ CORS allowlist of specific origins; never echo Origin without validation</li>
        <li>✓ Auth + authz logged on every protected endpoint</li>
        <li>✓ Rate limits on sensitive endpoints; anomaly alerting on the rest</li>
        <li>✓ Secrets in a secrets manager; rotation runbook tested quarterly</li>
        <li>✓ Application logs centralized; PII sanitized at write time</li>
        <li>✓ Monitoring dashboards for 4xx/5xx rates, auth failures, latency outliers</li>
        <li>✓ Inventory of every endpoint your API exposes — old versions, deprecated routes</li>
        <li>✓ Dependency updates on a regular cadence; subscribe to security advisories</li>
        <li>✓ Incident response runbook with on-call rotation; rehearsed at least annually</li>
      </ul>

      {/* CLOSING WRAP — ties the whole atlas together */}
      <SectionLabel>end of atlas</SectionLabel>
      <H2 num="◆">What you can do now</H2>
      <P>Four sections back, "API security" was a vague category. Now you can:</P>
      <ul className="text-zinc-300 text-[15px] leading-relaxed my-3 list-disc pl-6 space-y-1.5 max-w-prose">
        <li><strong className="text-cyan-300">Identify yourself correctly</strong> — pick the right authentication mechanism, decode a JWT, spot common JWT bugs</li>
        <li><strong className="text-cyan-300">Authorize precisely</strong> — pick the right OAuth flow, scope tokens to least privilege, avoid BOLA on every protected endpoint</li>
        <li><strong className="text-cyan-300">Recognize attacks in code</strong> — see SQL injection, command injection, SSRF, path traversal, mass assignment, prompt injection, and the others before they ship</li>
        <li><strong className="text-cyan-300">Layer defenses</strong> — TLS, headers, CORS, secrets management, logging, monitoring — so a single bug never becomes a single breach</li>
      </ul>
      <P>
        Atlas 19 — Production APIs — closes this three-atlas series. It covers what happens when your
        API moves from "works on my laptop" to "serves a million requests an hour": caching strategies,
        idempotency, pagination at scale, observability, and the design choices that determine whether
        your API stays up under real load. Different shape of problem; same approach — see how it works,
        understand the trade-offs, build the muscle memory.
      </P>
      <Callout kind="win" title="THE SHAPE OF EVERY GOOD API">
        Every API that works at scale has the same shape underneath. Atlas 17 + Atlas 18 + the
        python-track APIs chapters cover most of it. Build something. Get attacked (every public API
        does, eventually). Apply what is in these atlases. Atlas 19 is the operational frosting on
        what you already know.
      </Callout>
      <div className="text-zinc-500 text-center text-[10.5px] tracking-[0.3em] uppercase mt-12 mb-4"
        style={{ fontFamily: 'JetBrains Mono, monospace' }}>
        ⛨ · atlas eighteen · complete
      </div>
    </>
  );
}
