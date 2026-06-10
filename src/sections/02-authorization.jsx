/* Section 02 — Authorization.
 *
 * Prose + OAuth Flow Visualizer.
 *
 * The visualizer covers the 5 most common application shapes — web app,
 * SPA, mobile, server-to-server, CLI/device — and shows which OAuth flow
 * fits each, with a step-by-step exchange diagram. Includes the modern
 * defaults (PKCE everywhere user-facing) and explicitly calls out which
 * old flows (Implicit, Password) are deprecated and why.
 *
 * Also covers BOLA — the #1 OWASP API security issue — in the prose,
 * with a side-by-side bad/good code example.
 */

import { useState } from 'react';
import { Sparkles, User, Server, Smartphone, ArrowDown, Globe, Cpu } from 'lucide-react';
import { Code, Callout, H2, P, Kbd, SectionLabel } from '../components/primitives.jsx';

// ───────────────────────────────────────────────────────────────────────
// OAuth Flow Visualizer interactive
// ───────────────────────────────────────────────────────────────────────

const ACTOR_STYLES = {
  USER:   { color: 'text-zinc-300',  bg: 'bg-zinc-800/60',  border: 'border-zinc-700' },
  APP:    { color: 'text-cyan-300',  bg: 'bg-cyan-300/10',  border: 'border-cyan-300/40' },
  AUTH:   { color: 'text-orange-300',bg: 'bg-orange-400/10',border: 'border-orange-400/40' },
  API:    { color: 'text-violet-300',bg: 'bg-violet-300/10',border: 'border-violet-300/40' },
  DEVICE: { color: 'text-cyan-300',  bg: 'bg-cyan-300/10',  border: 'border-cyan-300/40' },
};

const AUTHCODE_PKCE_STEPS = [
  { actor: 'APP', action: 'Generate a random "code_verifier" and its SHA-256 hash "code_challenge". Keep the verifier; send the challenge.' },
  { actor: 'APP', action: 'Redirect user to Auth Server', data: 'client_id, redirect_uri, code_challenge, scope, state' },
  { actor: 'USER', action: 'Logs in at the Auth Server (password, MFA, whatever the auth server requires)' },
  { actor: 'AUTH', action: 'Verifies user, redirects back to app\'s redirect_uri', data: 'authorization_code, state' },
  { actor: 'APP', action: 'Exchanges the code at Auth Server\'s token endpoint', data: 'authorization_code, code_verifier, client_id' },
  { actor: 'AUTH', action: 'Checks that SHA-256(code_verifier) == code_challenge — proves the same app started and finished the flow', data: '→ access_token, refresh_token, id_token (if OIDC)' },
  { actor: 'APP', action: 'Stores tokens, uses access_token in every API call' },
];

const CLIENT_CREDENTIALS_STEPS = [
  { actor: 'APP', action: 'Sends a token request to the Auth Server', data: 'client_id, client_secret, scope, grant_type=client_credentials' },
  { actor: 'AUTH', action: 'Verifies the client_secret, issues a token', data: '→ access_token' },
  { actor: 'APP', action: 'Calls the API with the access_token in the Authorization header' },
];

const DEVICE_CODE_STEPS = [
  { actor: 'DEVICE', action: 'Requests device authorization from Auth Server', data: 'client_id, scope' },
  { actor: 'AUTH', action: 'Returns a code pair', data: 'device_code (for the device), user_code "BJVR-WXLP" (for the user), verification_uri "https://example.com/device"' },
  { actor: 'DEVICE', action: 'Shows the user_code and verification_uri on its screen' },
  { actor: 'USER', action: 'Opens the verification_uri on a phone or laptop, enters the user_code, logs in normally' },
  { actor: 'DEVICE', action: 'Meanwhile, polls Auth Server every few seconds with the device_code' },
  { actor: 'AUTH', action: 'Once user has authorized, responds with tokens', data: '→ access_token, refresh_token' },
  { actor: 'DEVICE', action: 'Stops polling, uses the access_token' },
];

const SCENARIOS = [
  {
    id: 'web-app',
    icon: Globe,
    label: 'Traditional web app',
    blurb: 'Server-rendered (Django, Rails, Express). Has a backend that can hold secrets.',
    flow: 'Authorization Code + PKCE',
    why: 'Backend can keep a client_secret AND PKCE protects the code-in-transit. Modern best practice uses both; OAuth 2.1 makes PKCE mandatory even when you have a secret.',
    steps: AUTHCODE_PKCE_STEPS,
    examples: ['Login with Google on a Rails app', 'GitHub Enterprise SSO', 'Login with Microsoft on a Django app'],
    notRecommended: [
      { flow: 'Implicit', reason: 'Deprecated. Tokens returned in URL fragments — exposed in browser history.' },
      { flow: 'Password Grant', reason: 'Deprecated. App handles the user\'s password directly — defeats the point of OAuth.' },
    ],
  },
  {
    id: 'spa',
    icon: Cpu,
    label: 'Single-page app (SPA)',
    blurb: 'Pure browser app (React, Vue, Svelte). No backend that can keep secrets.',
    flow: 'Authorization Code + PKCE',
    why: 'PKCE is mandatory because the browser cannot hold a client_secret. The code_verifier never leaves the SPA; the code_challenge that hits the network is useless without it.',
    steps: AUTHCODE_PKCE_STEPS,
    examples: ['Notion web app', 'Linear', 'Vercel dashboard'],
    notRecommended: [
      { flow: 'Implicit', reason: 'Deprecated. Was the default for SPAs pre-2020; PKCE replaces it.' },
      { flow: 'Client Credentials', reason: 'There is a user in the loop here; Client Credentials is for server-to-server only.' },
    ],
  },
  {
    id: 'mobile',
    icon: Smartphone,
    label: 'Mobile native app (iOS/Android)',
    blurb: 'Same secret problem as SPA — no way to safely keep a client_secret on a user device.',
    flow: 'Authorization Code + PKCE',
    why: 'PKCE is the only way for a native app to prove it\'s the same client across the redirect. Use the system browser (SFSafariViewController on iOS, Chrome Custom Tabs on Android) — NOT an embedded WebView, which lets your app see the user\'s password.',
    steps: AUTHCODE_PKCE_STEPS,
    examples: ['Spotify mobile sign-in', 'GitHub mobile app', 'Slack mobile'],
    notRecommended: [
      { flow: 'Embedded WebView for login', reason: 'Lets your app intercept the password. Apple and Google reject apps that do this.' },
      { flow: 'Password Grant', reason: 'Same problem — your app should NEVER see the user\'s password.' },
    ],
  },
  {
    id: 's2s',
    icon: Server,
    label: 'Server-to-server',
    blurb: 'One service calling another. No user involved. Both sides are trusted servers.',
    flow: 'Client Credentials',
    why: 'No user in the loop, so no Authorization Code or redirects. The calling service is itself the principal; client_secret proves who it is.',
    steps: CLIENT_CREDENTIALS_STEPS,
    examples: ['Your backend calling the Stripe API', 'Cron job posting to Slack', 'Microservice-to-microservice auth'],
    notRecommended: [
      { flow: 'Authorization Code', reason: 'Requires a user-driven browser redirect. No user here.' },
      { flow: 'Hardcoded API keys in source', reason: 'Not technically OAuth, but worth saying: don\'t. Use environment variables; rotate regularly.' },
    ],
  },
  {
    id: 'cli',
    icon: User,
    label: 'CLI / IoT device',
    blurb: 'No browser, or input-limited browser. Think: GitHub CLI on a server, smart-TV apps.',
    flow: 'Device Code',
    why: 'The device has no good way to handle a redirect-based flow. Instead, the user authorizes the device on a SEPARATE device (their phone or laptop) by entering a short code.',
    steps: DEVICE_CODE_STEPS,
    examples: ['gh auth login', 'Netflix on a smart TV', 'AWS CLI sign-in', 'Google sign-in on Apple TV'],
    notRecommended: [
      { flow: 'Authorization Code', reason: 'No browser on the device to redirect through.' },
      { flow: 'Password Grant', reason: 'Asking the user to type their password into a CLI is bad UX and bad security.' },
    ],
  },
];

function StepRow({ step, index }) {
  const style = ACTOR_STYLES[step.actor];
  return (
    <div className="flex gap-3 items-start">
      <div className="flex flex-col items-center shrink-0" style={{ width: '80px' }}>
        <div className={`text-[10px] tracking-[0.2em] font-bold px-2 py-1 border ${style.color} ${style.border} ${style.bg} w-full text-center`}
          style={{ fontFamily: 'JetBrains Mono, monospace' }}>
          {step.actor}
        </div>
        <div className="text-zinc-600 text-[10px] mt-0.5"
          style={{ fontFamily: 'JetBrains Mono, monospace' }}>
          step {index + 1}
        </div>
      </div>
      <div className="flex-1 pt-1">
        <div className="text-zinc-200 text-[13.5px] leading-relaxed">
          {step.action}
        </div>
        {step.data && (
          <div className={`mt-1 text-[12px] ${step.data.startsWith('→') ? 'text-orange-300' : 'text-cyan-300'}`}
            style={{ fontFamily: 'JetBrains Mono, monospace' }}>
            {step.data}
          </div>
        )}
      </div>
    </div>
  );
}

function OAuthVisualizer() {
  const [idx, setIdx] = useState(0);
  const scenario = SCENARIOS[idx];
  const Icon = scenario.icon;

  return (
    <div className="my-6 border border-cyan-300/30 bg-zinc-900/40">
      <div className="flex items-center justify-between bg-zinc-950 px-4 py-2.5 border-b border-cyan-300/30">
        <div className="flex items-center gap-2">
          <Sparkles size={14} className="text-cyan-300" />
          <span className="text-cyan-300 text-[11px] tracking-[0.25em] uppercase font-semibold"
            style={{ fontFamily: 'JetBrains Mono, monospace' }}>
            interactive · oauth flow visualizer
          </span>
        </div>
      </div>

      <div className="p-4">
        {/* Scenario picker */}
        <div className="text-zinc-500 text-[9.5px] tracking-[0.25em] uppercase mb-2"
          style={{ fontFamily: 'JetBrains Mono, monospace' }}>
          I am building a...
        </div>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-1.5 mb-4">
          {SCENARIOS.map((s, i) => {
            const SIcon = s.icon;
            return (
              <button key={s.id} onClick={() => setIdx(i)}
                className={`px-2.5 py-2 border text-[11.5px] transition-colors flex items-center gap-2 ${
                  i === idx
                    ? 'border-cyan-300 bg-cyan-300/15 text-cyan-200'
                    : 'border-zinc-700 text-zinc-400 hover:border-cyan-300/50 hover:text-zinc-200'
                }`}
                style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                <SIcon size={13} className="shrink-0" />
                <span className="text-left">{s.label}</span>
              </button>
            );
          })}
        </div>

        {/* Scenario description */}
        <div className="mb-4 p-3 border border-zinc-800 bg-zinc-900/40 flex items-start gap-3">
          <Icon size={20} className="text-cyan-300 shrink-0 mt-1" />
          <div>
            <div className="text-zinc-100 text-[15px] font-semibold mb-1"
              style={{ fontFamily: 'Bricolage Grotesque, sans-serif' }}>
              {scenario.label}
            </div>
            <div className="text-zinc-400 text-[13px]">{scenario.blurb}</div>
          </div>
        </div>

        {/* Recommended flow */}
        <div className="mb-4 border border-cyan-300/40 bg-cyan-300/5 p-4">
          <div className="text-cyan-300 text-[10px] tracking-[0.25em] uppercase font-semibold mb-1.5"
            style={{ fontFamily: 'JetBrains Mono, monospace' }}>
            recommended flow
          </div>
          <div className="text-zinc-100 text-[16px] font-semibold mb-2"
            style={{ fontFamily: 'Bricolage Grotesque, sans-serif' }}>
            {scenario.flow}
          </div>
          <div className="text-zinc-300 text-[13.5px] leading-relaxed">{scenario.why}</div>
        </div>

        {/* Step-by-step */}
        <div className="mb-4">
          <div className="text-zinc-500 text-[9.5px] tracking-[0.25em] uppercase mb-3"
            style={{ fontFamily: 'JetBrains Mono, monospace' }}>
            step-by-step
          </div>
          <div className="border border-zinc-800 bg-zinc-950/40 p-4 space-y-3">
            {scenario.steps.map((s, i) => (
              <div key={i}>
                <StepRow step={s} index={i} />
                {i < scenario.steps.length - 1 && (
                  <div className="flex justify-center my-2 ml-10">
                    <ArrowDown size={14} className="text-zinc-700" />
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Not recommended */}
        <div className="mb-4 border border-rose-400/30 bg-rose-400/5 p-4">
          <div className="text-rose-400 text-[10px] tracking-[0.25em] uppercase font-semibold mb-2"
            style={{ fontFamily: 'JetBrains Mono, monospace' }}>
            not recommended for this scenario
          </div>
          <div className="space-y-2">
            {scenario.notRecommended.map((nr, i) => (
              <div key={i} className="text-[13px]">
                <span className="text-rose-300 font-semibold mr-2">{nr.flow}</span>
                <span className="text-zinc-400">— {nr.reason}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Real-world examples */}
        <div className="border border-zinc-800 bg-zinc-900/40 p-3">
          <div className="text-zinc-500 text-[9.5px] tracking-[0.25em] uppercase mb-1.5"
            style={{ fontFamily: 'JetBrains Mono, monospace' }}>
            real-world examples
          </div>
          <div className="flex flex-wrap gap-1.5">
            {scenario.examples.map((ex, i) => (
              <span key={i} className="px-2 py-0.5 border border-zinc-700 text-zinc-300 text-[11.5px]"
                style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                {ex}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ───────────────────────────────────────────────────────────────────────
// Section content
// ───────────────────────────────────────────────────────────────────────

export default function Section02_Authz() {
  return (
    <>
      <SectionLabel>section 02</SectionLabel>
      <h2 className="text-zinc-50 text-[28px] leading-tight mb-3"
        style={{ fontFamily: 'Bricolage Grotesque, sans-serif', fontWeight: 600 }}>
        Authorization — what can you do?
      </h2>
      <P>
        Authentication established who is calling. Authorization decides what they are allowed to
        do. These two get conflated constantly — even in HTTP status codes, where 401 is named
        "Unauthorized" but actually means authentication failed. They are different problems with
        different solutions, and the bugs they produce hit different parts of your system.
      </P>

      <H2 num="◇ 01">AuthN vs AuthZ — the distinction that matters</H2>
      <Code id="authn-vs-authz" lang="text">{`AUTHENTICATION (AuthN)     AUTHORIZATION (AuthZ)
──────────────────────     ──────────────────────
"Who are you?"             "What can you do?"
Identity check             Permission check
Runs once per session       Runs on every protected operation
Failures: 401              Failures: 403
JWT, OAuth tokens, cookies  Roles, scopes, ACLs, policies`}</Code>
      <P>
        Authentication runs once when you log in. Authorization runs every time you touch anything
        protected. A bug in authentication lets the wrong person in. A bug in authorization lets the
        right person do the wrong things — usually worse, because the audit trail will show a
        legitimate logged-in user did it.
      </P>

      <H2 num="◇ 02">Permission models — pick your poison</H2>
      <P>
        Three common ways to model "who can do what":
      </P>
      <ul className="text-zinc-300 text-[15px] leading-relaxed my-3 list-disc pl-6 space-y-2 max-w-prose">
        <li>
          <strong className="text-cyan-300">RBAC — Role-Based Access Control.</strong> Users are
          assigned roles ("admin", "editor", "viewer"); roles have permissions. Simple, easy to
          audit, the default for most apps. Breaks down when permissions need to depend on context
          ("admin of this team but not that team").
        </li>
        <li>
          <strong className="text-cyan-300">ABAC — Attribute-Based Access Control.</strong>{' '}
          Permissions are expressed as policies over attributes (user.department == resource.department
          AND user.clearance &gt;= resource.classification). More flexible, harder to reason about, used
          in enterprise systems with complex compliance needs.
        </li>
        <li>
          <strong className="text-cyan-300">ReBAC — Relationship-Based Access Control.</strong>{' '}
          Permissions follow graph relationships ("user owns document", "user is member of group
          that has access"). The model Google's Zanzibar uses internally. Best fit for social
          products and complex sharing models (Docs, Notion, Figma).
        </li>
      </ul>
      <P>
        For most APIs: start with RBAC, document the roles explicitly, and reach for ABAC or
        ReBAC only when RBAC stops fitting. Premature flexibility is its own bug source.
      </P>

      <H2 num="◇ 03">Scopes — fine-grained permissions on tokens</H2>
      <P>
        OAuth tokens carry <em>scopes</em> — strings declaring what the token is allowed to do.
        Scopes let you issue different tokens to different clients without changing the user's
        underlying permissions.
      </P>
      <Code id="scopes-example" lang="text">{`# A GitHub OAuth token issued to a backup tool, scoped to read-only repo access:
{
  "scopes": ["repo:read", "user:email"]
}

# That same user's session token (used by github.com itself) has wider scope:
{
  "scopes": ["repo", "admin:org", "user"]
}

# Different tokens. Same user. Different blast radius if either leaks.`}</Code>
      <P>
        The Authorization Code flow lets users PICK which scopes to grant when authorizing a
        third-party app. That is why "Continue with Google" shows a screen listing exactly which
        permissions the app is asking for. Always ask for the minimum scope set; never request
        everything just to be safe.
      </P>

      <H2 num="◇ 04">Principle of least privilege</H2>
      <Callout kind="info" title="THE ONE PRINCIPLE THAT COVERS HALF OF AUTHORIZATION">
        Every token, every service account, every API key should have the minimum permissions
        needed for its job. A backup service does not need write access. A read-only dashboard
        does not need delete. A microservice that handles billing does not need access to inventory.
        The smaller the permission set, the smaller the damage when something leaks. This is the
        single most repeated rule in security and the single most violated one in real codebases.
      </Callout>

      <H2 num="◇ 05">OAuth 2.0 — what it actually is</H2>
      <P>
        OAuth is a protocol for letting users grant a third-party app limited access to their data
        on another service WITHOUT giving that app their password. "Login with GitHub" works
        because OAuth issues your app a token that can act on a user's behalf, scoped to whatever
        permissions the user agreed to, without your app ever seeing their GitHub password.
      </P>
      <P>
        OAuth 2.0 (2012) defines several different <em>flows</em> for different situations. You
        do not need to know all of them; you need to know which one to pick for what you are
        building. The visualizer below covers the five cases that cover ~99% of real apps.
      </P>
      <Callout kind="warn" title="OAUTH IS AUTHORIZATION, NOT AUTHENTICATION">
        Subtle but important: OAuth was designed to delegate permission, not to prove identity.
        For identity ("this user is genuinely Cle"), you want OpenID Connect (OIDC) — a thin
        layer built on top of OAuth that adds an <Kbd>id_token</Kbd> with verified claims about
        the user. Almost every "Login with X" button you see uses OIDC, not plain OAuth. The
        flows look identical from outside; OIDC just adds the identity layer.
      </Callout>

      <SectionLabel>practice</SectionLabel>
      <H2 num="◇ 06">Pick the right OAuth flow for what you're building</H2>
      <P>
        Five scenarios. Pick what you are building; see which flow fits, why, and the
        step-by-step exchange between user, app, and auth server. The flows that do NOT fit are
        called out with the specific reason they are wrong here.
      </P>

      <OAuthVisualizer />

      <H2 num="◇ 07">BOLA — the #1 API security bug</H2>
      <P>
        BOLA stands for Broken Object Level Authorization. It is the top item on the OWASP API
        Security Top 10 — the most common authorization bug in production APIs, by a wide margin.
      </P>
      <P>
        The pattern: your endpoint authenticates the user (great), then fetches whatever object
        was named in the URL (fine), but never checks whether the user is actually allowed to see
        THAT specific object. So User A, logged in legitimately, calls{' '}
        <Kbd>GET /accounts/42</Kbd> and gets User B's account.
      </P>
      <Code id="bola-bad" lang="python">{`# BAD — returns ANY account if the user is logged in
@app.get("/accounts/{account_id}")
def get_account(account_id: int, current_user = Depends(auth)):
    return db.query(Account).get(account_id)
    # ^ no check that this account belongs to current_user`}</Code>
      <Code id="bola-good" lang="python">{`# GOOD — scope every query to the current user
@app.get("/accounts/{account_id}")
def get_account(account_id: int, current_user = Depends(auth)):
    account = db.query(Account).filter(
        Account.id == account_id,
        Account.user_id == current_user.id,
    ).first()
    if not account:
        raise HTTPException(404)
    return account`}</Code>
      <Callout kind="danger" title="THE FIX IS A HABIT, NOT A FEATURE">
        BOLA gets shipped over and over because the "auth check" feels done — the user is logged
        in, the framework returned <Kbd>current_user</Kbd> — but checking the user against the
        SPECIFIC object got skipped. The cure is a habit: every query against an owned resource
        gets filtered by the owning user. Centralize it in a repository helper if you can. Every
        time you write <Kbd>db.query(X).get(id)</Kbd> for a user-owned object, pause and ask:
        "did I just authorize that?"
      </Callout>

      <H2 num="◇ 08">Other authorization failure modes worth knowing</H2>
      <ul className="text-zinc-300 text-[15px] leading-relaxed my-3 list-disc pl-6 space-y-2 max-w-prose">
        <li>
          <strong className="text-rose-400">Privilege escalation via mass assignment.</strong>{' '}
          User sends <Kbd>{`{"name": "Cle", "is_admin": true}`}</Kbd> in their profile update;
          your framework happily assigns every field including the admin flag. Fix: never use
          "accept whatever the client sends" patterns. Whitelist the fields each endpoint is
          allowed to update.
        </li>
        <li>
          <strong className="text-rose-400">Function-level authorization gaps.</strong> The UI
          hides the "delete user" button for non-admins, but the underlying API endpoint does not
          check the role. Attacker hits the endpoint directly. Fix: never rely on the UI to enforce
          permissions; check on the server every time.
        </li>
        <li>
          <strong className="text-rose-400">Token scope abuse.</strong> A token issued for{' '}
          <Kbd>read:profile</Kbd> is used against <Kbd>POST /users/me</Kbd> and your server
          forgets to check scopes. Fix: scope checks at the endpoint, not just at the auth layer.
        </li>
        <li>
          <strong className="text-rose-400">Stale permissions.</strong> User was an admin when
          their token was issued; got demoted; the token still says "admin" because nobody revoked
          it. Fix: short-lived access tokens (the section-01 refresh-token pattern); revoke refresh
          tokens on permission changes.
        </li>
      </ul>

      <H2 num="◇ 09">Hardening checklist for authorization</H2>
      <ul className="text-zinc-300 text-[15px] leading-relaxed my-3 list-disc pl-6 space-y-1.5 max-w-prose">
        <li>✓ Every protected endpoint runs an authorization check, not just an authentication check</li>
        <li>✓ Object-level checks: every query against user-owned data is filtered by the owning user</li>
        <li>✓ Whitelist updatable fields per endpoint; never blindly assign request bodies</li>
        <li>✓ Server-side enforcement of every permission — UI hiding is not a security boundary</li>
        <li>✓ Scopes checked at the endpoint, not just at login</li>
        <li>✓ Short access-token lifetimes so permission changes propagate quickly</li>
        <li>✓ Default to deny: unknown role / missing scope = no access</li>
        <li>✓ Audit log every authorization decision on sensitive endpoints</li>
        <li>✓ Use the system browser (not a WebView) for OAuth in mobile apps</li>
      </ul>
      <Callout kind="info" title="WHAT'S NEXT">
        Authentication identifies. Authorization permits. Section 03 covers what happens when the
        attacker bypasses both — the common attack surfaces of an API and the patterns that
        produce each one.
      </Callout>
    </>
  );
}
