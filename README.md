# API Security — Atlas #18 (B. Symbolic)

Authentication · Authorization · Attack surfaces · Defense in depth

Standalone Vite + React + Tailwind project. Build script uses
`node ./node_modules/vite/bin/vite.js build` to bypass Vercel's intermittent
bin-permission issue.

## Run locally
```
npm install
npm run dev          # http://localhost:5173
```

## Deploy
Push to GitHub. Connect at vercel.com/new. Auto-detects Vite. ~60s to live URL.

## Section status — all complete
- 01 Authentication      — JWT Decoder & Analyzer (5 example tokens, security analysis)
- 02 Authorization       — OAuth Flow Visualizer (5 scenarios, step-by-step diagrams)
- 03 Attack surfaces     — Vulnerability Identifier (10 snippets, 12-option menu)
- 04 Defense in depth    — Security Headers Auditor (3 scenarios, per-header feedback)

## Conventions
- Palette: cyan-300 primary, orange-400 accent
- Glyph: ⛨
- Type: Bricolage Grotesque · JetBrains Mono · Manrope
- Severity colors: critical=rose-400, high/medium=orange-400, low=zinc-700

## Series
- Atlas 17 — API Foundations (REST, GraphQL, versioning, errors)
- Atlas 18 — API Security (this one)
- Atlas 19 — Production APIs (planned)
