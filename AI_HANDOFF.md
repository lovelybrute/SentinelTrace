# SentinelTrace AI Handoff Document

## 1. Original project architecture
- Frontend: React 18, Vite, TailwindCSS, Framer Motion, Three.js, Recharts
- Backend: FastAPI, SQLAlchemy, SQLite (sentineltrace.db)
- Communication: REST APIs (JSON)

## 2. Features fully completed
- Phase 1: Core setup and design system.
- Phase 2: Navigation and application shell.
- Phase 3: Cinematic intro with session gating, skip/replay controls, reduced-motion handling, and a mobile 2D fallback.
- Phase 4: Cyber Command Center dashboard with lazy-loaded threat globe, backend-backed metrics, explicit demo fallbacks, recent-threat rail, and `.eml` upload actions.

## 3. Features partially completed
- None in Phases 1–4.

## 4. Features not yet started
- Email Analyzer (Holographic Forensic Lab)
- Forensic Modules (Intelligence OS)

## 5. Files created or modified
- web/tailwind.config.js (updated colors)
- web/src/components/intro/TeamBruteIntro.tsx (cinematic intro)
- web/src/components/dashboard/ThreatGlobe.tsx (interactive threat globe)
- web/src/pages/Dashboard.tsx (Cyber Command Center)
- web/src/App.tsx (session-gated intro)
- web/src/pages/Settings.tsx (intro controls)
- AI_HANDOFF.md (Created)
- TASK_PROGRESS.md (Created)

## 6. Important design and technical decisions
- Using #02070D / #06111C as deep navy structural backgrounds.
- Selected #00D9FF (Cyan) and #8B5CF6 (Violet) as primary intelligence and forensic markers.
- Keeping Vite+React stack, preparing to add robust Three.js components.

## 7. Backend APIs and response formats used
- Currently mapping existing endpoints: /analyze, /stats, /recent-threats, /threat-by-country, /cases, /search.

## 8. Commands required to run and test the project
- Backend: start_backend.bat or cd backend && uvicorn main:app --reload
- Frontend: start_frontend.bat or cd web && npm run dev

## 9. Current build, lint and test results
- `npm run typecheck`: pass.
- `npm run build`: pass.
- No frontend lint script is currently configured.
- Backend offline unit tests covering SPF, DKIM/DMARC, relay parsing, BEC, attachments, URLs, and ML disclosure pass 18/18.
- Backend API health, stats, and case-lifecycle tests pass 3/3.
- ML metrics API and model-loader tests pass; frontend Model Performance route builds successfully.
- Test dependencies are declared in `requirements-dev.txt`.
- Vite reports a non-blocking circular/manual chunk warning and a large Three.js vendor chunk.

## 10. Known bugs and remaining tasks
- Complete Phase 5 and Phase 6.
- Consider refining Vite vendor chunking to reduce the Three.js chunk size.
- Add a frontend lint script.
- Supply a licensed public labeled corpus and run the new `ml/` workflow; no dataset is bundled because email corpora may contain personal data and independent license terms.

## 11. The exact next implementation step
- Begin Phase 5: Holographic Forensic Lab email analyzer, preserving the existing backend response contracts.
