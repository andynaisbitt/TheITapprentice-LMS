# Testing & Screenshot Automation

Playwright-based testing and documentation screenshot tooling for TheITApprentice.

---

## Setup

```bash
cd testing
npm install
npm run install:browsers   # installs Chromium
```

---

## Screenshot Automation

Captures screenshots of all key pages and game states for blog posts,
docs, and social media. Outputs to `testing/screenshots/<timestamp>/`.

```bash
# Local dev (requires frontend running on localhost:5173)
npm run screenshots

# Production site
npm run screenshots:prod

# Dark mode variants
npm run screenshots:dark

# Both dark + production
BASE_URL=https://theitapprentice.com DARK_MODE=true npx ts-node scripts/screenshots.ts
```

### Output structure

```
testing/screenshots/2026-02-27T14-30-00/
  desktop/
    homepage.png
    blog.png
    typing-landing.png
    typing-qbf-start.png
    typing-qbf-round1-active.png
    typing-infinite-rush-start.png
    typing-infinite-rush-active.png
    typing-ghost-start.png
    typing-ghost-active.png
    typing-practice-mode.png
    typing-leaderboard.png
    skills.png
    challenges.png
    quizzes.png
  mobile/
    homepage-mobile.png
    typing-landing-mobile.png
    typing-qbf-mobile.png
    typing-infinite-rush-mobile.png
```

Screenshots are **gitignored** (they're generated output).
Copy the ones you want to use into `docs/screenshots/` for permanent storage.

---

## Smoke Tests

Fast sanity checks — are all pages loading without errors?

```bash
# Local dev
npm run smoke

# Production
npm run smoke:prod

# View HTML report after run
npm run test:report
```

### What's tested

| Suite | Tests |
|-------|-------|
| Core Pages | Homepage, Blog, About, Login, Leaderboard |
| Typing Games | All 4 game modes load + are startable |
| Learn Pages | Courses, Tutorials, Quizzes, Skills, Challenges |
| Navigation | Header, sidebar open/close, link navigation |
| API Health | Backend `/health`, site settings endpoint |
| Dark Mode | Theme applies correctly |

---

## Adding New Screenshots

Edit `scripts/screenshots.ts` — add a new block following the existing pattern:

```typescript
try {
  await goto(page, '/your-new-page');
  await applyDarkMode(page);
  await page.waitForTimeout(800);
  await shot(page, 'your-new-page');
} catch (e) {
  warn(`your-new-page failed: ${e}`);
}
```

Each `shot()` call saves a `.png` to the appropriate output directory.

---

## Adding New Smoke Tests

Edit `scripts/smoke-tests.spec.ts` — add inside the relevant `test.describe` block:

```typescript
test('your new page loads', async ({ page }) => {
  await page.goto(`${BASE_URL}/your-page`);
  await expect(page.locator('h1')).toBeVisible();
});
```

---

## Environment Variables

| Variable   | Default                  | Description                  |
|------------|--------------------------|------------------------------|
| `BASE_URL` | `http://localhost:5173`  | Frontend URL                 |
| `API_URL`  | `http://localhost:8100`  | Backend API URL              |
| `DARK_MODE`| `false`                  | Set `true` for dark variants |

---

## Files

```
testing/
  package.json           — deps and npm scripts
  playwright.config.ts   — Playwright config (3 projects: Desktop, Mobile, Dark)
  tsconfig.json          — TypeScript config
  README.md              — this file
  scripts/
    screenshots.ts       — documentation screenshot automation
    smoke-tests.spec.ts  — smoke test suite
  screenshots/           — gitignored output from screenshots.ts
```
