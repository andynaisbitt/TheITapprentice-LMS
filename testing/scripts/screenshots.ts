/**
 * TheITApprentice — Documentation Screenshot Automation
 *
 * Captures screenshots of all key pages and game states for:
 *   - Blog post imagery
 *   - Marketing materials
 *   - Feature documentation
 *   - LinkedIn / social media
 *
 * Usage:
 *   npm run screenshots                        # local dev (localhost:5173)
 *   npm run screenshots:prod                   # production
 *   npm run screenshots:dark                   # dark mode
 *   BASE_URL=http://localhost:5173 npx ts-node scripts/screenshots.ts
 *
 * Output:
 *   testing/screenshots/<timestamp>/
 *     ├── desktop/
 *     │   ├── typing-landing.png
 *     │   ├── typing-qbf-round3.png
 *     │   ├── typing-results.png
 *     │   ├── typing-infinite-rush.png
 *     │   ├── typing-ghost-mode.png
 *     │   ├── typing-practice-mode.png
 *     │   ├── typing-leaderboard.png
 *     │   ├── homepage.png
 *     │   ├── skills.png
 *     │   ├── challenges.png
 *     │   └── blog.png
 *     └── mobile/
 *         ├── typing-landing-mobile.png
 *         ├── typing-qbf-mobile.png
 *         └── homepage-mobile.png
 */

import { chromium, Browser, Page, BrowserContext } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

// ─── Config ────────────────────────────────────────────────────────────────

const BASE_URL = process.env.BASE_URL || 'http://localhost:5173';
const DARK_MODE = process.env.DARK_MODE === 'true';
const TIMESTAMP = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const OUT_BASE = path.join(__dirname, '..', 'screenshots', TIMESTAMP);
const OUT_DESKTOP = path.join(OUT_BASE, 'desktop');
const OUT_MOBILE = path.join(OUT_BASE, 'mobile');

const DESKTOP_VIEWPORT = { width: 1280, height: 800 };
const MOBILE_VIEWPORT = { width: 390, height: 844 };

// ─── Helpers ───────────────────────────────────────────────────────────────

function ensureDirs() {
  [OUT_DESKTOP, OUT_MOBILE].forEach((d) => fs.mkdirSync(d, { recursive: true }));
}

function log(msg: string) {
  console.log(`  ✓ ${msg}`);
}

function warn(msg: string) {
  console.warn(`  ⚠ ${msg}`);
}

async function createContext(browser: Browser, mobile = false): Promise<BrowserContext> {
  const ctx = await browser.newContext({
    viewport: mobile ? MOBILE_VIEWPORT : DESKTOP_VIEWPORT,
    colorScheme: DARK_MODE ? 'dark' : 'light',
    deviceScaleFactor: mobile ? 2 : 1,
  });
  return ctx;
}

async function shot(page: Page, filename: string, mobile = false): Promise<void> {
  const outDir = mobile ? OUT_MOBILE : OUT_DESKTOP;
  const filepath = path.join(outDir, `${filename}.png`);
  await page.screenshot({ path: filepath, fullPage: false });
  log(`${filename}.png`);
}

async function goto(page: Page, urlPath: string) {
  await page.goto(`${BASE_URL}${urlPath}`, { waitUntil: 'networkidle' });
}

async function applyDarkMode(page: Page) {
  if (DARK_MODE) {
    await page.evaluate(() => {
      document.documentElement.classList.add('dark');
      localStorage.setItem('theme', 'dark');
    });
    await page.waitForTimeout(300);
  }
}

// ─── Desktop Screenshots ───────────────────────────────────────────────────

async function desktopScreenshots(browser: Browser) {
  console.log('\n📸 Desktop screenshots...');
  const ctx = await createContext(browser, false);
  const page = await ctx.newPage();

  // ── Homepage ──────────────────────────────────────────────────────────────
  try {
    await goto(page, '/');
    await applyDarkMode(page);
    await page.waitForTimeout(800);
    await shot(page, 'homepage');
  } catch (e) {
    warn(`homepage failed: ${e}`);
  }

  // ── Blog ──────────────────────────────────────────────────────────────────
  try {
    await goto(page, '/blog');
    await applyDarkMode(page);
    await page.waitForTimeout(800);
    await shot(page, 'blog');
  } catch (e) {
    warn(`blog failed: ${e}`);
  }

  // ── Typing Practice — Landing ─────────────────────────────────────────────
  try {
    await goto(page, '/typing-practice');
    await applyDarkMode(page);
    await page.waitForTimeout(1000);
    await shot(page, 'typing-landing');
  } catch (e) {
    warn(`typing-landing failed: ${e}`);
  }

  // ── Typing Practice — Leaderboard ─────────────────────────────────────────
  try {
    await goto(page, '/typing-practice/leaderboard');
    await applyDarkMode(page);
    await page.waitForTimeout(800);
    await shot(page, 'typing-leaderboard');
  } catch (e) {
    warn(`typing-leaderboard failed: ${e}`);
  }

  // ── Quick Brown Fox — Start Screen ────────────────────────────────────────
  try {
    await goto(page, '/typing-practice/play');
    await applyDarkMode(page);
    await page.waitForTimeout(800);
    await shot(page, 'typing-qbf-start');
  } catch (e) {
    warn(`typing-qbf-start failed: ${e}`);
  }

  // ── Quick Brown Fox — In Progress (Round 1) ───────────────────────────────
  try {
    await goto(page, '/typing-practice/play');
    await applyDarkMode(page);
    await page.waitForTimeout(800);

    // Click the start/play button
    const startBtn = page.locator('button', { hasText: /start|play|begin/i }).first();
    if (await startBtn.isVisible()) {
      await startBtn.click();
      await page.waitForTimeout(500);
    }

    // Find the input and type a few words
    const input = page.locator('input[type="text"], input:not([type]), textarea').first();
    if (await input.isVisible()) {
      await input.focus();
      // Type several words to get a combo going
      const words = ['sudo', 'chmod', 'docker', 'nginx', 'grep'];
      for (const word of words) {
        await input.type(word, { delay: 60 });
        await input.press('Space');
        await page.waitForTimeout(100);
      }
      await shot(page, 'typing-qbf-round1-active');
    } else {
      await shot(page, 'typing-qbf-round1');
    }
  } catch (e) {
    warn(`typing-qbf-active failed: ${e}`);
  }

  // ── Infinite Rush — Start Screen ──────────────────────────────────────────
  try {
    await goto(page, '/typing-practice/infinite-rush');
    await applyDarkMode(page);
    await page.waitForTimeout(800);
    await shot(page, 'typing-infinite-rush-start');
  } catch (e) {
    warn(`typing-infinite-rush-start failed: ${e}`);
  }

  // ── Infinite Rush — In Progress ───────────────────────────────────────────
  try {
    await goto(page, '/typing-practice/infinite-rush');
    await applyDarkMode(page);
    await page.waitForTimeout(600);

    const startBtn = page.locator('button', { hasText: /start|play|begin/i }).first();
    if (await startBtn.isVisible()) {
      await startBtn.click();
      await page.waitForTimeout(400);
    }

    const input = page.locator('input[type="text"], input:not([type]), textarea').first();
    if (await input.isVisible()) {
      await input.focus();
      const words = ['sudo', 'docker', 'nginx', 'chmod', 'grep', 'ssh', 'kubectl', 'netstat'];
      for (const word of words) {
        await input.type(word, { delay: 50 });
        await input.press('Space');
        await page.waitForTimeout(80);
      }
      await shot(page, 'typing-infinite-rush-active');
    } else {
      await shot(page, 'typing-infinite-rush');
    }
  } catch (e) {
    warn(`typing-infinite-rush-active failed: ${e}`);
  }

  // ── Ghost Mode — Start Screen ─────────────────────────────────────────────
  try {
    await goto(page, '/typing-practice/ghost');
    await applyDarkMode(page);
    await page.waitForTimeout(800);
    await shot(page, 'typing-ghost-start');
  } catch (e) {
    warn(`typing-ghost-start failed: ${e}`);
  }

  // ── Ghost Mode — In Progress ──────────────────────────────────────────────
  try {
    await goto(page, '/typing-practice/ghost');
    await applyDarkMode(page);
    await page.waitForTimeout(600);

    const startBtn = page.locator('button', { hasText: /start|play|begin/i }).first();
    if (await startBtn.isVisible()) {
      await startBtn.click();
      await page.waitForTimeout(400);
    }

    const input = page.locator('input[type="text"], input:not([type]), textarea').first();
    if (await input.isVisible()) {
      await input.focus();
      const words = ['sudo', 'chmod', 'docker', 'nginx', 'grep', 'ssh'];
      for (const word of words) {
        await input.type(word, { delay: 55 });
        await input.press('Space');
        await page.waitForTimeout(90);
      }
      await shot(page, 'typing-ghost-active');
    } else {
      await shot(page, 'typing-ghost');
    }
  } catch (e) {
    warn(`typing-ghost-active failed: ${e}`);
  }

  // ── Practice Mode ─────────────────────────────────────────────────────────
  try {
    await goto(page, '/typing-practice/practice');
    await applyDarkMode(page);
    await page.waitForTimeout(800);
    await shot(page, 'typing-practice-mode');
  } catch (e) {
    warn(`typing-practice-mode failed: ${e}`);
  }

  // ── Skills Page ───────────────────────────────────────────────────────────
  try {
    await goto(page, '/skills');
    await applyDarkMode(page);
    await page.waitForTimeout(1000);
    await shot(page, 'skills');
  } catch (e) {
    warn(`skills failed: ${e}`);
  }

  // ── Challenges Page ───────────────────────────────────────────────────────
  try {
    await goto(page, '/challenges');
    await applyDarkMode(page);
    await page.waitForTimeout(800);
    await shot(page, 'challenges');
  } catch (e) {
    warn(`challenges failed: ${e}`);
  }

  // ── Quizzes Page ──────────────────────────────────────────────────────────
  try {
    await goto(page, '/quizzes');
    await applyDarkMode(page);
    await page.waitForTimeout(800);
    await shot(page, 'quizzes');
  } catch (e) {
    warn(`quizzes failed: ${e}`);
  }

  await ctx.close();
}

// ─── Mobile Screenshots ────────────────────────────────────────────────────

async function mobileScreenshots(browser: Browser) {
  console.log('\n📱 Mobile screenshots...');
  const ctx = await createContext(browser, true);
  const page = await ctx.newPage();

  // ── Typing Landing — Mobile ───────────────────────────────────────────────
  try {
    await goto(page, '/typing-practice');
    await applyDarkMode(page);
    await page.waitForTimeout(1000);
    await shot(page, 'typing-landing-mobile', true);
  } catch (e) {
    warn(`typing-landing-mobile failed: ${e}`);
  }

  // ── Quick Brown Fox — Mobile In Progress ──────────────────────────────────
  try {
    await goto(page, '/typing-practice/play');
    await applyDarkMode(page);
    await page.waitForTimeout(800);

    const startBtn = page.locator('button', { hasText: /start|play|begin/i }).first();
    if (await startBtn.isVisible()) {
      await startBtn.click();
      await page.waitForTimeout(500);
    }

    await shot(page, 'typing-qbf-mobile', true);
  } catch (e) {
    warn(`typing-qbf-mobile failed: ${e}`);
  }

  // ── Homepage — Mobile ─────────────────────────────────────────────────────
  try {
    await goto(page, '/');
    await applyDarkMode(page);
    await page.waitForTimeout(800);
    await shot(page, 'homepage-mobile', true);
  } catch (e) {
    warn(`homepage-mobile failed: ${e}`);
  }

  // ── Infinite Rush — Mobile ────────────────────────────────────────────────
  try {
    await goto(page, '/typing-practice/infinite-rush');
    await applyDarkMode(page);
    await page.waitForTimeout(800);
    await shot(page, 'typing-infinite-rush-mobile', true);
  } catch (e) {
    warn(`typing-infinite-rush-mobile failed: ${e}`);
  }

  await ctx.close();
}

// ─── Entry Point ───────────────────────────────────────────────────────────

async function main() {
  ensureDirs();

  console.log('');
  console.log('┌─────────────────────────────────────────────────┐');
  console.log('│  TheITApprentice — Screenshot Automation         │');
  console.log('└─────────────────────────────────────────────────┘');
  console.log(`  Target:    ${BASE_URL}`);
  console.log(`  Dark mode: ${DARK_MODE}`);
  console.log(`  Output:    testing/screenshots/${TIMESTAMP}/`);
  console.log('');

  const browser = await chromium.launch({ headless: true });

  try {
    await desktopScreenshots(browser);
    await mobileScreenshots(browser);
  } finally {
    await browser.close();
  }

  // ── Summary ──────────────────────────────────────────────────────────────
  const desktopFiles = fs.readdirSync(OUT_DESKTOP);
  const mobileFiles = fs.readdirSync(OUT_MOBILE);
  const total = desktopFiles.length + mobileFiles.length;

  console.log('');
  console.log(`✅ Done — ${total} screenshots saved`);
  console.log(`   Desktop: ${desktopFiles.length} (${OUT_DESKTOP})`);
  console.log(`   Mobile:  ${mobileFiles.length} (${OUT_MOBILE})`);
  console.log('');
  console.log('  Copy your favourites to docs/screenshots/ for docs/blog use.');
  console.log('');
}

main().catch((err) => {
  console.error('Screenshot script failed:', err);
  process.exit(1);
});
