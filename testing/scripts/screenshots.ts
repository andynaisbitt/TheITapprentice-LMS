/**
 * TheITApprentice — Documentation Screenshot Automation
 *
 * Usage:
 *   npm run screenshots                        # local dev (localhost:5173)
 *   npm run screenshots:prod                   # production
 *   npm run screenshots:dark                   # dark mode
 *   BASE_URL=https://theitapprentice.com DARK_MODE=true npx ts-node scripts/screenshots.ts
 */

import { chromium, Browser, Page, BrowserContext } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

const BASE_URL = process.env.BASE_URL || 'http://localhost:5173';
const DARK_MODE = process.env.DARK_MODE === 'true';
const TIMESTAMP = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const OUT_BASE = path.join(__dirname, '..', 'screenshots', TIMESTAMP);
const OUT_DESKTOP = path.join(OUT_BASE, 'desktop');
const OUT_MOBILE  = path.join(OUT_BASE, 'mobile');

const DESKTOP_VIEWPORT = { width: 1280, height: 800 };
const MOBILE_VIEWPORT  = { width: 390, height: 844 };

// ─── Helpers ───────────────────────────────────────────────────────────────

function ensureDirs() {
  [OUT_DESKTOP, OUT_MOBILE].forEach((d) => fs.mkdirSync(d, { recursive: true }));
}
function log(msg: string)  { console.log(`  ✓ ${msg}`); }
function warn(msg: string) { console.warn(`  ⚠ ${msg}`); }

async function createContext(browser: Browser, mobile = false): Promise<BrowserContext> {
  return browser.newContext({
    viewport: mobile ? MOBILE_VIEWPORT : DESKTOP_VIEWPORT,
    colorScheme: DARK_MODE ? 'dark' : 'light',
    deviceScaleFactor: mobile ? 2 : 1,
  });
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

/** Dismiss cookie/privacy consent banner if present */
async function dismissCookieBanner(page: Page) {
  try {
    const acceptBtn = page.locator('button', { hasText: /accept all|accept cookies|accept/i }).first();
    if (await acceptBtn.isVisible({ timeout: 2000 })) {
      await acceptBtn.click();
      await page.waitForTimeout(400);
    }
  } catch {
    // No banner — fine
  }
}

/** Scroll back to top after interactions */
async function scrollToTop(page: Page) {
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(200);
}

/** Click start button, dismiss banner first */
async function startGame(page: Page): Promise<boolean> {
  await dismissCookieBanner(page);
  await scrollToTop(page);

  const startBtn = page.locator('button', { hasText: /start|play|begin/i }).first();
  try {
    await startBtn.waitFor({ state: 'visible', timeout: 5000 });
    await startBtn.click({ force: true });
    await page.waitForTimeout(600);
    return true;
  } catch {
    return false;
  }
}

/** Type a sequence of words into the focused game input */
async function typeWords(page: Page, words: string[], delayMs = 55) {
  const input = page.locator('input[type="text"], input:not([type]), textarea').first();
  try {
    await input.waitFor({ state: 'visible', timeout: 3000 });
    await input.focus();
    for (const word of words) {
      await input.type(word, { delay: delayMs });
      await input.press('Space');
      await page.waitForTimeout(80);
    }
  } catch {
    // Input not found — game may auto-focus differently
  }
}

// ─── Desktop ───────────────────────────────────────────────────────────────

async function desktopScreenshots(browser: Browser) {
  console.log('\n📸 Desktop screenshots...');
  const ctx = await createContext(browser, false);
  const page = await ctx.newPage();

  // ── Homepage ──────────────────────────────────────────────────────────────
  try {
    await goto(page, '/');
    await applyDarkMode(page);
    await page.waitForTimeout(800);
    await shot(page, '01-homepage');

    // Clean shot — dismiss banner then screenshot
    await dismissCookieBanner(page);
    await page.waitForTimeout(300);
    await shot(page, '01-homepage-clean');
  } catch (e) { warn(`homepage: ${e}`); }

  // ── Blog ──────────────────────────────────────────────────────────────────
  try {
    await goto(page, '/blog');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    await page.waitForTimeout(600);
    await shot(page, '02-blog');
  } catch (e) { warn(`blog: ${e}`); }

  // ── Typing Practice — Landing ─────────────────────────────────────────────
  try {
    await goto(page, '/typing-practice');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    await page.waitForTimeout(600);
    await shot(page, '03-typing-landing');
  } catch (e) { warn(`typing-landing: ${e}`); }

  // ── Quick Brown Fox — Start Screen ────────────────────────────────────────
  try {
    await goto(page, '/typing-practice/play');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    await scrollToTop(page);
    await page.waitForTimeout(400);
    await shot(page, '04-qbf-start');
  } catch (e) { warn(`qbf-start: ${e}`); }

  // ── Quick Brown Fox — Round 1 Active ──────────────────────────────────────
  try {
    await goto(page, '/typing-practice/play');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    const started = await startGame(page);
    if (started) {
      await typeWords(page, ['sudo', 'chmod', 'docker', 'nginx']);
      await scrollToTop(page);
      await page.waitForTimeout(200);
      await shot(page, '05-qbf-round1-active');
    }
  } catch (e) { warn(`qbf-active: ${e}`); }

  // ── Quick Brown Fox — Round 3 INSANE MODE ─────────────────────────────────
  try {
    await goto(page, '/typing-practice/play');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    const started = await startGame(page);
    if (started) {
      // Complete round 1 fast to advance
      const roundWords = ['sudo', 'chmod', 'docker', 'nginx', 'grep', 'ssh', 'curl', 'ping',
                          'bash', 'python', 'node', 'git', 'npm', 'aws', 'kubectl', 'helm'];
      await typeWords(page, roundWords, 30);
      await page.waitForTimeout(1500);
      await scrollToTop(page);
      await shot(page, '06-qbf-round2-or-3');
    }
  } catch (e) { warn(`qbf-round3: ${e}`); }

  // ── Infinite Rush — Start Screen ──────────────────────────────────────────
  try {
    await goto(page, '/typing-practice/infinite-rush');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    await scrollToTop(page);
    await page.waitForTimeout(400);
    await shot(page, '07-infinite-rush-start');
  } catch (e) { warn(`infinite-rush-start: ${e}`); }

  // ── Infinite Rush — Active ────────────────────────────────────────────────
  try {
    await goto(page, '/typing-practice/infinite-rush');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    const started = await startGame(page);
    if (started) {
      await typeWords(page, ['sudo', 'docker', 'nginx', 'chmod', 'grep', 'ssh', 'kubectl', 'netstat', 'iptables'], 45);
      await scrollToTop(page);
      await page.waitForTimeout(200);
      await shot(page, '08-infinite-rush-active');
    }
  } catch (e) { warn(`infinite-rush-active: ${e}`); }

  // ── Ghost Mode — Start Screen ─────────────────────────────────────────────
  try {
    await goto(page, '/typing-practice/ghost');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    await scrollToTop(page);
    await page.waitForTimeout(400);
    await shot(page, '09-ghost-start');
  } catch (e) { warn(`ghost-start: ${e}`); }

  // ── Ghost Mode — Active ───────────────────────────────────────────────────
  try {
    await goto(page, '/typing-practice/ghost');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    const started = await startGame(page);
    if (started) {
      await typeWords(page, ['sudo', 'chmod', 'docker', 'nginx', 'grep', 'ssh'], 50);
      await scrollToTop(page);
      await page.waitForTimeout(200);
      await shot(page, '10-ghost-active');
    }
  } catch (e) { warn(`ghost-active: ${e}`); }

  // ── Practice Mode ─────────────────────────────────────────────────────────
  try {
    await goto(page, '/typing-practice/practice');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    await scrollToTop(page);
    await page.waitForTimeout(600);
    await shot(page, '11-practice-mode');
  } catch (e) { warn(`practice-mode: ${e}`); }

  // ── Leaderboard ───────────────────────────────────────────────────────────
  try {
    await goto(page, '/typing-practice/leaderboard');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    await page.waitForTimeout(600);
    await shot(page, '12-leaderboard');
  } catch (e) { warn(`leaderboard: ${e}`); }

  // ── Skills ────────────────────────────────────────────────────────────────
  try {
    await goto(page, '/skills');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    await page.waitForTimeout(800);
    await shot(page, '13-skills');
  } catch (e) { warn(`skills: ${e}`); }

  // ── Challenges ────────────────────────────────────────────────────────────
  try {
    await goto(page, '/challenges');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    await page.waitForTimeout(600);
    await shot(page, '14-challenges');
  } catch (e) { warn(`challenges: ${e}`); }

  // ── Quizzes ───────────────────────────────────────────────────────────────
  try {
    await goto(page, '/quizzes');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    await page.waitForTimeout(600);
    await shot(page, '15-quizzes');
  } catch (e) { warn(`quizzes: ${e}`); }

  await ctx.close();
}

// ─── Mobile ────────────────────────────────────────────────────────────────

async function mobileScreenshots(browser: Browser) {
  console.log('\n📱 Mobile screenshots...');
  const ctx = await createContext(browser, true);
  const page = await ctx.newPage();

  const mobilePages: Array<[string, string]> = [
    ['/typing-practice',           'mobile-01-typing-landing'],
    ['/',                          'mobile-02-homepage'],
    ['/typing-practice/infinite-rush', 'mobile-03-infinite-rush'],
    ['/typing-practice/play',      'mobile-04-qbf-start'],
    ['/quizzes',                   'mobile-05-quizzes'],
    ['/challenges',                'mobile-06-challenges'],
  ];

  for (const [urlPath, filename] of mobilePages) {
    try {
      await goto(page, urlPath);
      await dismissCookieBanner(page);
      await applyDarkMode(page);
      await scrollToTop(page);
      await page.waitForTimeout(600);
      await shot(page, filename, true);
    } catch (e) { warn(`${filename}: ${e}`); }
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

  const desktopFiles = fs.readdirSync(OUT_DESKTOP);
  const mobileFiles  = fs.readdirSync(OUT_MOBILE);
  const total = desktopFiles.length + mobileFiles.length;

  console.log('');
  console.log(`✅ Done — ${total} screenshots`);
  console.log(`   Desktop: ${desktopFiles.length}  →  ${OUT_DESKTOP}`);
  console.log(`   Mobile:  ${mobileFiles.length}   →  ${OUT_MOBILE}`);
  console.log('');
}

main().catch((err) => { console.error(err); process.exit(1); });
