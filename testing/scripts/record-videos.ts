/**
 * TheITApprentice — Video Recording Automation
 *
 * Records gameplay videos of each typing game mode for:
 *   - Social media clips
 *   - Gemini/Veo video generation input
 *   - YouTube demos
 *   - Blog post embeds
 *
 * Playwright records the browser as a .webm file, then we rename to .mp4
 * (Chromium records webm/vp8 — works in all modern editors and uploaders).
 *
 * Usage:
 *   npm run record                             # local dev
 *   npm run record:prod                        # production
 *   npm run record:dark                        # dark mode
 *
 * Output:
 *   testing/videos/<timestamp>/
 *     01-typing-landing.webm
 *     02-qbf-demo.webm
 *     03-infinite-rush-demo.webm
 *     04-ghost-mode-demo.webm
 *     05-practice-mode.webm
 *     06-leaderboard.webm
 *     07-homepage.webm
 */

import { chromium, Browser, BrowserContext, Page } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

const BASE_URL  = process.env.BASE_URL  || 'http://localhost:5173';
const DARK_MODE = process.env.DARK_MODE === 'true';
const TIMESTAMP = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const OUT_DIR   = path.join(__dirname, '..', 'videos', TIMESTAMP);

const VIDEO_SIZE = { width: 1280, height: 800 };

// ─── Helpers ───────────────────────────────────────────────────────────────

function log(msg: string)  { console.log(`  🎬 ${msg}`); }
function warn(msg: string) { console.warn(`  ⚠  ${msg}`); }

async function makeContext(browser: Browser): Promise<BrowserContext> {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  return browser.newContext({
    viewport: VIDEO_SIZE,
    colorScheme: DARK_MODE ? 'dark' : 'light',
    recordVideo: {
      dir: OUT_DIR,
      size: VIDEO_SIZE,
    },
  });
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
    await page.waitForTimeout(400);
  }
}

async function dismissCookieBanner(page: Page) {
  try {
    const btn = page.locator('button', { hasText: /accept all|accept/i }).first();
    if (await btn.isVisible({ timeout: 2000 })) {
      await btn.click();
      await page.waitForTimeout(500);
    }
  } catch { /* no banner */ }
}

async function scrollToTop(page: Page) {
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }));
  await page.waitForTimeout(400);
}

async function typeWords(page: Page, words: string[], delayMs = 80) {
  const input = page.locator('input[type="text"], input:not([type]), textarea').first();
  try {
    await input.waitFor({ state: 'visible', timeout: 4000 });
    await input.focus();
    for (const word of words) {
      await input.type(word, { delay: delayMs });
      await input.press('Space');
      await page.waitForTimeout(100);
    }
  } catch { /* input not found */ }
}

async function startGame(page: Page): Promise<boolean> {
  const btn = page.locator('button', { hasText: /start|play|begin/i }).first();
  try {
    await btn.waitFor({ state: 'visible', timeout: 5000 });
    await btn.click({ force: true });
    await page.waitForTimeout(800);
    return true;
  } catch {
    return false;
  }
}

/** Save a page's recorded video with a descriptive name */
async function saveVideo(page: Page, ctx: BrowserContext, name: string) {
  const video = page.video();
  if (!video) { warn(`No video object for ${name}`); return; }
  await page.close();
  await ctx.close(); // Finalize the .webm before we touch the file
  await new Promise((r) => setTimeout(r, 600)); // Windows: release file lock
  const generatedPath = await video.path();
  const destPath = path.join(OUT_DIR, `${name}.webm`);
  fs.renameSync(generatedPath, destPath);
  const sizeMb = (fs.statSync(destPath).size / 1024 / 1024).toFixed(1);
  log(`${name}.webm  (${sizeMb} MB)`);
}

// ─── Recordings ────────────────────────────────────────────────────────────

/**
 * 01 — Typing Practice Landing Page
 * Pan slowly over the game mode cards
 */
async function recordLanding(ctx: BrowserContext) {
  const page = await ctx.newPage();
  try {
    await goto(page, '/typing-practice');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    await scrollToTop(page);
    await page.waitForTimeout(3000); // Hold on landing for 3s
    // Scroll down slowly to show Top Players section
    await page.evaluate(() => window.scrollBy({ top: 300, behavior: 'smooth' }));
    await page.waitForTimeout(2000);
    await scrollToTop(page);
    await page.waitForTimeout(1000);
  } catch (e) { warn(`landing: ${e}`); }
  await saveVideo(page, ctx, '01-typing-landing');
}

/**
 * 02 — Quick Brown Fox Demo
 * Show round 1, type several words, let Round 2 kick in
 */
async function recordQBF(ctx: BrowserContext) {
  const page = await ctx.newPage();
  try {
    await goto(page, '/typing-practice/play');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    await scrollToTop(page);
    await page.waitForTimeout(2000); // Show the start screen

    const started = await startGame(page);
    if (started) {
      await scrollToTop(page);
      // Round 1 — warmup, type at a natural pace
      await typeWords(page, [
        'sudo', 'chmod', 'docker', 'nginx', 'grep', 'ssh',
        'curl', 'ping', 'bash', 'python', 'node', 'git',
      ], 90);
      await page.waitForTimeout(1500);
      await scrollToTop(page);
      // Hold on results / round transition
      await page.waitForTimeout(2000);
      // Round 2 — speed up
      await typeWords(page, [
        'npm', 'aws', 'kubectl', 'helm', 'terraform', 'ansible',
        'docker', 'nginx', 'redis', 'postgres',
      ], 65);
      await page.waitForTimeout(1500);
    }
    await page.waitForTimeout(2000); // Show final results
  } catch (e) { warn(`qbf: ${e}`); }
  await saveVideo(page, ctx, '02-qbf-demo');
}

/**
 * 03 — Infinite Rush Demo
 * 60-second sprint — type as many words as possible
 */
async function recordInfiniteRush(ctx: BrowserContext) {
  const page = await ctx.newPage();
  try {
    await goto(page, '/typing-practice/infinite-rush');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    await scrollToTop(page);
    await page.waitForTimeout(2000); // Show start screen

    const started = await startGame(page);
    if (started) {
      await scrollToTop(page);
      // Type continuously — builds a good demo showing the word stream
      const words = [
        'sudo', 'docker', 'nginx', 'chmod', 'grep', 'ssh', 'kubectl',
        'netstat', 'iptables', 'curl', 'wget', 'bash', 'python', 'git',
        'npm', 'node', 'aws', 'azure', 'linux', 'ubuntu', 'debian',
        'redis', 'postgres', 'mysql', 'mongo', 'ansible', 'terraform',
        'helm', 'vault', 'consul', 'nginx', 'apache', 'systemd', 'cron',
        'chmod', 'chown', 'grep', 'awk', 'sed', 'tail', 'head',
      ];
      await typeWords(page, words, 55);
      await page.waitForTimeout(3000); // Let timer run a bit more visibly
    }
    await page.waitForTimeout(2000); // Show results screen
  } catch (e) { warn(`infinite-rush: ${e}`); }
  await saveVideo(page, ctx, '03-infinite-rush-demo');
}

/**
 * 04 — Ghost Mode Demo
 * Show the ghost interface — "No Ghost Yet" screen is actually fine for demo
 * Shows the concept, prompts sign-in
 */
async function recordGhostMode(ctx: BrowserContext) {
  const page = await ctx.newPage();
  try {
    await goto(page, '/typing-practice/ghost');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    await scrollToTop(page);
    await page.waitForTimeout(3000); // Hold on ghost screen

    // Try to start anyway — if no ghost, still shows game interface
    const started = await startGame(page);
    if (started) {
      await scrollToTop(page);
      await typeWords(page, [
        'sudo', 'chmod', 'docker', 'nginx', 'grep',
        'ssh', 'curl', 'ping', 'bash', 'python',
      ], 70);
      await page.waitForTimeout(2000);
    }
    await page.waitForTimeout(1500);
  } catch (e) { warn(`ghost-mode: ${e}`); }
  await saveVideo(page, ctx, '04-ghost-mode-demo');
}

/**
 * 05 — Practice Mode
 */
async function recordPracticeMode(ctx: BrowserContext) {
  const page = await ctx.newPage();
  try {
    await goto(page, '/typing-practice/practice');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    await scrollToTop(page);
    await page.waitForTimeout(2500);
    // Scroll to show any word list options
    await page.evaluate(() => window.scrollBy({ top: 200, behavior: 'smooth' }));
    await page.waitForTimeout(1500);
    await scrollToTop(page);
    await page.waitForTimeout(1000);
  } catch (e) { warn(`practice: ${e}`); }
  await saveVideo(page, ctx, '05-practice-mode');
}

/**
 * 06 — Leaderboard
 */
async function recordLeaderboard(ctx: BrowserContext) {
  const page = await ctx.newPage();
  try {
    await goto(page, '/typing-practice/leaderboard');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    await scrollToTop(page);
    await page.waitForTimeout(2000);
    await page.evaluate(() => window.scrollBy({ top: 400, behavior: 'smooth' }));
    await page.waitForTimeout(1500);
    await scrollToTop(page);
    await page.waitForTimeout(500);
  } catch (e) { warn(`leaderboard: ${e}`); }
  await saveVideo(page, ctx, '06-leaderboard');
}

/**
 * 07 — Homepage pan (great for intro/outro of marketing video)
 */
async function recordHomepage(ctx: BrowserContext) {
  const page = await ctx.newPage();
  try {
    await goto(page, '/');
    await dismissCookieBanner(page);
    await applyDarkMode(page);
    await scrollToTop(page);
    await page.waitForTimeout(2000);
    // Slow scroll down the homepage
    for (let i = 0; i < 6; i++) {
      await page.evaluate(() => window.scrollBy({ top: 150, behavior: 'smooth' }));
      await page.waitForTimeout(600);
    }
    await scrollToTop(page);
    await page.waitForTimeout(1000);
  } catch (e) { warn(`homepage: ${e}`); }
  await saveVideo(page, ctx, '07-homepage-pan');
}

// ─── Entry Point ───────────────────────────────────────────────────────────

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  console.log('');
  console.log('┌─────────────────────────────────────────────────┐');
  console.log('│  TheITApprentice — Video Recording               │');
  console.log('└─────────────────────────────────────────────────┘');
  console.log(`  Target:    ${BASE_URL}`);
  console.log(`  Dark mode: ${DARK_MODE}`);
  console.log(`  Output:    testing/videos/${TIMESTAMP}/`);
  console.log(`  Format:    .webm (VP8) — import into any video editor`);
  console.log('');
  console.log('  Each game gets its own browser context (isolated session).');
  console.log('');

  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox'],
  });

  try {
    // Each recording needs its own context with recordVideo enabled
    await recordLanding(await makeContext(browser));
    await recordQBF(await makeContext(browser));
    await recordInfiniteRush(await makeContext(browser));
    await recordGhostMode(await makeContext(browser));
    await recordPracticeMode(await makeContext(browser));
    await recordLeaderboard(await makeContext(browser));
    await recordHomepage(await makeContext(browser));
  } finally {
    await browser.close();
  }

  const files = fs.readdirSync(OUT_DIR).filter((f) => f.endsWith('.webm'));
  const totalMb = files.reduce((acc, f) => {
    return acc + fs.statSync(path.join(OUT_DIR, f)).size / 1024 / 1024;
  }, 0);

  console.log('');
  console.log(`✅ Done — ${files.length} videos  (${totalMb.toFixed(1)} MB total)`);
  console.log(`   Output: ${OUT_DIR}`);
  console.log('');
  console.log('  💡 Tips:');
  console.log('     - Import .webm files directly into DaVinci Resolve, Premiere, or CapCut');
  console.log('     - Use ffmpeg to convert: ffmpeg -i input.webm output.mp4');
  console.log('     - Feed clips to Gemini/Veo alongside the video prompt');
  console.log('     - Re-run with DARK_MODE=true for dark theme variants');
  console.log('');
}

main().catch((err) => { console.error(err); process.exit(1); });
