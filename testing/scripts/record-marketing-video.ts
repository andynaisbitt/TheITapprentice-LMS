/**
 * TheITApprentice — End-to-End Marketing Video
 *
 * Records a single continuous .webm that walks through every typing game mode
 * with injected title cards, smooth scrolling, live gameplay, and a beta CTA.
 *
 * Cookie consent is pre-set via addInitScript — the banner NEVER appears.
 * Everything records in one browser context → one seamless video file.
 *
 * Usage:
 *   npm run marketing                         # local dev
 *   npm run marketing:prod                    # production
 *   npm run marketing:dark                    # dark mode
 *   npm run marketing:prod:dark               # production + dark
 *
 * Output:
 *   testing/videos/<timestamp>/marketing-video.webm
 *
 * Post-production tips:
 *   ffmpeg -i marketing-video.webm marketing-video.mp4
 *   Import into DaVinci Resolve / CapCut / Premiere and add music
 *   Feed to Gemini Veo alongside docs/features/typing-games.md
 */

import { chromium, BrowserContext, Page } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

const BASE_URL  = process.env.BASE_URL  || 'http://localhost:5173';
const DARK_MODE = process.env.DARK_MODE === 'true';
const TIMESTAMP = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const OUT_DIR   = path.join(__dirname, '..', 'videos', TIMESTAMP);

// 720p — standard YouTube/social format
const VIDEO_SIZE = { width: 1280, height: 720 };

// Pre-built cookie consent — set before any page loads so the banner never fires
const COOKIE_CONSENT = JSON.stringify({
  preferences: { necessary: true, analytics: true, marketing: true, functional: true },
  timestamp: new Date().toISOString(),
  version: '1.0',
});

// ─── Helpers ───────────────────────────────────────────────────────────────

function log(msg: string)  { console.log(`  🎬 ${msg}`); }
function warn(msg: string) { console.warn(`  ⚠  ${msg}`); }

async function goto(page: Page, urlPath: string) {
  await page.goto(`${BASE_URL}${urlPath}`, { waitUntil: 'networkidle' });
}

/** Apply dark class + localStorage flag after navigation */
async function applyDarkMode(page: Page) {
  if (DARK_MODE) {
    await page.evaluate(() => {
      document.documentElement.classList.add('dark');
      localStorage.setItem('theme', 'dark');
    });
    await page.waitForTimeout(350);
  }
}

async function scrollToTop(page: Page) {
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }));
  await page.waitForTimeout(450);
}

/** Smooth, cinematic downward scroll */
async function pan(page: Page, totalPx: number, steps = 5, stepDelayMs = 650) {
  const stepPx = Math.round(totalPx / steps);
  for (let i = 0; i < steps; i++) {
    await page.evaluate((px) => window.scrollBy({ top: px, behavior: 'smooth' }), stepPx);
    await page.waitForTimeout(stepDelayMs);
  }
}

/** Click the first visible Start/Play/Begin button */
async function startGame(page: Page): Promise<boolean> {
  const btn = page.locator('button', { hasText: /start|play|begin/i }).first();
  try {
    await btn.waitFor({ state: 'visible', timeout: 5000 });
    await btn.click({ force: true });
    await page.waitForTimeout(900);
    return true;
  } catch {
    return false;
  }
}

/** Type a sequence of words into the active game input */
async function typeWords(page: Page, words: string[], delayMs = 78) {
  const input = page.locator('input[type="text"], input:not([type]), textarea').first();
  try {
    await input.waitFor({ state: 'visible', timeout: 4000 });
    await input.focus();
    for (const word of words) {
      await input.type(word, { delay: delayMs });
      await input.press('Space');
      await page.waitForTimeout(90);
    }
  } catch { /* input not found — game may auto-focus */ }
}

/**
 * Inject a full-screen title card over whatever page is currently showing.
 * Fades in, holds, then fades out.
 *
 * The card sits at z-index 999999 so it always covers everything.
 */
async function showTitleCard(
  page: Page,
  title: string,
  subtitle: string,
  holdMs = 2400,
) {
  // Inject
  await page.evaluate(
    ({ t, s }) => {
      const existing = document.getElementById('__mktc__');
      if (existing) existing.remove();

      const el = document.createElement('div');
      el.id = '__mktc__';
      el.style.cssText = [
        'position:fixed;inset:0;z-index:999999',
        'background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%)',
        'display:flex;flex-direction:column;align-items:center;justify-content:center;gap:0.75rem',
        'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif',
        'color:#f8fafc;opacity:0;transition:opacity 0.4s ease',
        'padding:3rem',
      ].join(';');

      el.innerHTML = `
        <div style="
          font-size:2.6rem;font-weight:800;
          letter-spacing:-0.03em;text-align:center;line-height:1.15;
          background:linear-gradient(135deg,#38bdf8,#818cf8);
          -webkit-background-clip:text;-webkit-text-fill-color:transparent;
          background-clip:text;
        ">${t}</div>
        <div style="
          font-size:1.15rem;color:#94a3b8;text-align:center;
          font-weight:400;max-width:640px;line-height:1.6;
        ">${s}</div>
      `;
      document.body.appendChild(el);
      requestAnimationFrame(() => requestAnimationFrame(() => {
        el.style.opacity = '1';
      }));
    },
    { t: title, s: subtitle },
  );

  await page.waitForTimeout(holdMs);

  // Fade out + remove
  await page.evaluate(() => {
    const el = document.getElementById('__mktc__');
    if (el) el.style.opacity = '0';
  });
  await page.waitForTimeout(450);
  await page.evaluate(() => {
    document.getElementById('__mktc__')?.remove();
  });
  await page.waitForTimeout(150);
}

// ─── Scene Runners ─────────────────────────────────────────────────────────

/** Scene 1 — Homepage: hero pan */
async function sceneHomepage(page: Page) {
  log('Scene 1/7  Homepage');
  await goto(page, '/');
  await applyDarkMode(page);
  await page.waitForTimeout(800);
  await showTitleCard(
    page,
    'TheITApprentice',
    'Level up your keyboard. Test your speed. Climb the leaderboard.',
  );
  await scrollToTop(page);
  await page.waitForTimeout(1500); // Hold on hero
  await pan(page, 800, 6, 700);
  await scrollToTop(page);
  await page.waitForTimeout(600);
}

/** Scene 2 — Typing Practice landing: game mode card overview */
async function sceneTypingLanding(page: Page) {
  log('Scene 2/7  Typing Practice landing');
  await goto(page, '/typing-practice');
  await applyDarkMode(page);
  await page.waitForTimeout(800);
  await showTitleCard(
    page,
    '4 Game Modes',
    'Quick Brown Fox  •  Infinite Rush  •  Ghost Mode  •  Practice',
  );
  await scrollToTop(page);
  await page.waitForTimeout(2000); // Hold on game cards
  await pan(page, 550, 5, 700);
  await scrollToTop(page);
  await page.waitForTimeout(700);
}

/** Scene 3 — Quick Brown Fox: start + live Round 1 typing */
async function sceneQBF(page: Page) {
  log('Scene 3/7  Quick Brown Fox');
  await goto(page, '/typing-practice/play');
  await applyDarkMode(page);
  await page.waitForTimeout(800);
  await showTitleCard(
    page,
    'Quick Brown Fox',
    'Round 1: Warmup → Round 2: Speed Challenge → Round 3: INSANE MODE',
  );
  await scrollToTop(page);
  await page.waitForTimeout(1200);

  const started = await startGame(page);
  if (started) {
    await scrollToTop(page);
    await page.waitForTimeout(400);
    // Round 1 — natural pace
    await typeWords(page, [
      'sudo', 'chmod', 'docker', 'nginx', 'grep',
      'ssh', 'curl', 'bash', 'python', 'git',
      'npm', 'aws', 'kubectl', 'helm', 'terraform',
    ], 82);
    await scrollToTop(page);
    await page.waitForTimeout(2800); // Show round transition / results
    // Partial Round 2 — faster
    await typeWords(page, [
      'redis', 'postgres', 'ansible', 'vault', 'consul',
      'debian', 'ubuntu', 'systemd', 'cron',
    ], 60);
    await page.waitForTimeout(1500);
  } else {
    await page.waitForTimeout(2000);
  }
}

/** Scene 4 — Infinite Rush: 60-second sprint */
async function sceneInfiniteRush(page: Page) {
  log('Scene 4/7  Infinite Rush');
  await goto(page, '/typing-practice/infinite-rush');
  await applyDarkMode(page);
  await page.waitForTimeout(800);
  await showTitleCard(
    page,
    'Infinite Rush',
    '60 seconds. How many IT words can you smash through?',
  );
  await scrollToTop(page);
  await page.waitForTimeout(1200);

  const started = await startGame(page);
  if (started) {
    await scrollToTop(page);
    await page.waitForTimeout(300);
    // Long typing run — shows WPM counter climbing and word stream
    await typeWords(page, [
      'sudo', 'docker', 'nginx', 'chmod', 'grep', 'ssh', 'kubectl',
      'netstat', 'iptables', 'curl', 'wget', 'bash', 'python', 'git',
      'npm', 'node', 'aws', 'azure', 'linux', 'ubuntu', 'debian',
      'redis', 'postgres', 'mysql', 'mongo', 'ansible', 'terraform',
      'helm', 'vault', 'consul', 'apache', 'systemd', 'cron',
      'chmod', 'chown', 'grep', 'awk', 'sed', 'tail',
    ], 50);
    await page.waitForTimeout(2500); // Show results / timer running out
  } else {
    await page.waitForTimeout(2000);
  }
}

/** Scene 5 — Ghost Mode: race your personal best */
async function sceneGhostMode(page: Page) {
  log('Scene 5/7  Ghost Mode');
  await goto(page, '/typing-practice/ghost');
  await applyDarkMode(page);
  await page.waitForTimeout(800);
  await showTitleCard(
    page,
    'Ghost Mode',
    'A recording of your last run races alongside you. Can you beat yourself?',
  );
  await scrollToTop(page);
  await page.waitForTimeout(2500); // Hold on the ghost interface

  const started = await startGame(page);
  if (started) {
    await scrollToTop(page);
    await typeWords(page, [
      'sudo', 'chmod', 'docker', 'nginx', 'grep',
      'ssh', 'curl', 'bash', 'python',
    ], 72);
    await page.waitForTimeout(1800);
  } else {
    // No ghost saved yet — that's fine, still shows the interface
    await page.waitForTimeout(1500);
  }
}

/** Scene 6 — Leaderboard: see where you rank */
async function sceneLeaderboard(page: Page) {
  log('Scene 6/7  Leaderboard');
  await goto(page, '/typing-practice/leaderboard');
  await applyDarkMode(page);
  await page.waitForTimeout(800);
  await showTitleCard(
    page,
    'Leaderboard',
    'See where you stack up. Top players, WPM, accuracy — all public.',
  );
  await scrollToTop(page);
  await page.waitForTimeout(1500);
  await pan(page, 500, 4, 700);
  await scrollToTop(page);
  await page.waitForTimeout(600);
}

/** Scene 7 — CTA: beta invite, back to landing */
async function sceneCTA(page: Page) {
  log('Scene 7/7  CTA');
  await goto(page, '/typing-practice');
  await applyDarkMode(page);
  await page.waitForTimeout(800);
  await showTitleCard(
    page,
    'Open for Beta Testing',
    'No sign-up needed  •  Free to play  •  theitapprentice.com\nSee how fast you can type!',
    3800,
  );
  await scrollToTop(page);
  await page.waitForTimeout(2000);
  // Final lingering pan over the game cards
  await pan(page, 700, 7, 750);
  await scrollToTop(page);
  await page.waitForTimeout(2000); // Hold on the landing page hero
}

// ─── Entry Point ───────────────────────────────────────────────────────────

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });

  console.log('');
  console.log('┌──────────────────────────────────────────────────────┐');
  console.log('│  TheITApprentice — End-to-End Marketing Video         │');
  console.log('└──────────────────────────────────────────────────────┘');
  console.log(`  Target:      ${BASE_URL}`);
  console.log(`  Dark mode:   ${DARK_MODE}`);
  console.log(`  Resolution:  ${VIDEO_SIZE.width}×${VIDEO_SIZE.height} (720p)`);
  console.log(`  Output:      testing/videos/${TIMESTAMP}/marketing-video.webm`);
  console.log('');
  console.log('  Scenes:');
  console.log('    1/7  Homepage hero pan');
  console.log('    2/7  Typing Practice landing — all 4 game modes');
  console.log('    3/7  Quick Brown Fox — live Round 1 + Round 2 gameplay');
  console.log('    4/7  Infinite Rush — 60s sprint, live WPM counter');
  console.log('    5/7  Ghost Mode — race your personal best');
  console.log('    6/7  Leaderboard');
  console.log('    7/7  Beta CTA  —  "No sign-up needed. See how fast you can type!"');
  console.log('');
  console.log('  Cookie consent: pre-set via addInitScript (banner never appears)');
  console.log('');

  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox'],
  });

  // Single context = single continuous video
  const ctx: BrowserContext = await browser.newContext({
    viewport: VIDEO_SIZE,
    colorScheme: DARK_MODE ? 'dark' : 'light',
    recordVideo: { dir: OUT_DIR, size: VIDEO_SIZE },
  });

  // Pre-set cookie consent + theme BEFORE any page loads
  await ctx.addInitScript(
    ({ consent, dark }) => {
      try {
        localStorage.setItem('cookie_consent', consent);
        if (dark) {
          localStorage.setItem('theme', 'dark');
        }
      } catch { /* storage may not be available in init script context */ }
    },
    { consent: COOKIE_CONSENT, dark: DARK_MODE },
  );

  const page = await ctx.newPage();

  try {
    await sceneHomepage(page);
    await sceneTypingLanding(page);
    await sceneQBF(page);
    await sceneInfiniteRush(page);
    await sceneGhostMode(page);
    await sceneLeaderboard(page);
    await sceneCTA(page);
  } catch (e) {
    warn(`Unexpected error: ${e}`);
  }

  // ── Save the single video file ─────────────────────────────────────────
  const video = page.video();
  await page.close();
  await ctx.close();                             // Finalises the .webm
  await new Promise((r) => setTimeout(r, 700)); // Windows: release file lock
  await browser.close();

  if (video) {
    const generated = await video.path();
    const dest = path.join(OUT_DIR, 'marketing-video.webm');
    fs.renameSync(generated, dest);
    const sizeMb = (fs.statSync(dest).size / 1024 / 1024).toFixed(1);
    console.log('');
    console.log(`✅ Done — marketing-video.webm  (${sizeMb} MB)`);
    console.log(`   Path: ${dest}`);
  } else {
    warn('No video object — recording may have failed.');
  }

  console.log('');
  console.log('  💡 Post-production:');
  console.log('     ffmpeg -i marketing-video.webm -c:v libx264 -crf 23 marketing-video.mp4');
  console.log('     Open in DaVinci Resolve or CapCut to add background music');
  console.log('     Run with DARK_MODE=true for a dark-theme cut');
  console.log('');
}

main().catch((err) => { console.error(err); process.exit(1); });
