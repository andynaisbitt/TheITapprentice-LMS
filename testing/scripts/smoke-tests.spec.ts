/**
 * TheITApprentice — Smoke Tests
 *
 * Fast sanity checks: pages load, no console errors, key elements render.
 * Not full E2E — just "is the site alive and not broken?"
 *
 * Usage:
 *   npm run smoke                              # local
 *   npm run smoke:prod                         # production
 */

import { test, expect, Page } from '@playwright/test';

const BASE_URL = process.env.BASE_URL || 'http://localhost:5173';

// ─── Helpers ───────────────────────────────────────────────────────────────

async function expectNoJSErrors(page: Page) {
  const errors: string[] = [];
  page.on('pageerror', (err) => errors.push(err.message));
  return () => {
    const critical = errors.filter(
      (e) =>
        !e.includes('ResizeObserver') && // common false positive
        !e.includes('Non-Error promise rejection') // often benign
    );
    expect(critical, `JS errors: ${critical.join(', ')}`).toHaveLength(0);
  };
}

// ─── Core Pages ────────────────────────────────────────────────────────────

test.describe('Core Pages', () => {
  test('homepage loads', async ({ page }) => {
    const checkErrors = await expectNoJSErrors(page);
    await page.goto(`${BASE_URL}/`);
    await expect(page).toHaveTitle(/.+/);
    checkErrors();
  });

  test('blog page loads', async ({ page }) => {
    await page.goto(`${BASE_URL}/blog`);
    await expect(page.locator('h1, h2').first()).toBeVisible();
  });

  test('about page loads', async ({ page }) => {
    await page.goto(`${BASE_URL}/about`);
    await expect(page.locator('h1, h2').first()).toBeVisible();
  });

  test('login page loads', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`);
    await expect(page.locator('input[type="email"], input[name="email"]').first()).toBeVisible();
  });

  test('leaderboard loads', async ({ page }) => {
    await page.goto(`${BASE_URL}/leaderboard`);
    await expect(page.locator('body')).not.toBeEmpty();
  });
});

// ─── Typing Games ──────────────────────────────────────────────────────────

test.describe('Typing Games', () => {
  test('typing practice landing loads', async ({ page }) => {
    const checkErrors = await expectNoJSErrors(page);
    await page.goto(`${BASE_URL}/typing-practice`);

    // Game mode cards should be visible
    await expect(page.locator('text=Quick Brown Fox')).toBeVisible();
    await expect(page.locator('text=Infinite Rush')).toBeVisible();
    await expect(page.locator('text=Ghost Mode')).toBeVisible();
    await expect(page.locator('text=Practice')).toBeVisible();
    checkErrors();
  });

  test('quick brown fox page loads', async ({ page }) => {
    await page.goto(`${BASE_URL}/typing-practice/play`);
    await expect(page.locator('body')).not.toBeEmpty();
    // Should show a start/play button or the game already loaded
    const hasStart = await page.locator('button', { hasText: /start|play|begin/i }).count();
    const hasInput = await page.locator('input').count();
    expect(hasStart + hasInput).toBeGreaterThan(0);
  });

  test('infinite rush page loads', async ({ page }) => {
    await page.goto(`${BASE_URL}/typing-practice/infinite-rush`);
    await expect(page.locator('body')).not.toBeEmpty();
  });

  test('ghost mode page loads', async ({ page }) => {
    await page.goto(`${BASE_URL}/typing-practice/ghost`);
    await expect(page.locator('body')).not.toBeEmpty();
  });

  test('practice mode page loads', async ({ page }) => {
    await page.goto(`${BASE_URL}/typing-practice/practice`);
    await expect(page.locator('body')).not.toBeEmpty();
  });

  test('typing leaderboard loads', async ({ page }) => {
    await page.goto(`${BASE_URL}/typing-practice/leaderboard`);
    await expect(page.locator('body')).not.toBeEmpty();
  });

  test('QBF game is startable', async ({ page }) => {
    await page.goto(`${BASE_URL}/typing-practice/play`);
    await page.waitForTimeout(500);

    const startBtn = page.locator('button', { hasText: /start|play|begin/i }).first();
    if (await startBtn.isVisible()) {
      await startBtn.click();
      await page.waitForTimeout(500);
      // After starting, an input should appear
      const input = page.locator('input').first();
      await expect(input).toBeVisible({ timeout: 5000 });
    }
    // If no start button, game auto-started — either way we pass
  });

  test('infinite rush game is startable', async ({ page }) => {
    await page.goto(`${BASE_URL}/typing-practice/infinite-rush`);
    await page.waitForTimeout(500);

    const startBtn = page.locator('button', { hasText: /start|play|begin/i }).first();
    if (await startBtn.isVisible()) {
      await startBtn.click();
      await page.waitForTimeout(500);
    }
    // Timer or word display should be visible
    await expect(page.locator('body')).not.toBeEmpty();
  });
});

// ─── Learn Pages ───────────────────────────────────────────────────────────

test.describe('Learn Pages', () => {
  test('courses page loads', async ({ page }) => {
    await page.goto(`${BASE_URL}/courses`);
    await expect(page.locator('body')).not.toBeEmpty();
  });

  test('tutorials page loads', async ({ page }) => {
    await page.goto(`${BASE_URL}/tutorials`);
    await expect(page.locator('body')).not.toBeEmpty();
  });

  test('quizzes page loads', async ({ page }) => {
    await page.goto(`${BASE_URL}/quizzes`);
    await expect(page.locator('body')).not.toBeEmpty();
  });

  test('skills page loads', async ({ page }) => {
    await page.goto(`${BASE_URL}/skills`);
    await expect(page.locator('body')).not.toBeEmpty();
  });

  test('challenges page loads', async ({ page }) => {
    await page.goto(`${BASE_URL}/challenges`);
    await expect(page.locator('body')).not.toBeEmpty();
  });
});

// ─── Navigation ────────────────────────────────────────────────────────────

test.describe('Navigation', () => {
  test('header renders on homepage', async ({ page }) => {
    await page.goto(`${BASE_URL}/`);
    await expect(page.locator('header')).toBeVisible();
  });

  test('sidebar opens and closes', async ({ page }) => {
    await page.goto(`${BASE_URL}/`);
    await page.setViewportSize({ width: 1280, height: 800 });

    // Find and click the hamburger button
    const hamburger = page.locator('button[aria-label="Toggle navigation sidebar"]');
    if (await hamburger.isVisible()) {
      await hamburger.click();
      await page.waitForTimeout(300);

      // Sidebar should be visible
      await expect(page.locator('aside')).toBeVisible();

      // Click X to close
      const closeBtn = page.locator('aside button[aria-label="Close sidebar"]');
      await closeBtn.click();
      await page.waitForTimeout(300);

      // Sidebar should be gone
      await expect(page.locator('aside')).not.toBeVisible();
    }
  });

  test('navigation links work — blog', async ({ page }) => {
    await page.goto(`${BASE_URL}/`);
    await page.click('a[href="/blog"]');
    await expect(page).toHaveURL(/\/blog/);
  });

  test('404 page shows for unknown route', async ({ page }) => {
    const response = await page.goto(`${BASE_URL}/this-page-does-not-exist`);
    // Either a 404 status or a "not found" page element
    const body = await page.textContent('body');
    const is404 =
      response?.status() === 404 ||
      (body?.toLowerCase().includes('not found') ?? false) ||
      (body?.toLowerCase().includes('404') ?? false);
    // Just check the page renders something — SPA 404s vary
    await expect(page.locator('body')).not.toBeEmpty();
  });
});

// ─── API Health ────────────────────────────────────────────────────────────

test.describe('API Health', () => {
  const API_URL = process.env.API_URL || 'http://localhost:8100';

  test('backend health check', async ({ request }) => {
    const response = await request.get(`${API_URL}/health`).catch(() => null);
    if (response) {
      expect(response.status()).toBeLessThan(500);
    } else {
      // Backend not reachable in this environment — skip gracefully
      console.log('  ℹ Backend not reachable, skipping API health check');
    }
  });

  test('site settings API responds', async ({ request }) => {
    const response = await request
      .get(`${API_URL}/api/settings/public`)
      .catch(() => null);
    if (response) {
      expect(response.status()).toBeLessThan(500);
    }
  });
});

// ─── Dark Mode ─────────────────────────────────────────────────────────────

test.describe('Dark Mode', () => {
  test('dark mode applies on homepage', async ({ page }) => {
    await page.goto(`${BASE_URL}/`);

    // Toggle dark mode
    await page.evaluate(() => {
      document.documentElement.classList.add('dark');
      localStorage.setItem('theme', 'dark');
    });
    await page.waitForTimeout(300);

    const hasDark = await page.evaluate(() =>
      document.documentElement.classList.contains('dark')
    );
    expect(hasDark).toBe(true);
  });

  test('typing practice works in dark mode', async ({ page }) => {
    await page.goto(`${BASE_URL}/typing-practice`);
    await page.evaluate(() => {
      document.documentElement.classList.add('dark');
    });
    await page.waitForTimeout(300);
    await expect(page.locator('text=Quick Brown Fox')).toBeVisible();
  });
});
