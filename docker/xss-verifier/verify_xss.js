#!/usr/bin/env node
/**
 * XSS Verification Script using Playwright
 * Verifies if XSS payloads actually execute in a real browser
 */

const { chromium } = require('playwright');

async function verifyXSS(targetURL, payload, method, parameter) {
    const browser = await chromium.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    const context = await browser.newContext({
        ignoreHTTPSErrors: true
    });

    const page = await context.newPage();

    let xssTriggered = false;
    let alertMessage = '';
    let consoleLogs = [];

    // Detect alert dialogs
    page.on('dialog', async dialog => {
        xssTriggered = true;
        alertMessage = dialog.message();
        // console.log(`[XSS TRIGGERED] Alert detected: ${alertMessage}`); // Silent
        await dialog.dismiss();
    });

    // Detect console errors that might indicate XSS
    page.on('console', msg => {
        if (msg.type() === 'error' && msg.text().includes('XSS')) {
            consoleLogs.push(msg.text());
        }
    });

    try {
        // console.log(`[VERIFY] Testing URL: ${targetURL}`); // Silent
        // console.log(`[VERIFY] Payload: ${payload}`);       // Silent
        // console.log(`[VERIFY] Method: ${method}, Param: ${parameter}`); // Silent

        // Strategy Selection
        const isPost = method && method.toUpperCase() === 'POST';

        if (parameter) { // Specific parameter attack
            if (isPost) {
                console.log(`[VERIFY] Strategy: POST Injection via Auto-Submit Form`);
                // Construct auto-submit form to simulate POST request
                // note: simple replacement for quotes to avoid breaking HTML
                const safePayload = payload.replace(/"/g, '&quot;');
                const html = `
                    <html>
                        <body>
                            <form id="csrf" action="${targetURL}" method="POST">
                                <input type="hidden" name="${parameter}" value="${safePayload}">
                            </form>
                            <script>document.getElementById('csrf').submit();</script>
                        </body>
                    </html>
                `;
                // Use setContent to load our malicious page which auto-submits
                await page.setContent(html);
            } else {
                console.log(`[VERIFY] Strategy: GET Injection via URL Parameter`);
                const separator = targetURL.includes('?') ? '&' : '?';
                const attackURL = `${targetURL}${separator}${parameter}=${encodeURIComponent(payload)}`;
                await page.goto(attackURL, { waitUntil: 'networkidle', timeout: 10000 });
            }
        } else {
            console.log(`[VERIFY] Strategy: Direct Visit (No parameter specified)`);
            // Navigate to the URL directly
            await page.goto(targetURL, {
                waitUntil: 'networkidle',
                timeout: 10000
            });
        }

        // Wait a bit for any delayed XSS execution (for Reflected XSS)
        await page.waitForTimeout(2000);

        // Check if XSS was triggered immediately
        let result = {
            url: targetURL,
            payload: payload,
            verified: xssTriggered,
            alertMessage: alertMessage,
            consoleLogs: consoleLogs,
            timestamp: new Date().toISOString()
        };

        // If not verified yet and Method is POST or we have a parameter, try to exploit form
        if (!xssTriggered && (method.toUpperCase() === 'POST' || parameter !== '')) {
            console.log('[VERIFY] No initial XSS. Attempting specific form exploitation...');

            try {
                // If specific parameter is provided, look for it
                let targetInput = null;
                if (parameter) {
                    targetInput = await page.$(`input[name="${parameter}"], textarea[name="${parameter}"]`);
                    if (!targetInput) {
                        console.log(`[VERIFY] Parameter '${parameter}' not found on page.`);
                        // Fallback to finding any form if specific param not found?
                    }
                }

                // Initial scrape of forms count
                const formCount = await page.$$eval('form', forms => forms.length);
                console.log(`[VERIFY] Found ${formCount} forms`);

                if (formCount === 0) {
                    // Debug: Print title and body start to see where we are
                    const title = await page.title();
                    const body = await page.innerHTML('body');
                    console.log(`[VERIFY] Page Title: ${title}`);
                    console.log(`[VERIFY] Page Body Start: ${body.substring(0, 200)}...`);
                }

                for (let i = 0; i < formCount; i++) {
                    try {
                        if (i > 0) {
                            await page.goto(targetURL, { waitUntil: 'domcontentloaded', timeout: 5000 }).catch(() => { });
                        }

                        const forms = await page.$$('form');
                        if (!forms[i]) {
                            continue;
                        }
                        const form = forms[i];

                        // Fill inputs
                        const inputs = await form.$$('input[type="text"], textarea');
                        let filled = false;
                        for (const input of inputs) {
                            const name = await input.getAttribute('name');
                            if (parameter && name !== parameter) {
                                continue; // Skip if not matching requested parameter
                            }
                            await input.fill(payload).catch(() => { });
                            filled = true;
                        }

                        if (!filled && parameter) {
                            console.log(`[VERIFY] Form ${i} did not have parameter '${parameter}'`);
                            continue;
                        }

                        // Submit
                        const submitBtn = await form.$('button[type="submit"], input[type="submit"]');

                        // Swallow errors during click/submit as they cause navigation
                        const navPromise = page.waitForNavigation({ timeout: 5000 }).catch(() => { });

                        if (submitBtn) {
                            await submitBtn.click().catch(e => console.log(`[VERIFY] Click error: ${e.message}`));
                        } else {
                            await form.evaluate(f => f.submit()).catch(e => console.log(`[VERIFY] Submit error: ${e.message}`));
                        }

                        // Wait for nav
                        await navPromise;

                    } catch (e) {
                        console.log(`[VERIFY] Iteration error: ${e.message}`);
                    }

                    if (xssTriggered) {
                        result.verified = true;
                        result.alertMessage = alertMessage;
                        break;
                    }
                }

            } catch (outerErr) {
                console.log(`[VERIFY] Critical loop error: ${outerErr.message}`);
            }
        }

        console.log(JSON.stringify(result));

    } catch (error) {
        // console.error(`[ERROR] Verification failed: ${error.message}`); // Silent
        console.log(JSON.stringify({
            url: targetURL,
            payload: payload,
            verified: false,
            error: error.message
        }));
    } finally {
        await browser.close();
    }
}

// Main execution
const args = process.argv.slice(2);
if (args.length < 2) {
    console.error('Usage: verify_xss.js <target_url> <payload> [method] [parameter]');
    process.exit(1);
}

const targetURL = args[0];
const payload = args[1];
const method = args[2] || 'GET';
const parameter = args[3] || '';

verifyXSS(targetURL, payload, method, parameter).catch(err => {
    console.error(`[FATAL] Top-level error: ${err.message}`);
    console.log(JSON.stringify({
        url: targetURL,
        payload: payload,
        verified: false,
        error: err.message
    }));
    process.exit(1);
});
