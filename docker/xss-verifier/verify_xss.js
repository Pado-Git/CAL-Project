#!/usr/bin/env node
/**
 * XSS Verification Script using Playwright
 * Verifies if XSS payloads actually execute in a real browser
 */

const { chromium } = require('playwright');

async function verifyXSS(targetURL, payload) {
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

    // Detect alert dialogs
    page.on('dialog', async dialog => {
        xssTriggered = true;
        alertMessage = dialog.message();
        console.log(`[XSS TRIGGERED] Alert detected: ${alertMessage}`);
        await dialog.dismiss();
    });

    // Detect console errors that might indicate XSS
    page.on('console', msg => {
        if (msg.type() === 'error' && msg.text().includes('XSS')) {
            console.log(`[XSS INDICATOR] Console error: ${msg.text()}`);
        }
    });

    try {
        console.log(`[VERIFY] Testing URL: ${targetURL}`);
        console.log(`[VERIFY] Payload: ${payload}`);

        // Navigate to the URL with payload
        await page.goto(targetURL, {
            waitUntil: 'networkidle',
            timeout: 10000
        });

        // Wait a bit for any delayed XSS execution
        await page.waitForTimeout(2000);

        // Check if XSS was triggered
        const result = {
            url: targetURL,
            payload: payload,
            verified: xssTriggered,
            alertMessage: alertMessage,
            timestamp: new Date().toISOString()
        };

        console.log(JSON.stringify(result));

    } catch (error) {
        console.error(`[ERROR] Verification failed: ${error.message}`);
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
    console.error('Usage: verify_xss.js <target_url> <payload>');
    process.exit(1);
}

const targetURL = args[0];
const payload = args[1];

verifyXSS(targetURL, payload);
