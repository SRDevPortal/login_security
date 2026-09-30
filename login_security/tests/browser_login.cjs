// Browser interaction tests with mocked APIs; never connects to a Frappe/provider account.
// NODE_PATH=<directory containing playwright> node .../browser_login.cjs
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const script = fs.readFileSync(path.join(__dirname, "../public/js/login.js"), "utf8");
const css = fs.readFileSync(path.join(__dirname, "../public/css/login.css"), "utf8");
const html = `<!doctype html><html><body><main><section class="for-login">
  <form class="form-login"><input id="login_email"><input id="login_password" type="password">
  <button type="submit">Login</button></form></section></main><script>
  window.nativeCalls = []; window.notices = [];
  window.frappe = {csrf_token: "test", msgprint: value => window.notices.push(value)};
  window.login = {call: args => window.nativeCalls.push(args)};
  document.querySelector("form").addEventListener("submit", event => {
    event.preventDefault(); window.nativeCalls.push({native: true});
  });
  </script><script src="/login-security.js"></script></body></html>`;

(async () => {
  const browser = await chromium.launch({headless: true,
    executablePath: process.env.LOGIN_SECURITY_BROWSER || undefined, args: ["--no-sandbox"]});
  let passed = 0;
  async function scenario(name, options, test) {
    const context = await browser.newContext();
    const page = await context.newPage();
    if (options.viewport) await page.setViewportSize(options.viewport);
    const calls = [];
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.route("https://login.test/**", async route => {
      const url = new URL(route.request().url());
      if (url.pathname === "/assets/login_security/css/login.css") return route.fulfill({contentType: "text/css", body: css});
      if (url.pathname === "/login-security.js") return route.fulfill({contentType: "text/javascript", body: script});
      if (url.pathname === "/login" || url.pathname === "/") return route.fulfill({contentType: "text/html", body: html});
      if (!url.pathname.startsWith("/api/")) return route.fulfill({contentType: "text/html", body: "Destination"});
      const method = url.pathname.split(".").pop();
      const body = route.request().postDataJSON();
      calls.push({method, body, headers: route.request().headers()});
      let result;
      if (method === "configuration") {
        if (options.early) await new Promise(resolve => setTimeout(resolve, 1500));
        if (options.configurationFailure) return route.fulfill({status: 503, contentType: "application/json", body: "{}"});
        result = {enabled: options.enabled !== false};
      }
      else if (options.response) result = options.response(method, body);
      if (!result) result = ["start", "resend"].includes(method) ? {
        status: "challenge", challenge_id: "test-challenge", destination: "WhatsApp ending 2671",
        expires_in: 300, resend_after: 0, delivery: "accepted"
      } : {status: "logged_in", home_page: "/app"};
      return route.fulfill({contentType: "application/json", body: JSON.stringify({message: result})});
    });
    try {
      const configured = page.waitForResponse(response => response.url().endsWith(".configuration"));
      await page.goto("https://login.test" + (options.path || "/login") + (options.query || ""));
      if (!options.early) await configured;
      // Let the fetch JSON and chained capability handler settle before the user submits.
      await page.waitForTimeout(50);
      await page.fill("#login_email", "staff@example.test");
      await page.fill("#login_password", "test-password");
      await page.click('button[type="submit"]');
      await test(page, calls);
      assert.deepEqual(errors, []);
      passed++;
      console.log("PASS " + name);
    } finally { await context.close(); }
  }
  try {
    await scenario("OTP preserves leading zeros and CRM redirect", {query: "?redirect-to=/crm"}, async (page, calls) => {
      await page.waitForSelector("#login-security-code");
      const card = await page.locator(".login-security-card").boundingBox();
      assert.ok(card.width <= 448);
      await page.screenshot({path: path.join(require("node:os").tmpdir(), `login-security-desktop-${process.pid}.png`)});
      assert.equal(await page.inputValue("#login_password"), "");
      await page.fill("#login-security-code", "012345");
      await page.click(".login-security button[type=submit]");
      await page.waitForURL("https://login.test/crm");
      assert.equal(calls.find(call => call.method === "verify").body.code, "012345");
      assert.equal(calls.find(call => call.method === "start").headers["x-login-security"], "1");
    });
    await scenario("Recovery input and external redirect rejection", {query: "?redirect-to=https://untrusted.test"}, async page => {
      await page.click("[data-recovery]");
      await page.fill("#login-security-code", "0123456789abcdef0123456789abcdef");
      await page.click(".login-security button[type=submit]");
      await page.waitForURL("https://login.test/app");
    });
    await scenario("Resend and safe error rendering", {response: method => method === "verify" ? {
      status: "error", message: "<img src=x onerror=alert(1)> Invalid code"
    } : null}, async (page, calls) => {
      await page.click("[data-resend]");
      await page.waitForFunction(() => !document.querySelector("[data-resend]").disabled);
      await page.fill("#login-security-code", "123456");
      await page.click(".login-security button[type=submit]");
      await page.waitForFunction(() => document.querySelector("[data-status]").textContent.includes("Invalid code"));
      assert.equal(await page.locator("[data-status] img").count(), 0);
      assert.equal(calls.filter(call => call.method === "resend").length, 1);
      assert.equal(await page.inputValue("#login-security-code"), "");
    });
    await scenario("Disabled policy keeps native handler", {enabled: false}, async (page, calls) => {
      await page.waitForFunction(() => window.nativeCalls.length === 1);
      assert.equal(calls.filter(call => call.method === "start").length, 0);
      assert.equal(await page.locator(".login-security").count(), 0);
    });
    await scenario("Uncovered user delegates to native login", {response: () => ({status: "native_login"})}, async page => {
      await page.waitForFunction(() => window.nativeCalls.length === 1);
      assert.equal(await page.evaluate(() => window.nativeCalls[0].cmd), "login");
      assert.equal(await page.locator(".login-security").count(), 0);
    });
    await scenario("Mobile layout and recovery mode remain usable", {viewport: {width: 375, height: 812}}, async page => {
      await page.waitForSelector("#login-security-code");
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
      await page.screenshot({path: path.join(require("node:os").tmpdir(), `login-security-mobile-${process.pid}.png`)});
      await page.click("[data-recovery]");
      assert.equal(await page.getAttribute("#login-security-code", "maxlength"), "64");
      assert.equal(await page.locator("[data-timer]").textContent(), "Each recovery code can be used once.");
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    });
    await scenario("Early submission waits for verification settings", {early: true}, async (page, calls) => {
      await page.waitForSelector("#login-security-code");
      assert.equal(calls.filter(call => call.method === "start").length, 1);
      assert.equal(await page.evaluate(() => window.nativeCalls.length), 0);
    });
    await scenario("Configuration outage does not fall through to native login", {configurationFailure: true}, async page => {
      await page.waitForFunction(() => window.notices.length > 0);
      assert.equal(await page.evaluate(() => window.nativeCalls.length), 0);
      assert.match(await page.evaluate(() => window.notices[0]), /Unable to load login verification settings/);
    });
    await scenario("Root hash login opens OTP instead of native login", {path: "/#login"}, async page => {
      await page.waitForSelector("#login-security-code");
      assert.equal(await page.evaluate(() => window.nativeCalls.length), 0);
      await page.fill("#login-security-code", "012345");
      await page.click('.login-security button[type="submit"]');
      await page.waitForURL("https://login.test/app");
    });
    console.log(`${passed} browser scenarios passed`);
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
