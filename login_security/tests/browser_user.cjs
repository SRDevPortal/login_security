// Real User extension in Chrome, with a minimal mocked Frappe form/dialog API.
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const script = fs.readFileSync(path.join(__dirname, "../public/js/user.js"), "utf8");

(async () => {
  const browser = await chromium.launch({ headless: true,
    executablePath: process.env.LOGIN_SECURITY_BROWSER || undefined });
  try {
    const page = await browser.newPage();
    await page.route("https://user.test/**", route => route.fulfill({ contentType: "text/html", body: '<div id="status"></div>' }));
    await page.goto("https://user.test/app/user/test");
    await page.evaluate(() => {
      window.__ = value => value;
      window.$ = html => {
        const element = document.createElement(html.replace(/[<>]/g, ""));
        return { element, text(value) { element.textContent = value; return this; } };
      };
      window.dialogs = []; window.calls = []; window.notices = [];
      window.state = { label: "Prepared <img src=x>", destination: "WhatsApp ending 2671",
        can_manage: true, supported: true, enrolled: true, verified: false, coverage_version: 2 };
      window.frappe = { csrf_token: "test-csrf", msgprint: msg => notices.push(msg), show_alert: () => {},
        call: async () => ({ message: state }),
        ui: { form: { on: (name, handlers) => window.handlers = handlers },
          Dialog: class {
            constructor(options) { Object.assign(this, options); dialogs.push(this); this.values = {}; }
            get_primary_btn() { return { prop: () => {} }; }
            set_value(key, value) { this.values[key] = value; }
            show() { this.visible = true; }
            hide() { this.visible = false; }
          },
        },
      };
      window.fetch = async (url, options) => {
        calls.push({ url, body: JSON.parse(options.body), headers: options.headers });
        return { ok: true, json: async () => ({ message: url.endsWith(".complete") ? {
          status: "enrolled", recovery_codes: ["test-recovery-1", "test-recovery-2"],
        } : { status: "challenge", challenge_id: "test-id", delivery: "accepted" } }) };
      };
      window.frm = { doc: { name: "staff@example.test", mobile_no: "+14155552671", login_security_enabled: 1 },
        is_new: () => false, is_dirty: () => false, buttons: {}, properties: {},
        add_custom_button(label, handler) { this.buttons[label] = handler; },
        remove_custom_button(label) { delete this.buttons[label]; },
        set_df_property(field, key, value) { this.properties[field + "." + key] = value; },
        reload_doc: async () => { window.reloaded = true; },
        fields_dict: { login_security_status: { $wrapper: {
          empty() { document.querySelector("#status").replaceChildren(); return this; },
          append(...items) { items.forEach(item => document.querySelector("#status").append(item.element || item)); },
        } } },
      };
    });
    await page.addScriptTag({ content: script });
    await page.evaluate(() => handlers.refresh(frm));
    assert.equal(await page.locator("#status img").count(), 0);
    assert.equal(await page.evaluate(() => frm.properties["mobile_no.read_only"]), true);
    assert.equal(await page.evaluate(() => frm.properties["mobile_no.reqd"]), true);
    console.log("PASS verified number protected and status rendered as text");

    await page.evaluate(() => frm.buttons["Verify Mobile No."]());
    const fields = await page.evaluate(() => dialogs[0].fields);
    assert.equal(fields.find(f => f.fieldname === "destination").read_only, 1);
    assert.equal(fields.some(f => f.fieldname === "new_phone"), false);
    await page.evaluate(() => dialogs[0].primary_action({ password: "test-password", destination: "+442079460123" }));
    const initial = await page.evaluate(() => calls[0]);
    assert.deepEqual(initial.body, { user: "staff@example.test", password: "test-password" });
    assert.equal(initial.headers["X-Frappe-CSRF-Token"], "test-csrf");
    await page.evaluate(() => dialogs[1].primary_action({ code: "012345" }));
    assert.equal(await page.evaluate(() => calls[1].body.code), "012345");
    assert.equal(await page.evaluate(() => reloaded), true);
    assert.equal(await page.evaluate(() => dialogs[2].fields[0].default), "test-recovery-1\ntest-recovery-2");
    console.log("PASS initial enrollment uses saved target and displays recovery once");

    await page.evaluate(async () => { state.verified = true; await handlers.refresh(frm); });
    assert.equal(await page.evaluate(() => !!frm.buttons["Verify Mobile No."]), false);
    assert.equal(await page.evaluate(() => !!frm.buttons["Change Verified Number"]), true);
    assert.match(await page.locator("#status").textContent(), /Verified/);
    assert.equal(await page.locator(".login-security-user-badge.is-verified").count(), 1);
    assert.equal(await page.locator(".login-security-user-row").count(), 1);
    assert.equal(await page.locator("#login-security-user-styles").count(), 1);
    console.log("PASS verified number hides initial verification action after refresh");
    await page.evaluate(() => frm.buttons["Change Verified Number"]());
    await page.evaluate(() => dialogs[3].primary_action({ password: "test-password", new_phone: "+442079460123" }));
    const change = await page.evaluate(() => calls[2]);
    assert.equal(change.url.endsWith(".begin_change"), true);
    assert.equal(change.body.new_phone, "+442079460123");
    assert.equal(await page.evaluate(() => frm.doc.mobile_no), "+14155552671");
    console.log("PASS replacement uses staged endpoint without editing User");

    await page.evaluate(async () => { state.verified = false; await handlers.refresh(frm); });
    assert.equal(await page.evaluate(() => !!frm.buttons["Verify Mobile No."]), true);
    assert.match(await page.locator("#status").textContent(), /Not verified/);
    console.log("PASS revoked or mismatched verification restores verification action");
    await page.evaluate(async () => { state.can_manage = false; await handlers.refresh(frm); });
    assert.deepEqual(await page.evaluate(() => Object.keys(frm.buttons)), []);
    assert.equal(await page.evaluate(() => frm.properties["login_security_enabled.read_only"]), true);
    console.log("PASS ordinary user cannot access management actions");
    await page.evaluate(() => { frm.doc.login_security_enabled = 0; handlers.login_security_enabled(frm); });
    assert.equal(await page.evaluate(() => frm.properties["mobile_no.reqd"]), false);
    await page.evaluate(() => { frm.doc.login_security_enabled = 1; handlers.login_security_enabled(frm); });
    assert.equal(await page.evaluate(() => frm.properties["mobile_no.reqd"]), true);
    await page.evaluate(() => {
      frm._login_security_mobile_required = true;
      frm.doc.login_security_enabled = 0;
      handlers.login_security_enabled(frm);
    });
    assert.equal(await page.evaluate(() => frm.properties["mobile_no.reqd"]), true);
    console.log("PASS Mobile No. requirement follows checkbox and preserves existing requirements");
    console.log("7 User form scenarios passed");
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
