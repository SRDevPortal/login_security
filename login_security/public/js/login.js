/* Login Security extends the shared Frappe page without changing core assets. */
(() => {
  // Frappe can serve its login form at the website root with #login navigation.
  // Only intercept .form-login submissions; ordinary home-page forms stay untouched.
  if (!["", "/login"].includes(window.location.pathname.replace(/\/$/, ""))) return;
  let pending = null;
  let panel = null;
  let timer = null;
  let busy = false;
  let recovery = false;
  const stylesheet = document.createElement("link");
  stylesheet.rel = "stylesheet";
  stylesheet.href = "/assets/login_security/css/login.css?v=20260929-2";
  document.head.appendChild(stylesheet);

  const api = async (method, body) => {
    const response = await fetch(`/api/method/login_security.api.login.${method}`, {
      method: "POST", credentials: "same-origin", cache: "no-store",
      headers: { "Content-Type": "application/json", "X-Login-Security": "1",
        "X-Frappe-CSRF-Token": window.frappe?.csrf_token || "" },
      body: JSON.stringify(body),
    });
    const data = await response.json();
    const result = data.message;
    if (!response.ok || !result || result.status === "error") {
      throw new Error(result?.message || "Login verification is unavailable. Please try again.");
    }
    return result;
  };

  function status(message, error = false) {
    panel.querySelector("[data-status]").textContent = message;
    panel.querySelector("[data-status]").classList.toggle("is-error", error);
  }

  function setBusy(value) {
    busy = value;
    panel?.querySelectorAll("button").forEach(button => { button.disabled = value; });
    if (panel) {
      panel.setAttribute("aria-busy", String(value));
      panel.querySelector('[type="submit"]').textContent = value ? "Please wait…" : "Verify and sign in";
    }
    tick();
  }

  function tick() {
    if (!panel || !pending) return;
    const remaining = Math.max(0, Math.ceil((pending.expires - Date.now()) / 1000));
    const cooldown = Math.max(0, Math.ceil((pending.resendAt - Date.now()) / 1000));
    const duration = seconds => `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
    panel.querySelector("[data-timer]").textContent = recovery ? "Each recovery code can be used once." :
      remaining ? `Code expires in ${duration(remaining)}` : "Code expired. Request a new code.";
    panel.querySelector('[type="submit"]').disabled = busy || (!recovery && remaining === 0);
    const resend = panel.querySelector("[data-resend]");
    resend.textContent = cooldown ? `Resend in ${duration(cooldown)}` : "Resend code";
    resend.disabled = busy || cooldown > 0;
  }

  function acceptChallenge(result) {
    pending = { id: result.challenge_id, expires: Date.now() + result.expires_in * 1000,
      resendAt: Date.now() + result.resend_after * 1000 };
    panel.querySelector("[data-destination]").textContent = result.destination;
    status(result.delivery === "accepted" ? "Enter the code sent to your WhatsApp." :
      result.delivery === "rejected" ? "The message could not be sent. Retry after the countdown or use a recovery code." :
        "Delivery is not confirmed. Enter the code if it arrives, or retry after the countdown.");
    tick();
  }

  function finish(result) {
    if (result.status !== "logged_in") throw new Error("Login did not complete. Please restart.");
    const requested = new URLSearchParams(window.location.search).get("redirect-to");
    const safePath = (value) => {
      if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || /[\\\x00-\x1f]/.test(value)) return null;
      const url = new URL(value, window.location.origin);
      return url.origin === window.location.origin && url.pathname !== "/login" ? url.pathname + url.search + url.hash : null;
    };
    window.location.assign(safePath(requested) || safePath(result.home_page) || "/app");
  }

  function showPanel(result) {
    if (!panel) {
      panel = document.createElement("section");
      panel.className = "login-security";
      panel.setAttribute("aria-labelledby", "login-security-title");
      panel.innerHTML = `<div class="login-security-card">
        <div class="login-security-eyebrow">LOGIN VERIFICATION</div>
        <h2 id="login-security-title">Verify your login</h2>
        <p class="login-security-intro">Enter your 6-digit WhatsApp code to continue.</p>
        <p class="login-security-destination" data-destination></p>
        <form data-code-form><label for="login-security-code">Verification code</label>
          <input id="login-security-code" class="form-control" type="text" inputmode="numeric"
            autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" placeholder="000000"
            aria-describedby="login-security-status login-security-timer" required>
          <p id="login-security-status" data-status role="status" aria-live="polite"></p>
          <p id="login-security-timer" data-timer></p>
          <button type="submit" class="btn btn-primary btn-block">Verify and sign in</button>
        </form>
        <div class="login-security-resend"><span>Didn't get a code?</span>
          <button type="button" data-resend>Resend code</button></div>
        <div class="login-security-footer">
          <button type="button" data-recovery>Use a recovery code</button>
          <button type="button" data-restart>Back to login</button>
        </div>
      </div>`;
      document.querySelector(".for-login").parentElement.appendChild(panel);
      panel.querySelector("form").addEventListener("submit", async event => {
        event.preventDefault();
        if (busy || !pending) return;
        const input = panel.querySelector("input");
        setBusy(true);
        try {
          const value = input.value.trim();
          input.value = "";
          finish(await api(recovery ? "recover" : "verify", {challenge_id: pending.id,
            ...(recovery ? {recovery_code: value} : {code: value})}));
        } catch (error) { status(error.message, true); input.focus(); }
        finally { setBusy(false); }
      });
      panel.querySelector("[data-resend]").addEventListener("click", async () => {
        if (busy || !pending) return;
        setBusy(true);
        try { acceptChallenge(await api("resend", {challenge_id: pending.id})); }
        catch (error) { status(error.message, true); }
        finally { setBusy(false); }
      });
      panel.querySelector("[data-recovery]").addEventListener("click", () => {
        recovery = !recovery;
        const input = panel.querySelector("input");
        input.value = "";
        input.maxLength = recovery ? 64 : 6;
        input.inputMode = recovery ? "text" : "numeric";
        input.pattern = recovery ? "[a-fA-F0-9]{32}" : "[0-9]{6}";
        input.autocomplete = recovery ? "off" : "one-time-code";
        input.placeholder = recovery ? "Enter recovery code" : "000000";
        panel.classList.toggle("is-recovery", recovery);
        panel.querySelector(".login-security-intro").textContent = recovery ?
          "Use a saved recovery code to continue." : "Enter your 6-digit WhatsApp code to continue.";
        panel.querySelector("label").textContent = recovery ? "Recovery code" : "Verification code";
        panel.querySelector("[data-recovery]").textContent = recovery ? "Use WhatsApp code" : "Use a recovery code";
        status(recovery ? "Enter one unused recovery code provided during enrollment." : "Enter the newest WhatsApp code.");
        tick();
        input.focus();
      });
      panel.querySelector("[data-restart]").addEventListener("click", () => window.location.reload());
    }
    panel.parentElement.querySelectorAll("section:not(.login-security)").forEach(section => { section.style.display = "none"; });
    panel.style.display = "block";
    acceptChallenge(result);
    clearInterval(timer);
    timer = setInterval(tick, 1000);
    panel.querySelector("input").focus();
  }

  document.addEventListener("submit", async event => {
    if (!event.target.matches(".form-login")) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    if (busy) return;
    const usr = document.querySelector("#login_email").value.trim();
    let pwd = document.querySelector("#login_password").value;
    const button = event.target.querySelector('button[type="submit"]');
    busy = true;
    if (button) button.disabled = true;
    try {
      // Preserve emergency access if configuration loading fails.
      if (usr.toLowerCase() === "administrator") {
        window.login.call({cmd: "login", usr, pwd}, null, "/login");
        return;
      }
      const config = await configurationReady;
      if (!config) throw new Error("Unable to load login verification settings. Reload the page and try again.");
      if (!config.enabled) {
        window.login.call({cmd: "login", usr, pwd}, null, "/login");
        return;
      }
      const response = await fetch("/api/method/login", {
        method: "POST", credentials: "same-origin", cache: "no-store",
        headers: {"Content-Type": "application/json", "X-Login-Security": "1",
          "X-Frappe-CSRF-Token": window.frappe?.csrf_token || ""},
        body: JSON.stringify({usr, pwd}),
      });
      const data = await response.json();
      if (!data.login_security) {
        const handler = window.login.login_handlers?.[response.status];
        if (!handler) throw new Error("Native login did not complete. Reload and try again.");
        handler(data);
        return;
      }
      const result = data.login_security;
      if (result.status === "error") throw new Error(result.message);
      if (result.status === "native_login") {
        window.login.call({cmd: "login", usr, pwd}, null, "/login");
      } else {
        document.querySelector("#login_password").value = "";
        showPanel(result);
      }
    } catch (error) {
      document.querySelector("#login_password").value = "";
      window.frappe.msgprint(error.message);
    } finally {
      pwd = "";
      busy = false;
      if (button) button.disabled = false;
      tick();
    }
  }, true);

  const configurationReady = fetch("/api/method/login_security.api.login.configuration", {credentials: "same-origin", cache: "no-store"})
    .then(async response => {
      if (!response.ok) return null;
      const data = await response.json();
      return typeof data.message?.enabled === "boolean" ? data.message : null;
    })
    .catch(() => null);
})();
