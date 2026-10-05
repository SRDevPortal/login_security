/* User extensions owned by login_security. */
frappe.ui.form.on("User", {
  login_security_enabled(frm) {
    login_security_mobile_required(frm);
  },
  async refresh(frm) {
    login_security_mobile_required(frm);
    frm.set_df_property("login_security_enabled", "description",
      "");
    frm.remove_custom_button(__("Verify Mobile No."), __("Login Security"));
    frm.remove_custom_button(__("Change Verified Number"), __("Login Security"));
    if (frm.is_new() || !frm.fields_dict.login_security_status) return;
    const user = frm.doc.name;
    const { message: state } = await frappe.call({
      method: "login_security.user_policy.status", args: { user }, type: "GET",
    });
    if (!state || frm.doc.name !== user) return;
    login_security_render_status(frm, state);
    frm.set_df_property("login_security_enabled", "read_only",
      !state.can_manage || !state.supported || state.coverage_version < 2);
    frm.set_df_property("mobile_no", "read_only", state.enrolled || !!frm.doc.login_security_enabled);
    if (!state.can_manage || !state.supported) return;
    if (!state.verified) {
      frm.add_custom_button(__("Verify Mobile No."), () => login_security_enroll(frm, false, state), __("Login Security"));
    }
    frm.add_custom_button(__("Change Verified Number"), () => login_security_enroll(frm, true, state), __("Login Security"));
  },
});

function login_security_render_status(frm, state) {
  if (!document.getElementById("login-security-user-styles")) {
    const style = document.createElement("style");
    style.id = "login-security-user-styles";
    style.textContent = `
      .login-security-user-row {display:flex;align-items:center;flex-wrap:wrap;gap:8px;
        margin:6px 0;font-size:12px;color:var(--text-muted,#67766e);}
      .login-security-user-badge {padding:3px 8px;border-radius:6px;font-weight:600;
        background:var(--subtle-fg,#f2f4f5);color:var(--text-color,#48534e);}
      .login-security-user-badge.is-verified {background:var(--green-100,#e4f5eb);color:var(--green-800,#17633c);}
      .login-security-user-warning {font-size:12px;color:var(--text-muted,#67766e);margin:5px 0;}
      .frappe-control[data-fieldname="login_security_enabled"] .tooltip-content {display:none;}
    `;
    document.head.appendChild(style);
  }
  const row = document.createElement("div");
  row.className = "login-security-user-row";
  const badge = document.createElement("span");
  badge.className = `login-security-user-badge${state.verified ? " is-verified" : ""}`;
  badge.textContent = __(state.verified ? "Verified" : "Not verified");
  row.appendChild(badge);
  if (state.verified && state.destination) {
    const number = document.createElement("span");
    number.textContent = state.destination;
    row.appendChild(number);
  }
  const wrapper = frm.fields_dict.login_security_status.$wrapper.empty();
  if (state.supported && state.coverage_version >= 2) wrapper.append(row);
  // Keep actionable exceptions visible without repeating the normal enabled state.
  const warning = !state.supported || state.coverage_version < 2 ? state.label :
    state.site_active === false ? __("Site verification is inactive.") : "";
  if (warning) {
    const notice = document.createElement("p");
    notice.className = "login-security-user-warning";
    notice.textContent = warning;
    wrapper.append(notice);
  }
}
function login_security_mobile_required(frm) {
  // Preserve any existing mandatory setting supplied by the site's User metadata.
  if (frm._login_security_mobile_required === undefined) {
    frm._login_security_mobile_required = !!frm.fields_dict.mobile_no?.df.reqd;
  }
  frm.set_df_property("mobile_no", "reqd",
    frm._login_security_mobile_required || !!Number(frm.doc.login_security_enabled));
}

async function login_security_post(method, args) {
  const response = await fetch(`/api/method/login_security.${method}`, {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-Login-Security": "1",
      "X-Frappe-CSRF-Token": frappe.csrf_token },
    body: JSON.stringify(args),
  });
  const result = (await response.json()).message;
  if (!response.ok || !result || result.status === "error") {
    throw new Error(result?.message || __("Verification could not be completed."));
  }
  return result;
}

function login_security_enroll(frm, changing, state) {
  if (frm.is_dirty()) return frappe.msgprint(__("Save the User before verifying their number."));
  const fields = [{ fieldname: "password", label: __("Your administrator password"), fieldtype: "Password", reqd: 1 }];
  if (changing) fields.unshift({ fieldname: "new_phone", label: __("New Mobile No. with country code"), fieldtype: "Data", reqd: 1 });
  else fields.unshift({ fieldname: "destination", label: __("Saved Mobile No."), fieldtype: "Data", read_only: 1, default: state?.destination || __("Saved mobile number") });
  const dialog = new frappe.ui.Dialog({ title: __(changing ? "Change Verified Number" : "Verify Mobile No."), fields,
    primary_action_label: __("Send verification code"),
    async primary_action(values) {
      dialog.get_primary_btn().prop("disabled", true);
      try {
        const args = { user: frm.doc.name, password: values.password };
        if (changing) args.new_phone = values.new_phone;
        const challenge = await login_security_post(`enrollment.${changing ? "begin_change" : "begin"}`, args);
        dialog.set_value("password", "");
        dialog.hide();
        if (challenge.delivery === "rejected") return frappe.msgprint(__("Delivery was rejected. Check sender settings and start again."));
        const verify = new frappe.ui.Dialog({ title: __("Enter the code received on WhatsApp"),
          fields: [{ fieldname: "code", label: __("Verification code"), fieldtype: "Data", reqd: 1 }],
          primary_action_label: __("Verify number"),
          async primary_action(input) {
            verify.get_primary_btn().prop("disabled", true);
            try {
              const result = await login_security_post("enrollment.complete", { challenge_id: challenge.challenge_id, code: input.code });
              verify.set_value("code", "");
              verify.hide();
              const recovery = new frappe.ui.Dialog({ title: __("Save recovery codes securely"), fields: [
                { fieldname: "codes", fieldtype: "Small Text", read_only: 1, default: result.recovery_codes.join("\n"),
                  description: __("Shown once. Each code works once after the user's password. Previous codes are replaced.") },
              ] });
              recovery.show();
              await frm.reload_doc();
              frappe.show_alert({ message: __("Number verified. Set Enable Login Verification on this User when ready."), indicator: "green" });
            } catch (error) { frappe.msgprint(error.message); }
            finally { verify.get_primary_btn().prop("disabled", false); }
          },
        });
        verify.show();
      } catch (error) { frappe.msgprint(error.message); }
      finally { dialog.get_primary_btn().prop("disabled", false); }
    },
  });
  dialog.show();
}
