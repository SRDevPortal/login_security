frappe.ui.form.on("Login Security Settings", {
  refresh(frm) {
    frm.set_intro(__("Manage Enable Login Verification on each User. Codes go to that User's verified Mobile No. These settings control the shared sender, limits and site activation."));
    frm.add_custom_button(__("Open Users"), () => frappe.set_route("List", "User"));
    if (frappe.session.user === "Administrator" || frappe.user_roles.includes("System Manager")) {
      frm.add_custom_button(__("Detect Current Address"), () => {
        const origin = window.location.origin;
        if (window.location.protocol !== "https:") {
          return frappe.msgprint(__("Open these settings at the public HTTPS address before detecting it."));
        }
        frappe.confirm(
          __("Use {0} as the Public Login URL? Review the field and Save to apply it.",
            [frappe.utils.escape_html(origin)]),
          () => frm.set_value("public_login_url", origin)
        );
      });
    }
    if (frm.doc.coverage_version >= 2) return;
    frm.add_custom_button(__("Review Coverage Migration"), async () => {
      if (frm.is_dirty()) return frappe.msgprint(__("Save settings before reviewing migration."));
      const { message: report } = await frappe.call({ method: "login_security.coverage_migration.review", type: "GET" });
      const dialog = new frappe.ui.Dialog({ title: __("Review existing coverage"), fields: [
        { fieldname: "summary", fieldtype: "Small Text", read_only: 1,
          default: report.users.map(row => `${row.user}: ${row.destination} - ${row.ready ? "Ready" : "Verify saved Mobile No. first"}`).join("\n") || __("No selected staff users.") },
        { fieldname: "password", fieldtype: "Password", label: __("Your administrator password"), reqd: 1 },
      ], primary_action_label: __("Apply User coverage"), async primary_action(values) {
        dialog.get_primary_btn().prop("disabled", true);
        try {
          const response = await fetch("/api/method/login_security.coverage_migration.apply", {
            method: "POST", credentials: "same-origin",
            headers: { "Content-Type": "application/json", "X-Login-Security": "1", "X-Frappe-CSRF-Token": frappe.csrf_token },
            body: JSON.stringify({ review_token: report.review_token, password: values.password }),
          });
          const result = (await response.json()).message;
          if (!response.ok || result?.status !== "complete") throw new Error(result?.message || __("Migration failed."));
          dialog.set_value("password", "");
          dialog.hide();
          await frm.reload_doc();
        } catch (error) { frappe.msgprint(error.message); }
        finally { dialog.get_primary_btn().prop("disabled", false); }
      } });
      dialog.show();
    });
  },
});
