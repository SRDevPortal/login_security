import os
import tempfile
import unittest
from unittest.mock import patch

from frappe.installer import parse_app_name
from frappe.modules.patch_handler import PatchType, get_patches_from_app

from login_security import hooks


class RequiredAppsTests(unittest.TestCase):
    def test_whatsapp_dependency_resolves_locally_without_github(self):
        dependency = hooks.required_apps[1]
        original_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                with patch("frappe.installer.find_org", side_effect=AssertionError("Unexpected GitHub lookup")):
                    self.assertEqual(parse_app_name(dependency), "wa_chat_hub")
            finally:
                os.chdir(original_cwd)

    def test_patch_sections_are_compatible_with_v15_installer(self):
        self.assertEqual(get_patches_from_app("login_security", PatchType.pre_model_sync), [])
        self.assertEqual(
            get_patches_from_app("login_security"),
            ["login_security.patches.v0_2.migrate_user_verification"],
        )
