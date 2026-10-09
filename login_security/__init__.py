"""Channel-independent staff login verification."""

__version__ = "0.1.0"

# Imported by app discovery or the capability endpoint before browser login.
from login_security.native_login import install as _install_native_login
_install_native_login()
