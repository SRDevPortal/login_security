def execute():
    from login_security.install import after_migrate

    after_migrate()
