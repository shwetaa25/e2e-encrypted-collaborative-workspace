# tests/conftest.py
# Environment for the whole suite — loaded by pytest BEFORE any test module
# imports the app (Settings is cached on first import).
import os

os.environ.setdefault("REGISTER_MAX_PER_WINDOW", "0")          # many sign-ups from one IP
os.environ.setdefault("ADMIN_EMAILS", "console-admin@example.com")
