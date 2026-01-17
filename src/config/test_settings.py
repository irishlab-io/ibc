"""Test-specific Django settings configuration."""

import tempfile
from pathlib import Path

from config.settings import *

# Override settings for testing
DEBUG = False

# Use in-memory SQLite for faster tests
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
        "OPTIONS": {
            "timeout": 20,
        },
    }
}

# Disable migrations for faster test database creation
# class DisableMigrations:
#     def __contains__(self, item):
#         return True
#
#     def __getitem__(self, item):
#         return None
#
# MIGRATION_MODULES = DisableMigrations()

# Faster password hashing for tests
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

# Disable logging during tests
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "null": {
            "class": "logging.NullHandler",
        },
    },
    "root": {
        "handlers": ["null"],
        "level": "CRITICAL",
    },
}

# Cache configuration for tests
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

# Email backend for tests
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"

# Media files for tests - use secure temporary directory
MEDIA_ROOT = Path(tempfile.gettempdir()) / "ibc_test_media"

# Static files for tests - use secure temporary directory
STATIC_ROOT = Path(tempfile.gettempdir()) / "ibc_test_static"

# Security settings for tests (keep vulnerabilities for testing)
# Note: These maintain the intentional vulnerabilities for educational testing
SECRET_KEY = "test-secret-key-not-for-production"

# Test-specific middleware (preserve original for vulnerability testing)
TEST_MIDDLEWARE = MIDDLEWARE.copy()

# Session configuration for tests
SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"
