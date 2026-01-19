"""Global pytest configuration for Django testing."""

import os
import sys
from pathlib import Path

import django
import pytest

# Pytest configuration

# SECURITY NOTE: PyYAML Security Testing
# Add test_yaml_security.py with these tests to verify CVE-2020-14343 remediation:
#
# def test_unsafe_yaml_payload_rejected():
#     """Verify dangerous YAML payloads are blocked"""
#     import yaml
#     dangerous = '!!python/object/apply:os.system ["echo exploit"]'
#     with pytest.raises(yaml.constructor.ConstructorError):
#         yaml.safe_load(dangerous)
#
# def test_safe_yaml_loading():
#     """Verify safe YAML still works"""
#     import yaml
#     safe = 'name: test\nvalue: 123'
#     data = yaml.safe_load(safe)
#     assert data['name'] == 'test'

from django.conf import settings
from django.test.utils import get_runner

# Add src directory to Python path for importing Django modules
project_root = Path(__file__).parent.parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

# Configure Django settings
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.test_settings")


def pytest_configure(config):
    """Configure Django before running tests."""
    django.setup()


# @pytest.fixture(scope="session")
# def django_db_setup():
#     """Set up Django test database."""
#     settings.DATABASES["default"] = {
#         "ENGINE": "django.db.backends.sqlite3",
#         "NAME": ":memory:",
#     }


@pytest.fixture
def user_data():
    """Sample user data for testing."""
    return {
        "username": "testuser",
        "first_name": "Test",
        "last_name": "User",
        "email": "test@example.com",
        "password": "password123",
    }


@pytest.fixture
def account_data():
    """Sample account data for testing."""
    return {
        "account_number": "1234567890",
        "balance": 1000.00,
        "account_type": "checking",
    }


@pytest.fixture
def transaction_data():
    """Sample transaction data for testing."""
    return {
        "amount": 100.00,
        "description": "Test transaction",
        "transaction_type": "transfer",
    }


@pytest.fixture
def client():
    """Django test client."""
    from django.test import Client
    return Client()


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    """Allow database access for all tests."""
    pass


@pytest.fixture
def sample_account(db):
    """Create a sample Account model instance."""
    from web.models import Account

    account = Account.objects.create(
        username="testuser",
        name="Test",
        surname="User",
        password="testpass123"
    )

    return account


@pytest.fixture
def sample_cash_account(db, sample_account):
    """Create a sample CashAccount model instance."""
    from web.models import CashAccount

    cash_account = CashAccount.objects.create(
        number="1234567890",
        username=sample_account.username,
        description="Test Cash Account",
        availableBalance=1000.00
    )

    return cash_account


@pytest.fixture
def sample_credit_account(db, sample_cash_account):
    """Create a sample CreditAccount model instance."""
    from web.models import CreditAccount

    credit_account = CreditAccount.objects.create(
        cashAccountId=1,
        number="0987654321",
        username=sample_cash_account.username,
        description="Test Credit Account",
        availableBalance=5000.00
    )

    return credit_account


@pytest.fixture
def sample_transfer(db, sample_account):
    """Create a sample Transfer model instance."""
    from web.models import Transfer
    from datetime import datetime

    transfer = Transfer.objects.create(
        fromAccount="1234567890",
        toAccount="0987654321",
        description="Test Transfer",
        amount=100.00,
        fee=20.00,
        username=sample_account.username,
        date=datetime.now()
    )

    return transfer


@pytest.fixture
def sample_transaction(db):
    """Create a sample Transaction model instance."""
    from web.models import Transaction
    from datetime import datetime

    transaction = Transaction.objects.create(
        number="TXN123456",
        description="Test Transaction",
        amount=100.00,
        availableBalance=900.00,
        date=datetime.now()
    )

    return transaction


@pytest.fixture
def authenticated_user(db):
    """Create an authenticated user for testing."""
    from web.models import Account

    account = Account.objects.create(
        username="authuser",
        name="Auth",
        surname="User",
        password="authpass123"
    )

    return account


@pytest.fixture
def authenticated_client(client, authenticated_user):
    """Django test client with authenticated user."""
    # For this vulnerable app, we'll simulate authentication
    # by setting session data (since it doesn't use Django's built-in auth)
    session = client.session
    session['username'] = authenticated_user.username
    session.save()

    return client


@pytest.fixture
def db_with_data(db):
    """Database with sample test data using real models."""
    from web.models import Account, CashAccount, CreditAccount, Transfer, Transaction
    from datetime import datetime

    # Create test account
    account = Account.objects.create(
        username="testuser",
        name="Test",
        surname="User",
        password="testpass123"
    )

    # Create cash account
    cash_account = CashAccount.objects.create(
        number="1234567890",
        username=account.username,
        description="Test Cash Account",
        availableBalance=1000.00
    )

    # Create credit account
    credit_account = CreditAccount.objects.create(
        cashAccountId=1,
        number="0987654321",
        username=account.username,
        description="Test Credit Account",
        availableBalance=5000.00
    )

    # Create transfer
    transfer = Transfer.objects.create(
        fromAccount=cash_account.number,
        toAccount=credit_account.number,
        description="Test Transfer",
        amount=100.00,
        fee=20.00,
        username=account.username,
        date=datetime.now()
    )

    # Create transaction
    transaction = Transaction.objects.create(
        number="TXN123456",
        description="Test Transaction",
        amount=100.00,
        availableBalance=900.00,
        date=datetime.now()
    )

    return {
        "account": account,
        "cash_account": cash_account,
        "credit_account": credit_account,
        "transfer": transfer,
        "transaction": transaction
    }


@pytest.fixture
def account_factory():
    """Factory for creating Account instances."""
    def _create_account(**kwargs):
        from web.models import Account
        defaults = {
            'username': f"user_{generate_random_string(8)}",
            'name': "Test",
            'surname': "User",
            'password': "testpass123"
        }
        defaults.update(kwargs)
        return Account.objects.create(**defaults)
    return _create_account


@pytest.fixture
def cash_account_factory():
    """Factory for creating CashAccount instances."""
    def _create_cash_account(**kwargs):
        from web.models import CashAccount
        defaults = {
            'number': generate_account_number(),
            'username': f"user_{generate_random_string(8)}",
            'description': "Test Cash Account",
            'availableBalance': 1000.00
        }
        defaults.update(kwargs)
        return CashAccount.objects.create(**defaults)
    return _create_cash_account


@pytest.fixture
def credit_account_factory():
    """Factory for creating CreditAccount instances."""
    def _create_credit_account(**kwargs):
        from web.models import CreditAccount
        defaults = {
            'cashAccountId': 1,
            'number': generate_account_number(),
            'username': f"user_{generate_random_string(8)}",
            'description': "Test Credit Account",
            'availableBalance': 5000.00
        }
        defaults.update(kwargs)
        return CreditAccount.objects.create(**defaults)
    return _create_credit_account


@pytest.fixture
def transfer_factory():
    """Factory for creating Transfer instances."""
    def _create_transfer(**kwargs):
        from web.models import Transfer
        from datetime import datetime
        defaults = {
            'fromAccount': generate_account_number(),
            'toAccount': generate_account_number(),
            'description': "Test Transfer",
            'amount': 100.00,
            'fee': 20.00,
            'username': f"user_{generate_random_string(8)}",
            'date': datetime.now()
        }
        defaults.update(kwargs)
        return Transfer.objects.create(**defaults)
    return _create_transfer


@pytest.fixture
def transaction_factory():
    """Factory for creating Transaction instances."""
    def _create_transaction(**kwargs):
        from web.models import Transaction
        from datetime import datetime
        defaults = {
            'number': f"TXN{generate_random_string(6)}",
            'description': "Test Transaction",
            'amount': 100.00,
            'availableBalance': 900.00,
            'date': datetime.now()
        }
        defaults.update(kwargs)
        return Transaction.objects.create(**defaults)
    return _create_transaction


def generate_random_string(length: int = 10) -> str:
    """Generate a random string of specified length."""
    import random
    import string
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def generate_account_number() -> str:
    """Generate a valid-looking account number."""
    import random
    import string
    return ''.join(random.choices(string.digits, k=10))


@pytest.fixture
def mock_transfer_service():
    """Mock transfer service for testing."""
    from unittest.mock import Mock
    service = Mock()
    service.process_transfer.return_value = {"success": True, "transaction_id": "TXN123456"}
    service.validate_transfer.return_value = True
    service.calculate_fee.return_value = 20.00
    service.check_balance.return_value = True
    return service


@pytest.fixture
def mock_account_service():
    """Mock account service for testing."""
    from unittest.mock import Mock
    service = Mock()
    service.authenticate_user.return_value = True
    service.get_account_balance.return_value = 1000.00
    service.create_account.return_value = {"success": True, "account_number": "1234567890"}
    service.update_balance.return_value = True
    return service


@pytest.fixture
def mock_transaction_service():
    """Mock transaction service for testing."""
    from unittest.mock import Mock
    service = Mock()
    service.record_transaction.return_value = {"success": True, "id": 1}
    service.get_transaction_history.return_value = []
    service.validate_transaction.return_value = True
    return service


@pytest.fixture
def mock_security_service():
    """Mock security service for testing vulnerabilities."""
    from unittest.mock import Mock
    service = Mock()
    service.validate_input.return_value = True  # Intentionally vulnerable
    service.sanitize_sql.side_effect = lambda x: x  # No sanitization
    service.escape_html.side_effect = lambda x: x  # No escaping
    service.check_csrf_token.return_value = True  # Always passes
    return service


@pytest.fixture
def mock_database_connection():
    """Mock database connection for testing."""
    from unittest.mock import Mock
    connection = Mock()
    connection.execute.return_value = Mock()
    connection.fetchall.return_value = []
    connection.fetchone.return_value = None
    connection.commit.return_value = None
    connection.rollback.return_value = None
    return connection
