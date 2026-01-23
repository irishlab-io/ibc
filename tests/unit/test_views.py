"""
Unit tests for Django view classes.

This module provides comprehensive unit test coverage for all view classes in the
Insecure Bank application, testing authentication flows, HTTP handling, and
template rendering.

Test Categories:
- Authentication Views (LoginView, LogoutView)
- Admin and Activity Views (AdminView, ActivityView, ActivityCreditView)
- Dashboard and User Views (DashboardView, UserDetailView)
- Transfer Views (TransferView)
- File and Avatar Views (AvatarView, AvatarUpdateView)
- Certificate Views (CertificateDownloadView, SecureCertificateDownloadView, NewCertificateView)
- Image Views (CreditCardImageView)

Security Improvements:
- Certificate serialization now uses JSON instead of pickle
- Encryption now uses AES-256-GCM instead of DES
- Encryption keys are loaded from environment variables
"""

import json
import os
import tempfile
from datetime import date
from unittest.mock import Mock, patch, MagicMock

import pytest
from django.contrib.auth.models import AnonymousUser, User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.http import HttpRequest, HttpResponse
from django.test import TestCase, RequestFactory
from django.test.client import Client
from django.template import Context, Template

from web.models import Account, CashAccount, CreditAccount, Transfer
from web.views import (
    LoginView, LogoutView, AdminView, ActivityView, ActivityCreditView,
    DashboardView, UserDetailView, AvatarView, AvatarUpdateView,
    CertificateDownloadView, SecureCertificateDownloadView, NewCertificateView,
    CreditCardImageView, TransferView, TransferForm, Trusted,
    get_file_checksum, to_traces
)


class ViewTestMixin:
    """Common test utilities for view testing."""

    def setUp(self):
        """Set up common test data for view tests."""
        self.factory = RequestFactory()
        self.client = Client()

        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            email='test@example.com'
        )

        # Create test account
        self.account = Account.objects.create(
            username='testuser',
            name='Test',
            surname='User',
            password='testpass123'
        )

        # Create test cash account
        self.cash_account = CashAccount.objects.create(
            number='1234567890',
            username='testuser',
            description='Test Cash Account',
            availableBalance=1000.00
        )

        # Create test credit account
        self.credit_account = CreditAccount.objects.create(
            cashAccountId=self.cash_account.id,
            number='9876543210',
            username='testuser',
            description='Test Credit Account',
            availableBalance=1500.00
        )

    def create_authenticated_request(self, method='GET', path='/', data=None, user=None):
        """Create an authenticated request for testing."""
        if user is None:
            user = self.user

        if method.upper() == 'GET':
            request = self.factory.get(path, data or {})
        elif method.upper() == 'POST':
            request = self.factory.post(path, data or {})
        else:
            request = getattr(self.factory, method.lower())(path, data or {})

        request.user = user
        request.session = {}
        return request

    def create_anonymous_request(self, method='GET', path='/', data=None):
        """Create an anonymous request for testing."""
        if method.upper() == 'GET':
            request = self.factory.get(path, data or {})
        elif method.upper() == 'POST':
            request = self.factory.post(path, data or {})
        else:
            request = getattr(self.factory, method.lower())(path, data or {})

        request.user = AnonymousUser()
        request.session = {}
        return request


@pytest.mark.unit
class TestLoginView(ViewTestMixin, TestCase):
    """Unit tests for LoginView."""

    def test_login_view_get_request(self):
        """Test LoginView GET request renders login template."""
        request = self.create_anonymous_request('GET', '/login')
        view = LoginView()
        view.request = request

        response = view.get(request)
        if hasattr(response, 'render'):
            response.render()

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Log in to your account', response.content)

    def test_login_view_template_name(self):
        """Test LoginView uses correct template."""
        view = LoginView()
        self.assertEqual(view.template_name, 'login.html')

    def test_login_view_allowed_methods(self):
        """Test LoginView allows only GET and POST methods."""
        view = LoginView()
        self.assertEqual(view.http_method_names, ['get', 'post'])

    @patch('web.views.authenticate')
    @patch('web.views.login')
    def test_login_view_post_success(self, mock_login, mock_authenticate):
        """Test LoginView POST with valid credentials redirects to dashboard."""
        # Mock successful authentication
        mock_user = Mock()
        mock_authenticate.return_value = mock_user

        request = self.create_anonymous_request('POST', '/login', {
            'username': 'testuser',
            'password': 'testpass123'
        })

        view = LoginView()
        view.request = request

        response = view.post(request)

        # Should redirect to dashboard
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/dashboard')
        mock_authenticate.assert_called_once_with(request=request)
        mock_login.assert_called_once_with(request, mock_user)

    @patch('web.views.authenticate')
    @patch('web.views.loader')
    def test_login_view_post_failure(self, mock_loader, mock_authenticate):
        """Test LoginView POST with invalid credentials shows error."""
        # Mock failed authentication
        mock_authenticate.return_value = None

        # Mock template loader
        mock_template = Mock()
        mock_template.render.return_value = 'login template with error'
        mock_loader.get_template.return_value = mock_template

        request = self.create_anonymous_request('POST', '/login', {
            'username': 'testuser',
            'password': 'wrongpass'
        })

        view = LoginView()
        view.request = request

        response = view.post(request)

        # Should render login template with error
        self.assertEqual(response.status_code, 200)
        mock_authenticate.assert_called_once_with(request=request)
        mock_loader.get_template.assert_called_once_with('login.html')

        # Check error context
        expected_context = {'authenticationFailure': True}
        mock_template.render.assert_called_once_with(expected_context, request)

    @patch('web.views.authenticate')
    def test_login_view_authentication_bypass_vulnerability(self, mock_authenticate):
        """Test that authentication bypass vulnerability is preserved."""
        # The authenticate function doesn't validate credentials properly
        # This test ensures the vulnerability is preserved
        mock_authenticate.return_value = None

        request = self.create_anonymous_request('POST', '/login', {
            'username': 'admin\' OR \'1\'=\'1',  # SQL injection attempt
            'password': 'anything'
        })

        view = LoginView()
        view.request = request

        response = view.post(request)

        # The vulnerable code should call authenticate with the malicious input
        mock_authenticate.assert_called_once_with(request=request)
        # Authentication should fail (preserving expected behavior)
        self.assertEqual(response.status_code, 200)


@pytest.mark.unit
class TestLogoutView(ViewTestMixin, TestCase):
    """Unit tests for LogoutView."""

    def test_logout_view_allowed_methods(self):
        """Test LogoutView allows only GET method."""
        view = LogoutView()
        self.assertEqual(view.http_method_names, ['get'])

    @patch('web.views.logout')
    def test_logout_view_get_request(self, mock_logout):
        """Test LogoutView GET request logs out user and redirects."""
        request = self.create_authenticated_request('GET', '/logout')

        view = LogoutView()
        response = view.get(request)

        # Should call logout and redirect
        mock_logout.assert_called_once_with(request)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/login')

    @patch('web.views.logout')
    def test_logout_view_session_cleanup(self, mock_logout):
        """Test LogoutView properly handles session cleanup."""
        request = self.create_authenticated_request('GET', '/logout')
        request.session['test_data'] = 'should_be_cleaned'

        view = LogoutView()
        response = view.get(request)

        # Logout should be called (Django handles session cleanup)
        mock_logout.assert_called_once_with(request)
        self.assertEqual(response.status_code, 302)


@pytest.mark.unit
class TestAdminView(ViewTestMixin, TestCase):
    """Unit tests for AdminView."""

    def test_admin_view_template_name(self):
        """Test AdminView uses correct template."""
        view = AdminView()
        self.assertEqual(view.template_name, 'admin.html')

    def test_admin_view_allowed_methods(self):
        """Test AdminView allows only GET method."""
        view = AdminView()
        self.assertEqual(view.http_method_names, ['get'])

    @patch('web.views.AccountService.find_users_by_username')
    @patch('web.views.AccountService.find_all_users')
    def test_admin_view_context_data(self, mock_find_all, mock_find_by_username):
        """Test AdminView context data with mocked services."""
        # Mock service responses
        mock_find_by_username.return_value = [self.account]
        mock_find_all.return_value = [self.account]

        request = self.create_authenticated_request('GET', '/admin')

        view = AdminView()
        view.request = request

        context = view.get_context_data()

        # Check context contains expected data
        self.assertEqual(context['account'], self.account)
        self.assertEqual(context['accounts'], [self.account])

        # Verify service calls with SQL injection vulnerability preserved
        mock_find_by_username.assert_called_once_with('testuser')
        mock_find_all.assert_called_once()

    @patch('web.views.AccountService.find_users_by_username')
    @patch('web.views.AccountService.find_all_users')
    def test_admin_view_sql_injection_vulnerability(self, mock_find_all, mock_find_by_username):
        """Test that SQL injection vulnerability in admin view is preserved."""
        # Mock malicious username that would exploit SQL injection
        malicious_user = User.objects.create_user(
            username="admin'; DROP TABLE accounts; --",
            password='testpass'
        )

        mock_find_by_username.return_value = [self.account]
        mock_find_all.return_value = [self.account]

        request = self.create_authenticated_request('GET', '/admin', user=malicious_user)

        view = AdminView()
        view.request = request

        context = view.get_context_data()

        # The vulnerable service should be called with malicious username
        mock_find_by_username.assert_called_once_with("admin'; DROP TABLE accounts; --")

        # Verify context is still populated (preserving app functionality)
        self.assertIn('account', context)
        self.assertIn('accounts', context)


@pytest.mark.unit
class TestActivityView(ViewTestMixin, TestCase):
    """Unit tests for ActivityView."""

    def test_activity_view_template_name(self):
        """Test ActivityView uses correct template."""
        view = ActivityView()
        self.assertEqual(view.template_name, 'accountActivity.html')

    def test_activity_view_allowed_methods(self):
        """Test ActivityView allows GET and POST methods."""
        view = ActivityView()
        self.assertEqual(view.http_method_names, ['get', 'post'])

    @patch('web.views.AccountService.find_users_by_username')
    @patch('web.views.CashAccountService.find_cash_accounts_by_username')
    @patch('web.views.ActivityService.find_transactions_by_cash_account_number')
    def test_activity_view_get_context_default_account(self, mock_find_transactions,
                                                       mock_find_cash, mock_find_users):
        """Test ActivityView context with default account selection."""
        # Mock service responses
        mock_find_users.return_value = [self.account]
        mock_find_cash.return_value = [self.cash_account]
        mock_find_transactions.return_value = []

        request = self.create_authenticated_request('GET', '/activity')
        request.resolver_match = Mock()
        request.resolver_match.kwargs = {}

        view = ActivityView()
        view.request = request

        context = view.get_context_data()

        # Check context structure
        self.assertEqual(context['account'], self.account)
        self.assertEqual(context['cashAccounts'], [self.cash_account])
        self.assertEqual(context['actualCashAccountNumber'], '1234567890')
        self.assertIsInstance(context['cashAccount'], dict)

        # Verify service calls
        mock_find_users.assert_called_once_with('testuser')
        mock_find_cash.assert_called_once_with('testuser')
        mock_find_transactions.assert_called_once_with('1234567890')

    @patch('web.views.AccountService.find_users_by_username')
    @patch('web.views.CashAccountService.find_cash_accounts_by_username')
    @patch('web.views.ActivityService.find_transactions_by_cash_account_number')
    def test_activity_view_post_with_account_number(self, mock_find_transactions,
                                                    mock_find_cash, mock_find_users):
        """Test ActivityView POST request with account number parameter."""
        # Mock service responses
        mock_find_users.return_value = [self.account]
        mock_find_cash.return_value = [self.cash_account]
        mock_find_transactions.return_value = []

        request = self.create_authenticated_request('POST', '/activity', {
            'number': '9876543210'
        })
        request.resolver_match = Mock()
        request.resolver_match.kwargs = {}

        view = ActivityView()
        view.request = request

        response = view.post(request)

        # Should return rendered response
        self.assertEqual(response.status_code, 200)

        # Verify the account number from POST was used
        mock_find_transactions.assert_called_once_with('9876543210')

    def test_activity_view_post_method(self):
        """Test ActivityView POST method delegates to get_context_data."""
        request = self.create_authenticated_request('POST', '/activity')

        view = ActivityView()
        view.request = request

        # Mock get_context_data and render_to_response
        with patch.object(view, 'get_context_data') as mock_context:
            with patch.object(view, 'render_to_response') as mock_render:
                mock_context.return_value = {'test': 'data'}
                mock_render.return_value = HttpResponse('test')

                response = view.post(request)

                mock_context.assert_called_once()
                mock_render.assert_called_once_with({'test': 'data'})
                self.assertEqual(response.status_code, 200)


@pytest.mark.unit
class TestActivityCreditView(ViewTestMixin, TestCase):
    """Unit tests for ActivityCreditView."""

    def test_activity_credit_view_template_name(self):
        """Test ActivityCreditView uses correct template."""
        view = ActivityCreditView()
        self.assertEqual(view.template_name, 'creditActivity.html')

    def test_activity_credit_view_allowed_methods(self):
        """Test ActivityCreditView allows only GET method."""
        view = ActivityCreditView()
        self.assertEqual(view.http_method_names, ['get'])

    @patch('web.views.AccountService.find_users_by_username')
    def test_activity_credit_view_context_data(self, mock_find_users):
        """Test ActivityCreditView context data."""
        mock_find_users.return_value = [self.account]

        request = self.create_authenticated_request('GET', '/credit-activity?number=1234567890')
        request.GET = {'number': '1234567890'}

        view = ActivityCreditView()
        view.request = request

        context = view.get_context_data()

        self.assertEqual(context['account'], self.account)
        self.assertEqual(context['actualCreditCardNumber'], '1234567890')
        mock_find_users.assert_called_once_with('testuser')


@pytest.mark.unit
class TestDashboardView(ViewTestMixin, TestCase):
    """Unit tests for DashboardView."""

    def test_dashboard_view_template_name(self):
        """Test DashboardView uses correct template."""
        view = DashboardView()
        self.assertEqual(view.template_name, 'dashboard.html')

    def test_dashboard_view_allowed_methods(self):
        """Test DashboardView allows only GET method."""
        view = DashboardView()
        self.assertEqual(view.http_method_names, ['get'])

    @patch('web.views.AccountService.find_users_by_username')
    @patch('web.views.CashAccountService.find_cash_accounts_by_username')
    @patch('web.views.CreditAccountService.find_credit_accounts_by_username')
    def test_dashboard_view_context_data(self, mock_find_credit, mock_find_cash, mock_find_users):
        """Test DashboardView context data with all account types."""
        # Mock service responses
        mock_find_users.return_value = [self.account]
        mock_find_cash.return_value = [self.cash_account]
        mock_find_credit.return_value = [self.credit_account]

        request = self.create_authenticated_request('GET', '/dashboard')

        view = DashboardView()
        view.request = request

        context = view.get_context_data()

        # Verify all expected context data
        self.assertEqual(context['account'], self.account)
        self.assertEqual(context['cashAccounts'], [self.cash_account])
        self.assertEqual(context['creditAccounts'], [self.credit_account])

        # Verify service calls
        mock_find_users.assert_called_once_with('testuser')
        mock_find_cash.assert_called_once_with('testuser')
        mock_find_credit.assert_called_once_with('testuser')


@pytest.mark.unit
class TestUserDetailView(ViewTestMixin, TestCase):
    """Unit tests for UserDetailView."""

    def test_user_detail_view_template_name(self):
        """Test UserDetailView uses correct template."""
        view = UserDetailView()
        self.assertEqual(view.template_name, 'userDetail.html')

    def test_user_detail_view_allowed_methods(self):
        """Test UserDetailView allows only GET method."""
        view = UserDetailView()
        self.assertEqual(view.http_method_names, ['get'])

    @patch('web.views.AccountService.find_users_by_username')
    @patch('web.views.CreditAccountService.find_credit_accounts_by_username')
    def test_user_detail_view_context_data(self, mock_find_credit, mock_find_users):
        """Test UserDetailView context data."""
        mock_find_users.return_value = [self.account]
        mock_find_credit.return_value = [self.credit_account]

        request = self.create_authenticated_request('GET', '/user-detail')

        view = UserDetailView()
        view.request = request

        context = view.get_context_data()

        # Check context data
        self.assertEqual(context['account'], self.account)
        self.assertEqual(context['creditAccounts'], [self.credit_account])
        # Note: accountMalicious is set to the same account (potential vulnerability)
        self.assertEqual(context['accountMalicious'], self.account)

        mock_find_users.assert_called_once_with('testuser')
        mock_find_credit.assert_called_once_with('testuser')


@pytest.mark.unit
class TestAvatarView(ViewTestMixin, TestCase):
    """Unit tests for AvatarView."""

    def test_avatar_view_allowed_methods(self):
        """Test AvatarView allows only GET method."""
        view = AvatarView()
        self.assertEqual(view.http_method_names, ['get'])

    @patch('web.views.storage_service')
    def test_avatar_view_existing_image(self, mock_storage):
        """Test AvatarView with existing image file."""
        # Mock storage service
        mock_storage.exists.return_value = True
        mock_storage.load.return_value = b'fake_image_data'

        request = self.create_authenticated_request('GET', '/avatar?image=test.png')
        request.GET = {'image': 'test.png'}

        view = AvatarView()
        response = view.get(request)

        # Verify response
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'fake_image_data')
        self.assertEqual(response['Content-Type'], 'image/png')

        mock_storage.exists.assert_called_once_with('test.png')
        mock_storage.load.assert_called_once_with('test.png')

    @patch('web.views.storage_service')
    def test_avatar_view_nonexistent_image(self, mock_storage):
        """Test AvatarView with nonexistent image falls back to default."""
        # Mock storage service
        mock_storage.exists.return_value = False
        mock_storage.load.return_value = b'default_avatar_data'

        request = self.create_authenticated_request('GET', '/avatar?image=nonexistent.png')
        request.GET = {'image': 'nonexistent.png'}

        view = AvatarView()
        response = view.get(request)

        # Should fall back to default avatar
        self.assertEqual(response.status_code, 200)
        mock_storage.exists.assert_called_once_with('nonexistent.png')
        mock_storage.load.assert_called_once_with('avatar.png')

    @patch('web.views.storage_service')
    def test_avatar_view_path_traversal_vulnerability(self, mock_storage):
        """Test that path traversal vulnerability is preserved."""
        # Mock storage service
        mock_storage.exists.return_value = True
        mock_storage.load.return_value = b'sensitive_file_data'

        # Malicious path traversal attempt
        malicious_path = '../../../etc/passwd'
        request = self.create_authenticated_request('GET', f'/avatar?image={malicious_path}')
        request.GET = {'image': malicious_path}

        view = AvatarView()
        response = view.get(request)

        # The vulnerable code should pass the malicious path directly
        mock_storage.exists.assert_called_once_with(malicious_path)
        mock_storage.load.assert_called_once_with(malicious_path)


@pytest.mark.unit
class TestAvatarUpdateView(ViewTestMixin, TestCase):
    """Unit tests for AvatarUpdateView."""

    def test_avatar_update_view_allowed_methods(self):
        """Test AvatarUpdateView allows only POST method."""
        view = AvatarUpdateView()
        self.assertEqual(view.http_method_names, ['post'])

    @patch('web.views.storage_service')
    def test_avatar_update_view_file_upload(self, mock_storage):
        """Test AvatarUpdateView file upload functionality."""
        # Create mock uploaded file
        mock_file = SimpleUploadedFile("testuser.png", b'image_data')

        request = self.create_authenticated_request('POST', '/avatar-update', {'imageFile': mock_file})

        view = AvatarUpdateView()
        view.request = request

        response = view.post(request)

        # Should redirect to user detail page
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/dashboard/userDetail?username=testuser')

        # Verify file was saved with username
        mock_storage.save.assert_called_once_with(b'image_data', 'testuser.png')


@pytest.mark.unit
class TestCertificateViews(ViewTestMixin, TestCase):
    """Unit tests for certificate-related views."""

    def test_certificate_download_view_allowed_methods(self):
        """Test CertificateDownloadView allows only POST method."""
        from web.views import CertificateDownloadView
        view = CertificateDownloadView()
        self.assertEqual(view.http_method_names, ['post'])

    @patch('web.views.AccountService.find_users_by_username')
    def test_certificate_download_view(self, mock_find_users):
        """Test CertificateDownloadView generates safe certificate using JSON."""
        mock_find_users.return_value = [self.account]

        request = self.create_authenticated_request('POST', '/certificate-download')

        from web.views import CertificateDownloadView
        view = CertificateDownloadView()
        view.request = request

        response = view.post(request)

        # Verify response
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        self.assertIn('attachment;Certificate_=Test', response['Content-Disposition'])

        # Verify JSON content with Trusted data
        data = json.loads(response.content.decode('utf-8'))
        self.assertEqual(data['username'], 'this is safe')
        self.assertEqual(data['type'], 'trusted')

    def test_secure_certificate_download_view_allowed_methods(self):
        """Test SecureCertificateDownloadView allows only POST method."""
        from web.views import SecureCertificateDownloadView
        view = SecureCertificateDownloadView()
        self.assertEqual(view.http_method_names, ['post'])

    @patch('web.views.AccountService.find_users_by_username')
    @patch('web.views.get_file_checksum')
    def test_secure_certificate_download_view(self, mock_checksum, mock_find_users):
        """Test SecureCertificateDownloadView generates secure certificate."""
        mock_find_users.return_value = [self.account]
        mock_checksum.return_value = 'secure_checksum'

        request = self.create_authenticated_request('POST', '/secure-certificate-download')

        from web.views import SecureCertificateDownloadView, checksum
        view = SecureCertificateDownloadView()
        view.request = request

        response = view.post(request)

        # Verify response
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        self.assertIn('attachment;SecureCertificate_=Test', response['Content-Disposition'])

        # Verify JSON content with Trusted data
        data = json.loads(response.content.decode('utf-8'))
        self.assertEqual(data['username'], 'this is safe')
        self.assertEqual(data['type'], 'trusted')

        # Verify checksum was stored
        self.assertEqual(checksum[0], 'secure_checksum')

    def test_new_certificate_view_allowed_methods(self):
        """Test NewCertificateView allows only POST method."""
        from web.views import NewCertificateView
        view = NewCertificateView()
        self.assertEqual(view.http_method_names, ['post'])

    def test_new_certificate_view_no_file(self):
        """Test NewCertificateView with no file uploaded."""
        request = self.create_authenticated_request('POST', '/new-certificate')
        # request.FILES is empty by default

        from web.views import NewCertificateView
        view = NewCertificateView()

        response = view.post(request)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, b'<p>No file uploaded</p>')

    def test_new_certificate_view_valid_json(self):
        """Test NewCertificateView with valid JSON certificate."""
        valid_cert = json.dumps({"username": "testuser", "type": "trusted"}).encode('utf-8')
        mock_file = SimpleUploadedFile("certificate.json", valid_cert)

        request = self.create_authenticated_request('POST', '/new-certificate', {'file': mock_file})

        from web.views import NewCertificateView
        view = NewCertificateView()

        response = view.post(request)

        # Should process successfully using JSON deserialization
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'uploaded successfully', response.content)
        self.assertIn(b'testuser', response.content)

    def test_new_certificate_view_invalid_json(self):
        """Test NewCertificateView with invalid JSON format."""
        invalid_data = b'not valid json'
        mock_file = SimpleUploadedFile("invalid.json", invalid_data)

        request = self.create_authenticated_request('POST', '/new-certificate', {'file': mock_file})

        from web.views import NewCertificateView
        view = NewCertificateView()

        response = view.post(request)

        self.assertEqual(response.status_code, 400)
        self.assertIn(b'Invalid file format', response.content)

    def test_new_certificate_view_missing_username(self):
        """Test NewCertificateView with JSON missing username field."""
        invalid_cert = json.dumps({"type": "trusted"}).encode('utf-8')  # No username
        mock_file = SimpleUploadedFile("certificate.json", invalid_cert)

        request = self.create_authenticated_request('POST', '/new-certificate', {'file': mock_file})

        from web.views import NewCertificateView
        view = NewCertificateView()

        response = view.post(request)

        self.assertEqual(response.status_code, 400)
        self.assertIn(b'missing username', response.content)


@pytest.mark.unit
class TestCreditCardImageView(ViewTestMixin, TestCase):
    """Unit tests for CreditCardImageView."""

    def test_credit_card_image_view_allowed_methods(self):
        """Test CreditCardImageView allows only GET method."""
        view = CreditCardImageView()
        self.assertEqual(view.http_method_names, ['get'])

    @patch('builtins.open')
    @patch('os.path.join')
    def test_credit_card_image_view_file_access(self, mock_join, mock_open):
        """Test CreditCardImageView file access (potential directory traversal)."""
        mock_join.return_value = '/path/to/resources/card.png'
        mock_file = Mock()
        mock_file.read.return_value = b'image_data'
        mock_open.return_value.__enter__.return_value = mock_file

        request = self.create_authenticated_request('GET', '/credit-card-image?url=card.png')
        request.GET = {'url': 'card.png'}

        view = CreditCardImageView()
        response = view.get(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'image_data')
        self.assertEqual(response['Content-Type'], 'image/png')
        self.assertIn('attachment; filename="card.png"', response['Content-Disposition'])

    @patch('builtins.open')
    @patch('os.path.join')
    def test_credit_card_image_view_directory_traversal_vulnerability(self, mock_join, mock_open):
        """Test that directory traversal vulnerability is preserved."""
        # Malicious path traversal attempt
        malicious_url = '../../../etc/passwd'

        mock_join.return_value = '/path/to/resources/../../../etc/passwd'
        mock_file = Mock()
        mock_file.read.return_value = b'sensitive_data'
        mock_open.return_value.__enter__.return_value = mock_file

        request = self.create_authenticated_request('GET', f'/credit-card-image?url={malicious_url}')
        request.GET = {'url': malicious_url}

        view = CreditCardImageView()
        response = view.get(request)

        # The vulnerable code should process the malicious path
        mock_join.assert_called_once()
        mock_open.assert_called_once()
        self.assertEqual(response.status_code, 200)


@pytest.mark.unit
class TestTransferView(ViewTestMixin, TestCase):
    """Unit tests for TransferView."""

    def test_transfer_view_template_name(self):
        """Test TransferView uses correct template."""
        view = TransferView()
        self.assertEqual(view.template_name, 'newTransfer.html')

    def test_transfer_view_allowed_methods(self):
        """Test TransferView allows GET and POST methods."""
        view = TransferView()
        self.assertEqual(view.http_method_names, ['get', 'post'])

    @patch('web.views.AccountService.find_users_by_username')
    @patch('web.views.CashAccountService.find_cash_accounts_by_username')
    def test_transfer_view_get_context_data(self, mock_find_cash, mock_find_users):
        """Test TransferView GET context data."""
        mock_find_users.return_value = [self.account]
        mock_find_cash.return_value = [self.cash_account]

        request = self.create_authenticated_request('GET', '/transfer')

        view = TransferView()
        view.request = request

        context = view.get_context_data()

        # Verify context data
        self.assertEqual(context['account'], self.account)
        self.assertEqual(context['cashAccounts'], [self.cash_account])
        self.assertIsInstance(context['transfer'], Transfer)
        self.assertEqual(context['transfer'].fee, 5.0)

    @patch('web.views.AccountService.find_users_by_username')
    @patch('web.views.CashAccountService.find_cash_accounts_by_username')
    def test_transfer_view_get_with_cookie(self, mock_find_cash, mock_find_users):
        """Test TransferView GET sets accountType cookie."""
        mock_find_users.return_value = [self.account]
        mock_find_cash.return_value = [self.cash_account]

        request = self.create_authenticated_request('GET', '/transfer')

        view = TransferView()
        view.request = request

        response = view.get(request)

        # Check cookie is set
        self.assertEqual(response.cookies['accountType'].value, 'Personal')

    @patch('web.views.to_traces')
    @patch('web.views.loader.get_template')
    @patch('web.views.AccountService.find_users_by_username')
    def test_transfer_view_post_personal_account(self, mock_find_users, mock_get_template, mock_to_traces):
        """Test TransferView POST with Personal account type triggers check."""
        mock_find_users.return_value = [self.account]
        mock_template = Mock()
        mock_template.render.return_value = 'rendered_template'
        mock_get_template.return_value = mock_template

        request = self.create_authenticated_request('POST', '/transfer')
        request.COOKIES['accountType'] = 'Personal'
        request.POST = {
            'toAccount': '987654321',
            'amount': '100.00',
            'description': 'Test Transfer'
        }
        request.session = {}

        view = TransferView()
        view.request = request
        response = view.post(request)

        # Verify
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'rendered_template')
        mock_to_traces.assert_called()
        self.assertIn('pendingTransfer', request.session)
        mock_get_template.assert_called_with('transferCheck.html')

    @patch('web.views.TransferService.createNewTransfer')
    @patch('web.views.to_traces')
    @patch('web.views.loader.get_template')
    @patch('web.views.AccountService.find_users_by_username')
    @patch('web.views.CashAccountService.find_cash_accounts_by_username')
    def test_transfer_view_post_other_account(self, mock_find_cash, mock_find_users, mock_get_template, mock_to_traces, mock_create_transfer):
        """Test TransferView POST with non-Personal account type triggers confirmation."""
        mock_find_users.return_value = [self.account]
        mock_find_cash.return_value = [self.cash_account]
        mock_template = Mock()
        mock_template.render.return_value = 'rendered_template'
        mock_get_template.return_value = mock_template

        request = self.create_authenticated_request('POST', '/transfer')
        request.COOKIES['accountType'] = 'Business'
        request.POST = {
            'toAccount': '987654321',
            'amount': '100.00',
            'description': 'Test Transfer'
        }

        view = TransferView()
        view.request = request
        response = view.post(request)

        # Verify
        self.assertEqual(response.status_code, 200)
        mock_create_transfer.assert_called()
        mock_get_template.assert_called_with('transferConfirmation.html')

    @patch('web.views.TransferService.createNewTransfer')
    @patch('web.views.loader.get_template')
    @patch('web.views.AccountService.find_users_by_username')
    @patch('web.views.CashAccountService.find_cash_accounts_by_username')
    def test_transfer_view_post_confirm_action(self, mock_find_cash, mock_find_users, mock_get_template, mock_create_transfer):
        """Test TransferView POST confirm action."""
        mock_find_users.return_value = [self.account]
        mock_find_cash.return_value = [self.cash_account]
        mock_template = Mock()
        mock_template.render.return_value = 'rendered_template'
        mock_get_template.return_value = mock_template

        request = self.create_authenticated_request('POST', '/transfer/confirm')
        request.COOKIES['accountType'] = 'Personal'
        request.POST = {'action': 'confirm'}

        transfer_data = {
            'toAccount': '987654321',
            'amount': 100.00,
            'description': 'Test Transfer',
            'fee': 5.0,
            'fromAccount': '123456789',
            'sender': 'testuser'
        }
        request.session = {'pendingTransfer': json.dumps(transfer_data)}

        view = TransferView()
        view.request = request
        response = view.post(request)

        # Verify
        self.assertEqual(response.status_code, 200)
        mock_create_transfer.assert_called()
        self.assertNotIn('pendingTransfer', request.session)

    @patch('web.views.loader.get_template')
    @patch('web.views.AccountService.find_users_by_username')
    @patch('web.views.CashAccountService.find_cash_accounts_by_username')
    def test_transfer_confirmation_zero_amount(self, mock_find_cash, mock_find_users, mock_get_template):
        """Test transfer confirmation with zero amount shows error."""
        mock_find_users.return_value = [self.account]
        mock_find_cash.return_value = [self.cash_account]
        mock_template = Mock()
        mock_template.render.return_value = 'rendered_template'
        mock_get_template.return_value = mock_template

        request = self.create_authenticated_request('POST', '/transfer')
        transfer = Transfer(amount=0.0)

        view = TransferView()
        view.request = request
        response = view.transfer_confirmation(request, transfer, 'Personal')

        # Verify
        self.assertEqual(response.status_code, 200)
        mock_get_template.assert_called_with('newTransfer.html')
        # Verify context contains error
        call_args = mock_template.render.call_args
        self.assertTrue(call_args[0][0]['error'])

    def test_transfer_view_post_confirm_redirect(self):
        """Test TransferView POST confirm without pending transfer redirects."""
        request = self.create_authenticated_request('POST', '/transfer/confirm')
        request.POST = {'action': 'confirm'}
        # No pendingTransfer in session

        view = TransferView()
        view.request = request
        response = view.post(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/transfer')


@pytest.mark.unit
class TestTransferFormAndHelperFunctions(ViewTestMixin, TestCase):
    """Unit tests for TransferForm and helper functions."""

    def test_transfer_form_fields(self):
        """Test TransferForm includes correct fields."""
        form = TransferForm()
        expected_fields = ['fromAccount', 'toAccount', 'description', 'amount', 'fee']
        self.assertEqual(list(form.fields.keys()), expected_fields)

    def test_trusted_class(self):
        """Test Trusted class initialization."""
        trusted = Trusted('testuser')
        self.assertEqual(trusted.username, 'testuser')

    def test_trusted_class_to_dict(self):
        """Test Trusted class to_dict method for JSON serialization."""
        trusted = Trusted('testuser')
        result = trusted.to_dict()
        self.assertEqual(result, {'username': 'testuser', 'type': 'trusted'})

    def test_trusted_class_from_dict(self):
        """Test Trusted class from_dict method for safe deserialization."""
        data = {'username': 'testuser', 'type': 'trusted'}
        trusted = Trusted.from_dict(data)
        self.assertEqual(trusted.username, 'testuser')

    def test_trusted_class_from_dict_missing_username(self):
        """Test Trusted class from_dict raises error on missing username."""
        data = {'type': 'trusted'}
        with self.assertRaises(ValueError) as context:
            Trusted.from_dict(data)
        self.assertIn('username', str(context.exception))

    @patch('web.views.AESGCM')
    @patch('web.views.secrets.token_bytes')
    @patch('web.views.base64.b64encode')
    def test_get_file_checksum_uses_aes_gcm(self, mock_b64encode, mock_token_bytes, mock_aesgcm):
        """Test get_file_checksum function uses AES-256-GCM encryption."""
        # Mock AESGCM encryption
        mock_cipher = Mock()
        mock_cipher.encrypt.return_value = b'ciphertext_with_tag'
        mock_aesgcm.return_value = mock_cipher
        mock_token_bytes.return_value = b'random12byte'  # Exactly 12 bytes for GCM nonce
        mock_b64encode.return_value = b'base64_encoded'

        result = get_file_checksum(b'test_data')

        self.assertEqual(result, 'base64_encoded')
        # Verify AESGCM was used
        mock_aesgcm.assert_called_once()
        mock_cipher.encrypt.assert_called_once_with(b'random12byte', b'test_data', None)
        # Verify nonce + ciphertext are combined
        mock_b64encode.assert_called_once_with(b'random12byte' + b'ciphertext_with_tag')

    def test_get_file_checksum_produces_different_output(self):
        """Test get_file_checksum produces different output for same input (random nonce)."""
        # Due to random nonce, same input should produce different outputs
        result1 = get_file_checksum(b'test_data')
        result2 = get_file_checksum(b'test_data')

        # Results should be different due to random nonce
        self.assertNotEqual(result1, result2)

    def test_get_file_checksum_error_handling(self):
        """Test get_file_checksum raises ValueError on encryption failure."""
        with patch('web.views.AESGCM', side_effect=Exception("Encryption failed")):
            with self.assertRaises(ValueError) as context:
                get_file_checksum(b'test_data')
            self.assertIn('Failed to encrypt data', str(context.exception))

    @patch('os.system')
    def test_to_traces_command_injection_vulnerability(self, mock_system):
        """Test to_traces function preserves command injection vulnerability."""
        # Mock os.system return value
        mock_system.return_value = 0

        # Test with malicious command injection
        malicious_command = 'echo test; rm -rf /'
        result = to_traces(malicious_command)

        # The function should execute the command directly (vulnerability)
        mock_system.assert_called_once_with(malicious_command)
        self.assertEqual(result, '0')

    def test_to_traces_return_type(self):
        """Test to_traces returns string representation of system call result."""
        with patch('os.system', return_value=42):
            result = to_traces('safe_command')
            self.assertEqual(result, '42')
            self.assertIsInstance(result, str)
