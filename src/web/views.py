import json
import logging
import os
from datetime import date
from typing import Any

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.forms import ModelForm
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.template import loader
from django.views.generic.base import TemplateView, View

from web.models import Transfer
from web.services import (
    AccountService,
    ActivityService,
    CashAccountService,
    CreditAccountService,
    StorageService,
    TransferService,
)

logger = logging.getLogger(__name__)
storage_service = StorageService()

# Use environment variable for encryption key with secure fallback
# In production, this should be set via environment variable
ENCRYPTION_KEY_SALT = getattr(settings, 'ENCRYPTION_KEY_SALT', get_random_bytes(32))
SECRET_KEY = getattr(settings, 'SECRET_KEY', 'django-insecure-fallback-key')

resources = os.path.join(settings.BASE_DIR, "src", "web", "static", "resources")


class CertificateData:
    """Safe data class for certificate information (no pickle serialization)."""

    username: str | None = None

    def __init__(self, username: str):
        self.username = username

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON serialization."""
        return {"username": self.username}

    @classmethod
    def from_dict(cls, data: dict) -> "CertificateData":
        """Deserialize from dictionary."""
        return cls(username=data.get("username", ""))


def get_file_checksum(data: bytes) -> str:
    """
    Generate a secure checksum for file data using AES-256-GCM.

    Args:
        data: The file data to generate checksum for

    Returns:
        A secure checksum string
    """
    # Derive a key from the secret key using PBKDF2
    key = PBKDF2(SECRET_KEY, ENCRYPTION_KEY_SALT, dkLen=32)

    # Generate a random nonce for AES-GCM
    nonce = get_random_bytes(12)

    # Create AES cipher in GCM mode
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Encrypt and authenticate the data
    padded = pad(data, AES.block_size)
    ciphertext, tag = cipher.encrypt_and_digest(padded)

    # Combine nonce, tag, and ciphertext for storage
    # Format: nonce (12 bytes) + tag (16 bytes) + ciphertext
    combined = nonce + tag + ciphertext

    # Return as hex string for easy storage
    return combined.hex()


def to_traces(string: str) -> str:
    """
    Log transfer trace information securely.

    Instead of executing shell commands, this function now safely logs
    the information to a file using secure file operations.

    Args:
        string: The trace information to log

    Returns:
        Success status as string
    """
    try:
        # Sanitize the input by removing any potentially dangerous characters
        # Only allow alphanumeric, spaces, and safe punctuation
        safe_string = ''.join(c for c in string if c.isalnum() or c in ' -_:.')

        # Log to file using secure file operations instead of shell command
        trace_file = os.path.join(settings.BASE_DIR, "traces.txt")

        # Use secure file writing with proper permissions
        with open(trace_file, 'a', encoding='utf-8') as f:
            f.write(f"{safe_string}\n")

        logger.info(f"Trace logged: {safe_string}")
        return "0"  # Success
    except Exception as e:
        logger.error(f"Failed to write trace: {e}")
        return "1"  # Failure


class LoginView(TemplateView):
    http_method_names = ["get", "post"]
    template_name = "login.html"

    def post(self, request, *args, **kwargs):
        user = authenticate(request=request)
        if user is None:
            template = loader.get_template("login.html")
            context = {"authenticationFailure": True}
            return HttpResponse(template.render(context, request))
        login(request, user)
        return redirect("/dashboard")


class LogoutView(View):
    http_method_names = ["get"]

    def get(self, request, *args, **kwargs):
        logout(request)
        return redirect("/login")


class AdminView(TemplateView):
    http_method_names = ["get"]
    template_name = "admin.html"

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        principal = self.request.user
        context["account"] = AccountService.find_users_by_username(principal.username)[0]
        context["accounts"] = AccountService.find_all_users()
        return context


class ActivityView(TemplateView):
    http_method_names = ["get", "post"]
    template_name = "accountActivity.html"

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        return self.render_to_response(context)

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        principal = self.request.user
        account = AccountService.find_users_by_username(principal.username)[0]
        cash_accounts = CashAccountService.find_cash_accounts_by_username(principal.username)
        if "account" in self.request.resolver_match.kwargs:
            account_number = self.request.resolver_match.kwargs["account"]
        elif "number" in self.request.POST:
            account_number = self.request.POST["number"]
        else:
            account_number = cash_accounts[0].number
        first_cash_account_transfers = ActivityService.find_transactions_by_cash_account_number(account_number)
        reverse_fist_cash_account_transfers = list(reversed(first_cash_account_transfers))
        context["account"] = account
        context["cashAccounts"] = cash_accounts
        context["cashAccount"] = {}
        context["firstCashAccountTransfers"] = reverse_fist_cash_account_transfers
        context["actualCashAccountNumber"] = account_number
        return context


class ActivityCreditView(TemplateView):
    http_method_names = ["get"]
    template_name = "creditActivity.html"

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        principal = self.request.user
        number = self.request.GET["number"]
        account = AccountService.find_users_by_username(principal.username)[0]
        context["account"] = account
        context["actualCreditCardNumber"] = number
        return context


class DashboardView(TemplateView):
    http_method_names = ["get"]
    template_name = "dashboard.html"

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        principal = self.request.user
        context["account"] = AccountService.find_users_by_username(principal.username)[0]
        context["cashAccounts"] = CashAccountService.find_cash_accounts_by_username(principal.username)
        context["creditAccounts"] = CreditAccountService.find_credit_accounts_by_username(principal.username)
        return context


class UserDetailView(TemplateView):
    http_method_names = ["get"]
    template_name = "userDetail.html"

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        principal = self.request.user
        accounts = AccountService.find_users_by_username(principal.username)
        context["account"] = accounts[0]
        context["creditAccounts"] = CreditAccountService.find_credit_accounts_by_username(principal.username)
        context["accountMalicious"] = accounts[0]
        return context


class AvatarView(View):
    http_method_names = ["get"]

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Serve avatar images with path traversal protection.

        Args:
            request: The HTTP request

        Returns:
            HTTP response with the avatar image
        """
        image = request.GET.get("image", "avatar.png")

        # Prevent path traversal attacks by validating the filename
        if not image or not self._is_safe_filename(image):
            logger.warning(f"Unsafe filename attempted: {image}")
            image = "avatar.png"

        # Ensure the file exists before loading
        file = image if storage_service.exists(image) else "avatar.png"

        return HttpResponse(storage_service.load(file), content_type="image/png")

    @staticmethod
    def _is_safe_filename(filename: str) -> bool:
        """
        Validate that a filename is safe (no path traversal).

        Args:
            filename: The filename to validate

        Returns:
            True if the filename is safe, False otherwise
        """
        # Reject filenames with path separators or parent directory references
        if not filename:
            return False

        dangerous_patterns = ['..', '/', '\\', '\x00', '\n', '\r']
        if any(pattern in filename for pattern in dangerous_patterns):
            return False

        # Only allow alphanumeric, dots, dashes, and underscores
        allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_')
        if not all(c in allowed_chars for c in filename):
            return False

        # Ensure it ends with an allowed extension
        allowed_extensions = ['.png', '.jpg', '.jpeg', '.gif']
        return any(filename.lower().endswith(ext) for ext in allowed_extensions)


class AvatarUpdateView(View):
    http_method_names = ["post"]

    def post(self, request, *args, **kwargs):
        """
        Handle avatar image upload with validation.

        Args:
            request: The HTTP request with uploaded image

        Returns:
            Redirect to user detail page
        """
        if "imageFile" not in request.FILES:
            logger.warning("Avatar upload attempted without file")
            return redirect(f"/dashboard/userDetail?username={request.user.username}")

        image = request.FILES["imageFile"]

        # Validate file size (limit to 5MB)
        max_size = 5 * 1024 * 1024  # 5MB
        if image.size > max_size:
            logger.warning(f"Avatar upload rejected: file too large ({image.size} bytes)")
            return redirect(f"/dashboard/userDetail?username={request.user.username}")

        # Validate file type by checking magic bytes
        allowed_types = {
            b'\x89PNG': 'png',
            b'\xff\xd8\xff': 'jpg',
            b'GIF87a': 'gif',
            b'GIF89a': 'gif'
        }

        file_data = image.file.read()

        # Check magic bytes
        is_valid_image = False
        for magic_bytes in allowed_types.keys():
            if file_data.startswith(magic_bytes):
                is_valid_image = True
                break

        if not is_valid_image:
            logger.warning("Avatar upload rejected: invalid file type")
            return redirect(f"/dashboard/userDetail?username={request.user.username}")

        # Save with sanitized filename
        principal = self.request.user
        safe_username = ''.join(c for c in principal.username if c.isalnum() or c == '_')
        storage_service.save(file_data, safe_username + ".png")

        return redirect(f"/dashboard/userDetail?username={principal.username}")


class CertificateDownloadView(View):
    http_method_names = ["post"]

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Generate and download a certificate using safe JSON serialization.

        Args:
            request: The HTTP request

        Returns:
            HTTP response with the certificate data
        """
        # Use safe JSON serialization instead of pickle
        cert_data = CertificateData("this is safe")
        certificate_json = json.dumps(cert_data.to_dict()).encode('utf-8')

        principal = self.request.user
        account = AccountService.find_users_by_username(principal.username)[0]

        # Sanitize filename to prevent header injection
        safe_name = ''.join(c for c in account.name if c.isalnum() or c in ' -_')
        file_name = f'attachment; filename="Certificate_{safe_name}.json"'

        return HttpResponse(
            certificate_json,
            content_type="application/json",
            headers={"Content-Disposition": file_name},
        )


class MaliciousCertificateDownloadView(View):
    """
    Endpoint disabled for security reasons.

    Previously this view demonstrated insecure deserialization vulnerabilities.
    It has been replaced with secure certificate handling.
    """

    http_method_names = ["post"]

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Return an error response as this endpoint has been disabled."""
        logger.warning("Attempted access to disabled MaliciousCertificateDownloadView")
        return HttpResponse(
            json.dumps({"error": "This endpoint has been disabled for security reasons"}),
            content_type="application/json",
            status=410,  # Gone
        )


class NewCertificateView(View):
    http_method_names = ["post"]

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Handle certificate file upload with secure validation.

        Args:
            request: The HTTP request with uploaded file

        Returns:
            HTTP response indicating success or failure
        """
        if "file" not in request.FILES:
            return HttpResponse("<p>No file uploaded</p>", status=400)

        certificate = request.FILES["file"]

        # Validate file size (limit to 1MB)
        max_size = 1 * 1024 * 1024  # 1MB
        if certificate.size > max_size:
            return HttpResponse(
                f"<p>File too large. Maximum size is {max_size} bytes</p>",
                status=400
            )

        # Validate file type (only allow JSON)
        if not certificate.name.endswith('.json'):
            return HttpResponse(
                "<p>Invalid file type. Only JSON files are allowed</p>",
                status=400
            )

        try:
            # Read and parse as JSON (safe deserialization)
            data = certificate.file.read()

            # Attempt to parse as JSON
            cert_data = json.loads(data.decode('utf-8'))

            # Validate the structure
            if not isinstance(cert_data, dict) or 'username' not in cert_data:
                return HttpResponse(
                    "<p>Invalid certificate format</p>",
                    status=400
                )

            # Recreate certificate object safely
            cert_obj = CertificateData.from_dict(cert_data)

            logger.info(f"Certificate uploaded successfully for user: {cert_obj.username}")

            return HttpResponse(
                f"<p>File '{certificate.name}' uploaded and processed successfully</p>",
                content_type="text/plain"
            )

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in certificate upload: {e}")
            return HttpResponse(
                "<p>Invalid JSON format in certificate file</p>",
                status=400
            )
        except Exception as e:
            logger.error(f"Error processing certificate upload: {e}")
            return HttpResponse(
                "<p>Error processing certificate file</p>",
                status=500
            )


class CreditCardImageView(View):
    http_method_names = ["get"]

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Serve credit card images with path traversal protection.

        Args:
            request: The HTTP request

        Returns:
            HTTP response with the image data
        """
        image = request.GET.get("url", "")

        # Validate the filename to prevent path traversal
        if not image or not self._is_safe_filename(image):
            logger.warning(f"Unsafe filename attempted in CreditCardImageView: {image}")
            return HttpResponse(
                "<p>Invalid image filename</p>",
                status=400
            )

        # Get just the filename without any path components
        filename = os.path.basename(image)
        _, file_extension = os.path.splitext(filename)

        # Validate file extension
        allowed_extensions = ['.png', '.jpg', '.jpeg', '.gif']
        if file_extension.lower() not in allowed_extensions:
            return HttpResponse(
                "<p>Invalid file type</p>",
                status=400
            )

        # Construct safe file path
        safe_path = os.path.join(resources, filename)

        # Ensure the resolved path is still within the resources directory
        safe_path = os.path.normpath(safe_path)
        if not safe_path.startswith(os.path.normpath(resources)):
            logger.warning(f"Path traversal attempt detected: {image}")
            return HttpResponse(
                "<p>Invalid file path</p>",
                status=403
            )

        # Check if file exists
        if not os.path.exists(safe_path):
            return HttpResponse(
                "<p>File not found</p>",
                status=404
            )

        try:
            with open(safe_path, "rb") as fh:
                data = fh.read()

                # Sanitize filename for Content-Disposition header
                safe_filename = ''.join(c for c in filename if c.isalnum() or c in '.-_')

                return HttpResponse(
                    data,
                    content_type="image/png",
                    headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'},
                )
        except Exception as e:
            logger.error(f"Error reading image file: {e}")
            return HttpResponse(
                "<p>Error reading file</p>",
                status=500
            )

    @staticmethod
    def _is_safe_filename(filename: str) -> bool:
        """
        Validate that a filename is safe (no path traversal).

        Args:
            filename: The filename to validate

        Returns:
            True if the filename is safe, False otherwise
        """
        if not filename:
            return False

        # Reject filenames with path separators or parent directory references
        dangerous_patterns = ['..', '/', '\\', '\x00', '\n', '\r']
        if any(pattern in filename for pattern in dangerous_patterns):
            return False

        # Only allow safe characters
        allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_')
        return all(c in allowed_chars for c in filename)


class TransferForm(ModelForm):
    class Meta:
        model = Transfer
        fields = ["fromAccount", "toAccount", "description", "amount", "fee"]


class TransferView(TemplateView):
    http_method_names = ["get", "post"]
    template_name = "newTransfer.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        response = self.render_to_response(context)
        response.set_cookie("accountType", "Personal")
        return response

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        principal = self.request.user
        context["account"] = AccountService.find_users_by_username(principal.username)[0]
        context["cashAccounts"] = CashAccountService.find_cash_accounts_by_username(principal.username)
        context["transfer"] = Transfer(fee=5.0, fromAccount="", toAccount="", description="", amount=0.0)
        return context

    def post(self, request, *args, **kwargs):
        account_type = request.COOKIES.get("accountType")
        if request.path.endswith("/confirm"):
            action = request.POST["action"]
            if "pendingTransfer" in request.session and action == "confirm":
                transfer = Transfer()
                transfer.from_dict(json.loads(request.session["pendingTransfer"]))
                del request.session["pendingTransfer"]
                return self.transfer_confirmation(request, transfer, account_type)
            return redirect("/transfer")
        transfer_form = TransferForm(request.POST)
        transfer_form.is_valid()  # ensure model is bound
        transfer = transfer_form.instance
        to_traces(f"echo {transfer.fromAccount} to account {transfer.toAccount} accountType:{account_type}>traces.txt")
        if account_type == "Personal":
            return self.transfer_check(request, transfer)
        return self.transfer_confirmation(request, transfer, account_type)

    def transfer_check(self, request, transfer) -> HttpResponse:
        request.session["pendingTransfer"] = json.dumps(transfer.as_dict())
        principal = self.request.user
        accounts = AccountService.find_users_by_username(principal.username)
        template = loader.get_template("transferCheck.html")
        context = {
            "account": accounts[0],
            "transferbean": transfer,
            "operationConfirm": {},
        }
        return HttpResponse(template.render(context, request))

    def transfer_confirmation(self, request, transfer, account_type: str) -> HttpResponse:
        principal = self.request.user
        cash_accounts = CashAccountService.find_cash_accounts_by_username(principal.username)
        accounts = AccountService.find_users_by_username(principal.username)
        aux = transfer.amount
        if aux == 0.0:
            template = loader.get_template("newTransfer.html")
            context = {
                "account": accounts[0],
                "cashAccounts": cash_accounts,
                "transfer": transfer,
                "error": True,
            }
            return HttpResponse(template.render(context, request))
        transfer.username = principal.username
        transfer.date = date.today()
        transfer.amount = round(transfer.amount, 2)
        transfer.fee = round((transfer.amount * transfer.fee) / 100, 2)
        TransferService.createNewTransfer(transfer)
        template = loader.get_template("transferConfirmation.html")
        context = {
            "transferbean": transfer,
            "account": accounts[0],
            "accountType": account_type,
        }
        return HttpResponse(template.render(context, request))
