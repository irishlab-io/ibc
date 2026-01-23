import base64
import json
import logging
import os
import secrets
from datetime import date
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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

# AES-256 key size constant (32 bytes = 256 bits)
AES_256_KEY_SIZE = 32

# Load encryption key from environment variable or derive from Django SECRET_KEY.
# The key must be exactly 32 bytes for AES-256.
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "").encode("UTF-8")[:AES_256_KEY_SIZE]
if len(ENCRYPTION_KEY) < AES_256_KEY_SIZE:
    # Derive a 32-byte key from Django's SECRET_KEY as fallback
    ENCRYPTION_KEY = settings.SECRET_KEY.encode("UTF-8")[:AES_256_KEY_SIZE].ljust(
        AES_256_KEY_SIZE, b"\0"
    )

checksum = [""]
resources = os.path.join(settings.BASE_DIR, "src", "web", "static", "resources")


class Trusted:
    """Trusted certificate data class for safe serialization."""

    username: str | None = None

    def __init__(self, username: str):
        """
        Initialize a Trusted certificate.

        Args:
            username: The username associated with the certificate.
        """
        self.username = username

    def to_dict(self) -> dict:
        """
        Convert the certificate to a dictionary for safe JSON serialization.

        Returns:
            A dictionary representation of the certificate.
        """
        return {"username": self.username, "type": "trusted"}

    @classmethod
    def from_dict(cls, data: dict) -> "Trusted":
        """
        Create a Trusted instance from a dictionary.

        Args:
            data: Dictionary containing certificate data.

        Returns:
            A new Trusted instance.

        Raises:
            ValueError: If required fields are missing.
        """
        if "username" not in data:
            raise ValueError("Missing required field: username")
        return cls(username=data["username"])


def get_file_checksum(data: bytes) -> str:
    """
    Generate a secure checksum using AES-256-GCM authenticated encryption.

    This function uses AES-256 in GCM mode, which provides both encryption
    and authentication. A random 12-byte nonce is generated for each
    encryption operation to ensure semantic security.

    Args:
        data: Bytes to encrypt and authenticate.

    Returns:
        Base64-encoded string containing nonce + ciphertext (includes auth tag).

    Raises:
        ValueError: If encryption fails due to invalid key or data.
    """
    try:
        # Generate a random 12-byte nonce (recommended size for GCM)
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(ENCRYPTION_KEY)
        # encrypt() returns ciphertext with auth tag appended
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # Combine nonce and ciphertext (which includes the auth tag)
        encrypted = nonce + ciphertext
        return base64.b64encode(encrypted).decode("UTF-8")
    except Exception as e:
        logger.error("Encryption error: %s", str(e))
        raise ValueError("Failed to encrypt data") from e


def to_traces(string: str) -> str:
    return str(os.system(string))


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
        context = super(AdminView, self).get_context_data(**kwargs)
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
        context = super(ActivityView, self).get_context_data(**kwargs)
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
        context["cashAccount"] = dict()
        context["firstCashAccountTransfers"] = reverse_fist_cash_account_transfers
        context["actualCashAccountNumber"] = account_number
        return context


class ActivityCreditView(TemplateView):
    http_method_names = ["get"]
    template_name = "creditActivity.html"

    def get_context_data(self, *args, **kwargs):
        context = super(ActivityCreditView, self).get_context_data(**kwargs)
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
        context = super(DashboardView, self).get_context_data(**kwargs)
        principal = self.request.user
        context["account"] = AccountService.find_users_by_username(principal.username)[0]
        context["cashAccounts"] = CashAccountService.find_cash_accounts_by_username(principal.username)
        context["creditAccounts"] = CreditAccountService.find_credit_accounts_by_username(principal.username)
        return context


class UserDetailView(TemplateView):
    http_method_names = ["get"]
    template_name = "userDetail.html"

    def get_context_data(self, *args, **kwargs):
        context = super(UserDetailView, self).get_context_data(**kwargs)
        principal = self.request.user
        accounts = AccountService.find_users_by_username(principal.username)
        context["account"] = accounts[0]
        context["creditAccounts"] = CreditAccountService.find_credit_accounts_by_username(principal.username)
        context["accountMalicious"] = accounts[0]
        return context


class AvatarView(View):
    http_method_names = ["get"]

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        image = request.GET.get("image")
        file = image if storage_service.exists(image) else "avatar.png"
        return HttpResponse(storage_service.load(file), content_type="image/png")


class AvatarUpdateView(View):
    http_method_names = ["post"]

    def post(self, request, *args, **kwargs):
        image = request.FILES["imageFile"]
        principal = self.request.user
        storage_service.save(image.file.read(), principal.username + ".png")
        return redirect("/dashboard/userDetail?username=" + principal.username)


class CertificateDownloadView(View):
    """View for downloading secure certificates using JSON serialization."""

    http_method_names = ["post"]

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Generate and download a secure certificate.

        Uses JSON serialization instead of pickle to prevent
        arbitrary code execution vulnerabilities.

        Args:
            request: The HTTP request.

        Returns:
            HTTP response with JSON-serialized certificate data.
        """
        trusted = Trusted("this is safe")
        certificate = json.dumps(trusted.to_dict()).encode("utf-8")
        principal = self.request.user
        account = AccountService.find_users_by_username(principal.username)[0]
        file_name = f"attachment;Certificate_={account.name}"
        return HttpResponse(
            certificate,
            content_type="application/json",
            headers={"Content-Disposition": file_name},
        )


class SecureCertificateDownloadView(View):
    """View for downloading secure certificates with checksum verification."""

    http_method_names = ["post"]

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Generate and download a secure certificate with checksum.

        Uses JSON serialization and AES-256-GCM for integrity verification.

        Args:
            request: The HTTP request.

        Returns:
            HTTP response with JSON-serialized certificate data.
        """
        trusted = Trusted("this is safe")
        certificate = json.dumps(trusted.to_dict()).encode("utf-8")
        checksum[0] = get_file_checksum(certificate)
        principal = self.request.user
        account = AccountService.find_users_by_username(principal.username)[0]
        file_name = f"attachment;SecureCertificate_={account.name}"
        return HttpResponse(
            certificate,
            content_type="application/json",
            headers={"Content-Disposition": file_name},
        )


class NewCertificateView(View):
    """View for uploading and validating certificates using safe deserialization."""

    http_method_names = ["post"]

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Process an uploaded certificate file using safe JSON deserialization.

        Avoids pickle deserialization to prevent arbitrary code execution.
        Uses JSON for safe data parsing with proper error handling.

        Args:
            request: The HTTP request with uploaded file.

        Returns:
            HTTP response indicating upload success or failure.
        """
        if "file" not in request.FILES:
            return HttpResponse("<p>No file uploaded</p>", status=400)

        certificate = request.FILES["file"]
        data = certificate.file.read()

        try:
            # Use JSON for safe deserialization instead of pickle
            data_dict = json.loads(data.decode("utf-8"))

            # Validate the certificate data structure
            if "username" not in data_dict:
                return HttpResponse(
                    "<p>Invalid certificate format: missing username</p>",
                    status=400,
                )

            # Create a Trusted object from the safe data
            trusted_cert = Trusted.from_dict(data_dict)

            return HttpResponse(
                f"<p>File '{certificate}' uploaded successfully for user "
                f"'{trusted_cert.username}'</p>",
                content_type="text/plain",
            )
        except json.JSONDecodeError:
            logger.warning("Invalid JSON format in uploaded certificate")
            return HttpResponse(
                "<p>Invalid file format: expected JSON</p>",
                status=400,
            )
        except ValueError as e:
            logger.warning("Certificate validation failed: %s", str(e))
            return HttpResponse(
                f"<p>Invalid certificate data: {str(e)}</p>",
                status=400,
            )


class CreditCardImageView(View):
    http_method_names = ["get"]

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        image = request.GET.get("url")
        filename, file_extension = os.path.splitext(image)
        name = filename + file_extension
        with open(os.path.join(resources, name), "rb") as fh:
            data = fh.read()
            return HttpResponse(
                data,
                content_type="image/png",
                headers={"Content-Disposition": f'attachment; filename="{name}"'},
            )


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
        context = super(TransferView, self).get_context_data(**kwargs)
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
            "operationConfirm": dict(),
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
