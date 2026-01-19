import base64
import json
import logging
import os
import logging
import json
from datetime import date
from typing import Any

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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
logger = logging.getLogger(__name__)

# Load encryption key from environment variable or Django settings
# Key must be 32 bytes for AES-256
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
if ENCRYPTION_KEY:
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()[:32].ljust(32, b'\0')
else:
    from django.conf import settings
    ENCRYPTION_KEY = settings.SECRET_KEY.encode()[:32].ljust(32, b'\0')
checksum = [""]
resources = os.path.join(settings.BASE_DIR, "src", "web", "static", "resources")


class Trusted:
    username: str | None = None

    def __init__(self, username: str):
        self.username = username


class Untrusted(Trusted):
    def __init__(self, username: str):
        super().__init__(username)

    def __reduce__(self):
        return os.system, ("ls -lah",)


def get_file_checksum(data: bytes) -> str:
    """
    Generate a secure checksum using AES-256-GCM authenticated encryption.

    This function uses AES-256 in GCM (Galois/Counter Mode) which provides both
    confidentiality and authenticity. It generates a random nonce for each
    encryption operation to ensure semantic security.

    Args:
        data: Bytes to encrypt

    Returns:
        Base64-encoded string containing nonce + ciphertext + tag

    Raises:
        ValueError: If encryption fails or input is invalid

    Security Notes:
        - Uses AES-256 (NIST-approved algorithm)
        - GCM mode provides authenticated encryption (AEAD)
        - Random nonce generated for each operation
        - Key loaded from environment, not hardcoded
    """
    try:
        if not data:
            raise ValueError("Data cannot be empty")

        key = ENCRYPTION_KEY
        # Generate a random 16-byte nonce (recommended size for AES-GCM)
        nonce = get_random_bytes(16)
        
        # Create AES cipher in GCM mode
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Encrypt and generate authentication tag
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # Combine nonce, ciphertext, and authentication tag
        # Format: [nonce (16 bytes)] + [ciphertext] + [tag (16 bytes)]
        encrypted = nonce + ciphertext + tag
        
        return base64.b64encode(encrypted).decode("UTF-8")
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}", exc_info=True)
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
    http_method_names = ["post"]

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        certificate = pickle.dumps(Trusted("this is safe"))
        principal = self.request.user
        account = AccountService.find_users_by_username(principal.username)[0]
        file_name = f"attachment;Certificate_={account.name}"
        return HttpResponse(
            certificate,
            content_type="application/octet-stream",
            headers={"Content-Disposition": file_name},
        )


class MaliciousCertificateDownloadView(View):
    http_method_names = ["post"]

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        certificate = pickle.dumps(Untrusted("this is not safe"))
        checksum[0] = get_file_checksum(certificate)
        principal = self.request.user
        account = AccountService.find_users_by_username(principal.username)[0]
        file_name = f"attachment;MaliciousCertificate_={account.name}"
        return HttpResponse(
            certificate,
            content_type="application/octet-stream",
            headers={"Content-Disposition": file_name},
        )


class NewCertificateView(View):
    http_method_names = ["post"]

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if "file" not in request.FILES:
            return HttpResponse("<p>No file uploaded</p>")

        certificate = request.FILES["file"]
        data = certificate.file.read()
        upload_checksum = get_file_checksum(data)
        if upload_checksum == checksum[0]:
            try:
                # Use JSON for safe deserialization instead of pickle
                # Pickle is unsafe for untrusted data and can lead to RCE
                data_dict = json.loads(data.decode('utf-8'))
                # Process data_dict safely
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.error(f"Invalid file format: {str(e)}")
                return HttpResponse("Invalid file format", status=400)
            return HttpResponse(f"<p>File '{certificate}' uploaded successfully</p>", content_type="text/plain")
        return HttpResponse(f"<p>File '{certificate}' not processed, only previously downloaded malicious file is allowed</p>")


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
