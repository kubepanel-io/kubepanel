"""
Authentication views (login, logout, 2FA)
"""
import secrets
import hashlib
import base64
from io import BytesIO

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.utils import timezone
from django.http import HttpResponseForbidden

import logging

try:
    import pyotp
    import qrcode
    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False

from dashboard.services.logging_service import KubepanelLogger
from dashboard.forms import TOTPVerifyForm, TOTPSetupConfirmForm, RecoveryCodeForm, TOTPDisableForm
from .utils import get_client_ip, get_user_agent

logger = logging.getLogger("django")

# 2FA Session keys
PENDING_2FA_USER_ID = '_2fa_pending_user_id'
PENDING_2FA_TIMESTAMP = '_2fa_pending_timestamp'
PENDING_2FA_NEXT_URL = '_2fa_pending_next_url'
TOTP_SETUP_SECRET = '_2fa_setup_secret'

# 2FA Configuration
TWO_FA_SESSION_TIMEOUT = 300  # 5 minutes to complete 2FA
TWO_FA_MAX_ATTEMPTS = 5
RECOVERY_CODE_COUNT = 10


@csrf_protect
@require_http_methods(["GET", "POST"])
def kplogin(request):
    """
    Handle user login with proper security measures and comprehensive logging
    """
    if request.method == "GET":
        return render(request, "login/login.html")

    # Handle POST request (login attempt)
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)

    try:
        # Validate required POST data
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")

        if not username or not password:
            KubepanelLogger.log_system_event(
                message=f"Login attempt with missing credentials from IP {client_ip}",
                level="WARNING",
                actor="login_system",
                data={
                    "ip_address": client_ip,
                    "user_agent": user_agent,
                    "error": "missing_credentials",
                    "provided_username": bool(username),
                    "provided_password": bool(password)
                }
            )
            messages.error(request, "Please provide both username and password.")
            return render(request, "login/login.html")

        # Validate username length (reasonable limits)
        if len(username) > 150 or len(password) > 128:
            KubepanelLogger.log_system_event(
                message=f"Login attempt with excessive input length from IP {client_ip}",
                level="WARNING",
                actor="login_system",
                data={
                    "ip_address": client_ip,
                    "user_agent": user_agent,
                    "username_length": len(username),
                    "password_length": len(password),
                    "attempted_username": username[:50] + "..." if len(username) > 50 else username
                }
            )
            messages.error(request, "Invalid credentials provided.")
            return render(request, "login/login.html")

        # Attempt authentication
        user = authenticate(request, username=username, password=password)

        if user is not None:
            if user.is_active:
                # Check if 2FA is required for this user (superuser with 2FA enabled)
                if user.is_superuser and hasattr(user, 'profile') and user.profile.totp_enabled:
                    # Store pending 2FA state in session
                    request.session[PENDING_2FA_USER_ID] = user.id
                    request.session[PENDING_2FA_TIMESTAMP] = timezone.now().isoformat()

                    # Store next URL if provided
                    next_url = request.GET.get('next') or request.POST.get('next')
                    if next_url and next_url.startswith('/') and not next_url.startswith('//'):
                        request.session[PENDING_2FA_NEXT_URL] = next_url

                    KubepanelLogger.log_system_event(
                        message=f"2FA verification required for user {username}",
                        level="INFO",
                        actor=f"user:{username}",
                        user=user,
                        data={
                            "ip_address": client_ip,
                            "user_agent": user_agent,
                            "user_id": user.id,
                            "is_superuser": user.is_superuser,
                            "login_method": "form_authentication",
                            "2fa_required": True
                        }
                    )

                    return redirect('verify_2fa')

                # No 2FA required - proceed with normal login
                login(request, user)

                # Log successful login
                KubepanelLogger.log_system_event(
                    message=f"Successful login for user {username}",
                    level="INFO",
                    actor=f"user:{username}",
                    user=user,
                    data={
                        "ip_address": client_ip,
                        "user_agent": user_agent,
                        "user_id": user.id,
                        "is_superuser": user.is_superuser,
                        "login_method": "form_authentication"
                    }
                )

                # Also create a user-specific log entry
                try:
                    KubepanelLogger.log(
                        content_object=user,
                        message=f"User logged in from IP {client_ip}",
                        level="INFO",
                        actor=f"user:{username}",
                        user=user,
                        data={
                            "ip_address": client_ip,
                            "user_agent": user_agent,
                            "login_timestamp": timezone.now().isoformat(),
                            "session_key": request.session.session_key
                        }
                    )
                except Exception as e:
                    logger.warning(f"Failed to create user-specific login log for {username}: {e}")

                # Redirect to intended page or main dashboard
                next_url = request.GET.get('next') or request.POST.get('next')
                if next_url:
                    if next_url.startswith('/') and not next_url.startswith('//'):
                        return redirect(next_url)

                return redirect('kpmain')
            else:
                # User account is disabled
                KubepanelLogger.log_system_event(
                    message=f"Login attempt for disabled user {username} from IP {client_ip}",
                    level="WARNING",
                    actor="login_system",
                    data={
                        "ip_address": client_ip,
                        "user_agent": user_agent,
                        "username": username,
                        "error": "account_disabled",
                        "user_id": user.id
                    }
                )
                messages.error(request, "Your account has been disabled.")
                return render(request, "login/login.html")
        else:
            # Invalid credentials
            username_exists = User.objects.filter(username=username).exists()

            KubepanelLogger.log_system_event(
                message=f"Failed login attempt for username '{username}' from IP {client_ip}",
                level="WARNING",
                actor="login_system",
                data={
                    "ip_address": client_ip,
                    "user_agent": user_agent,
                    "attempted_username": username,
                    "username_exists": username_exists,
                    "error": "invalid_credentials",
                    "failure_reason": "invalid_password" if username_exists else "invalid_username"
                }
            )

            messages.error(request, "Invalid username or password.")
            return render(request, "login/login.html")

    except KeyError as e:
        KubepanelLogger.log_system_event(
            message=f"Login attempt with missing POST parameter from IP {client_ip}: {str(e)}",
            level="WARNING",
            actor="login_system",
            data={
                "ip_address": client_ip,
                "user_agent": user_agent,
                "error": "missing_post_parameter",
                "missing_parameter": str(e)
            }
        )
        messages.error(request, "Invalid login request.")
        return render(request, "login/login.html")

    except Exception as e:
        KubepanelLogger.log_system_event(
            message=f"Unexpected error during login from IP {client_ip}: {str(e)}",
            level="ERROR",
            actor="login_system",
            data={
                "ip_address": client_ip,
                "user_agent": user_agent,
                "error": "unexpected_error",
                "error_message": str(e),
                "error_type": type(e).__name__
            }
        )
        logger.exception(f"Unexpected error in login function: {e}")
        messages.error(request, "An unexpected error occurred. Please try again.")
        return render(request, "login/login.html")


def logout_view(request):
    """Handle user logout with logging"""
    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)

    if request.user.is_authenticated:
        username = request.user.username
        user_id = request.user.id

        KubepanelLogger.log_system_event(
            message=f"User {username} logged out",
            level="INFO",
            actor=f"user:{username}",
            user=request.user,
            data={
                "ip_address": client_ip,
                "user_agent": user_agent,
                "user_id": user_id,
                "logout_method": "manual_logout"
            }
        )

    logout(request)
    return render(request, "login/login.html")


# =============================================================================
# 2FA Helper Functions
# =============================================================================

def _generate_recovery_codes(count=RECOVERY_CODE_COUNT):
    """Generate a list of recovery codes."""
    codes = []
    for _ in range(count):
        # Generate 8-character alphanumeric code
        code = secrets.token_hex(4).upper()
        codes.append(code)
    return codes


def _hash_recovery_code(code):
    """Hash a recovery code for storage."""
    normalized = code.upper().replace('-', '').replace(' ', '')
    return hashlib.sha256(normalized.encode()).hexdigest()


def _verify_recovery_code(code, hashed_codes):
    """Verify a recovery code against stored hashes. Returns index if found, -1 otherwise."""
    code_hash = _hash_recovery_code(code)
    for i, stored_hash in enumerate(hashed_codes):
        if secrets.compare_digest(code_hash, stored_hash):
            return i
    return -1


def _format_recovery_code(code):
    """Format recovery code for display (e.g., ABCD-EFGH)."""
    code = code.upper()
    if len(code) == 8:
        return f"{code[:4]}-{code[4:]}"
    return code


def _clear_2fa_session(request):
    """Clear all 2FA-related session data."""
    for key in [PENDING_2FA_USER_ID, PENDING_2FA_TIMESTAMP, PENDING_2FA_NEXT_URL, TOTP_SETUP_SECRET]:
        request.session.pop(key, None)


def _is_2fa_session_valid(request):
    """Check if the pending 2FA session is still valid (not expired)."""
    timestamp_str = request.session.get(PENDING_2FA_TIMESTAMP)
    if not timestamp_str:
        return False

    try:
        timestamp = timezone.datetime.fromisoformat(timestamp_str)
        if timezone.is_naive(timestamp):
            timestamp = timezone.make_aware(timestamp)
        elapsed = (timezone.now() - timestamp).total_seconds()
        return elapsed < TWO_FA_SESSION_TIMEOUT
    except (ValueError, TypeError):
        return False


# =============================================================================
# 2FA Views
# =============================================================================

@csrf_protect
@require_http_methods(["GET", "POST"])
def verify_2fa(request):
    """Handle 2FA verification during login."""
    if not TOTP_AVAILABLE:
        messages.error(request, "2FA is not available. Please contact the administrator.")
        return redirect('kplogin')

    # Check for pending 2FA session
    user_id = request.session.get(PENDING_2FA_USER_ID)
    if not user_id or not _is_2fa_session_valid(request):
        _clear_2fa_session(request)
        messages.error(request, "Your session has expired. Please log in again.")
        return redirect('kplogin')

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        _clear_2fa_session(request)
        messages.error(request, "Invalid session. Please log in again.")
        return redirect('kplogin')

    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)

    if request.method == "GET":
        form = TOTPVerifyForm()
        return render(request, "login/2fa_verify.html", {
            'form': form,
            'username': user.username,
        })

    # Handle POST - verify TOTP code
    form = TOTPVerifyForm(request.POST)
    if form.is_valid():
        code = form.cleaned_data['code']
        totp = pyotp.TOTP(user.profile.totp_secret)

        if totp.verify(code, valid_window=1):
            # 2FA successful - complete login
            _clear_2fa_session(request)
            login(request, user)

            KubepanelLogger.log_system_event(
                message=f"2FA verification successful for user {user.username}",
                level="INFO",
                actor=f"user:{user.username}",
                user=user,
                data={
                    "ip_address": client_ip,
                    "user_agent": user_agent,
                    "user_id": user.id,
                    "2fa_method": "totp"
                }
            )

            # Redirect to intended URL or dashboard
            next_url = request.session.pop(PENDING_2FA_NEXT_URL, None)
            if next_url:
                return redirect(next_url)
            return redirect('kpmain')
        else:
            KubepanelLogger.log_system_event(
                message=f"Failed 2FA attempt for user {user.username}",
                level="WARNING",
                actor=f"user:{user.username}",
                user=user,
                data={
                    "ip_address": client_ip,
                    "user_agent": user_agent,
                    "user_id": user.id,
                    "2fa_method": "totp",
                    "error": "invalid_code"
                }
            )
            messages.error(request, "Invalid authentication code. Please try again.")

    return render(request, "login/2fa_verify.html", {
        'form': form,
        'username': user.username,
    })


@csrf_protect
@require_http_methods(["GET", "POST"])
def verify_2fa_recovery(request):
    """Handle 2FA verification using recovery code."""
    if not TOTP_AVAILABLE:
        messages.error(request, "2FA is not available. Please contact the administrator.")
        return redirect('kplogin')

    # Check for pending 2FA session
    user_id = request.session.get(PENDING_2FA_USER_ID)
    if not user_id or not _is_2fa_session_valid(request):
        _clear_2fa_session(request)
        messages.error(request, "Your session has expired. Please log in again.")
        return redirect('kplogin')

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        _clear_2fa_session(request)
        messages.error(request, "Invalid session. Please log in again.")
        return redirect('kplogin')

    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)

    if request.method == "GET":
        form = RecoveryCodeForm()
        return render(request, "login/2fa_recovery.html", {
            'form': form,
            'username': user.username,
        })

    # Handle POST - verify recovery code
    form = RecoveryCodeForm(request.POST)
    if form.is_valid():
        code = form.cleaned_data['code']
        backup_codes = user.profile.backup_codes or []

        code_index = _verify_recovery_code(code, backup_codes)
        if code_index >= 0:
            # Recovery code valid - remove it and complete login
            backup_codes.pop(code_index)
            user.profile.backup_codes = backup_codes
            user.profile.save()

            _clear_2fa_session(request)
            login(request, user)

            KubepanelLogger.log_system_event(
                message=f"2FA recovery code used for user {user.username}",
                level="INFO",
                actor=f"user:{user.username}",
                user=user,
                data={
                    "ip_address": client_ip,
                    "user_agent": user_agent,
                    "user_id": user.id,
                    "2fa_method": "recovery_code",
                    "remaining_codes": len(backup_codes)
                }
            )

            remaining = len(backup_codes)
            if remaining <= 2:
                messages.warning(
                    request,
                    f"You have only {remaining} recovery code(s) left. "
                    "Please generate new codes in your settings."
                )
            else:
                messages.success(request, "Recovery code accepted.")

            # Redirect to intended URL or dashboard
            next_url = request.session.pop(PENDING_2FA_NEXT_URL, None)
            if next_url:
                return redirect(next_url)
            return redirect('kpmain')
        else:
            KubepanelLogger.log_system_event(
                message=f"Invalid recovery code attempt for user {user.username}",
                level="WARNING",
                actor=f"user:{user.username}",
                user=user,
                data={
                    "ip_address": client_ip,
                    "user_agent": user_agent,
                    "user_id": user.id,
                    "2fa_method": "recovery_code",
                    "error": "invalid_code"
                }
            )
            messages.error(request, "Invalid recovery code. Please try again.")

    return render(request, "login/2fa_recovery.html", {
        'form': form,
        'username': user.username,
    })


@login_required(login_url="/")
@csrf_protect
@require_http_methods(["GET", "POST"])
def setup_2fa(request):
    """Setup 2FA for the current user (superusers only)."""
    if not TOTP_AVAILABLE:
        messages.error(request, "2FA is not available. Please contact the administrator.")
        return redirect('settings')

    if not request.user.is_superuser:
        return HttpResponseForbidden("2FA is only available for administrators.")

    # If 2FA is already enabled, redirect to settings
    if request.user.profile.totp_enabled:
        messages.info(request, "2FA is already enabled for your account.")
        return redirect('settings')

    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)

    # Generate or retrieve setup secret from session
    secret = request.session.get(TOTP_SETUP_SECRET)
    if not secret:
        secret = pyotp.random_base32()
        request.session[TOTP_SETUP_SECRET] = secret

    # Generate provisioning URI and QR code
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=request.user.username,
        issuer_name="KubePanel"
    )

    # Generate QR code as base64
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()

    if request.method == "GET":
        form = TOTPSetupConfirmForm()
        return render(request, "login/2fa_setup.html", {
            'form': form,
            'secret': secret,
            'qr_code': qr_code_base64,
        })

    # Handle POST - verify initial code to confirm setup
    form = TOTPSetupConfirmForm(request.POST)
    if form.is_valid():
        code = form.cleaned_data['code']

        if totp.verify(code, valid_window=1):
            # Generate recovery codes
            plain_codes = _generate_recovery_codes()
            hashed_codes = [_hash_recovery_code(c) for c in plain_codes]

            # Enable 2FA
            profile = request.user.profile
            profile.totp_secret = secret
            profile.totp_enabled = True
            profile.backup_codes = hashed_codes
            profile.save()

            # Clear setup secret from session
            request.session.pop(TOTP_SETUP_SECRET, None)

            KubepanelLogger.log_system_event(
                message=f"2FA enabled for user {request.user.username}",
                level="INFO",
                actor=f"user:{request.user.username}",
                user=request.user,
                data={
                    "ip_address": client_ip,
                    "user_agent": user_agent,
                    "user_id": request.user.id,
                }
            )

            # Show recovery codes
            formatted_codes = [_format_recovery_code(c) for c in plain_codes]
            messages.success(request, "Two-factor authentication has been enabled!")
            return render(request, "login/2fa_setup_complete.html", {
                'recovery_codes': formatted_codes,
            })
        else:
            messages.error(request, "Invalid code. Please scan the QR code and try again.")

    return render(request, "login/2fa_setup.html", {
        'form': form,
        'secret': secret,
        'qr_code': qr_code_base64,
    })


@login_required(login_url="/")
@csrf_protect
@require_http_methods(["GET", "POST"])
def disable_2fa(request):
    """Disable 2FA for the current user."""
    if not TOTP_AVAILABLE:
        messages.error(request, "2FA is not available.")
        return redirect('settings')

    if not request.user.is_superuser:
        return HttpResponseForbidden("2FA is only available for administrators.")

    if not request.user.profile.totp_enabled:
        messages.info(request, "2FA is not enabled for your account.")
        return redirect('settings')

    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)

    if request.method == "GET":
        form = TOTPDisableForm()
        return render(request, "login/2fa_disable.html", {'form': form})

    # Handle POST - verify code before disabling
    form = TOTPDisableForm(request.POST)
    if form.is_valid():
        code = form.cleaned_data['code']
        totp = pyotp.TOTP(request.user.profile.totp_secret)

        if totp.verify(code, valid_window=1):
            # Disable 2FA
            profile = request.user.profile
            profile.totp_enabled = False
            profile.totp_secret = None
            profile.backup_codes = []
            profile.save()

            KubepanelLogger.log_system_event(
                message=f"2FA disabled for user {request.user.username}",
                level="INFO",
                actor=f"user:{request.user.username}",
                user=request.user,
                data={
                    "ip_address": client_ip,
                    "user_agent": user_agent,
                    "user_id": request.user.id,
                }
            )

            messages.success(request, "Two-factor authentication has been disabled.")
            return redirect('settings')
        else:
            messages.error(request, "Invalid authentication code.")

    return render(request, "login/2fa_disable.html", {'form': form})


@login_required(login_url="/")
@csrf_protect
@require_http_methods(["GET", "POST"])
def regenerate_recovery_codes(request):
    """Generate new recovery codes for the current user."""
    if not TOTP_AVAILABLE:
        messages.error(request, "2FA is not available.")
        return redirect('settings')

    if not request.user.is_superuser:
        return HttpResponseForbidden("2FA is only available for administrators.")

    if not request.user.profile.totp_enabled:
        messages.info(request, "2FA is not enabled for your account.")
        return redirect('settings')

    client_ip = get_client_ip(request)
    user_agent = get_user_agent(request)

    if request.method == "GET":
        form = TOTPVerifyForm()
        return render(request, "login/2fa_regenerate_codes.html", {'form': form})

    # Handle POST - verify code before generating new codes
    form = TOTPVerifyForm(request.POST)
    if form.is_valid():
        code = form.cleaned_data['code']
        totp = pyotp.TOTP(request.user.profile.totp_secret)

        if totp.verify(code, valid_window=1):
            # Generate new recovery codes
            plain_codes = _generate_recovery_codes()
            hashed_codes = [_hash_recovery_code(c) for c in plain_codes]

            profile = request.user.profile
            profile.backup_codes = hashed_codes
            profile.save()

            KubepanelLogger.log_system_event(
                message=f"Recovery codes regenerated for user {request.user.username}",
                level="INFO",
                actor=f"user:{request.user.username}",
                user=request.user,
                data={
                    "ip_address": client_ip,
                    "user_agent": user_agent,
                    "user_id": request.user.id,
                }
            )

            formatted_codes = [_format_recovery_code(c) for c in plain_codes]
            messages.success(request, "New recovery codes have been generated!")
            return render(request, "login/2fa_setup_complete.html", {
                'recovery_codes': formatted_codes,
                'regenerated': True,
            })
        else:
            messages.error(request, "Invalid authentication code.")

    return render(request, "login/2fa_regenerate_codes.html", {'form': form})
