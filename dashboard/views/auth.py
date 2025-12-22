"""
Authentication views (login, logout)
"""
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.utils import timezone

import logging

from dashboard.services.logging_service import KubepanelLogger
from .utils import get_client_ip, get_user_agent

logger = logging.getLogger("django")


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
                # Successful login
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
