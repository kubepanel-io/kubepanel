from django.core.cache import cache
from django.http import HttpResponse
from dashboard.services.logging_service import KubepanelLogger
import time

class LoginRateLimitMiddleware:
    """
    Middleware to rate limit login attempts per IP address
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.max_attempts = 5  # Max attempts per time window
        self.time_window = 300  # 5 minutes in seconds
        self.lockout_time = 900  # 15 minutes lockout
    
    def __call__(self, request):
        # Only apply to login endpoint
        if request.path == '/dashboard/' and request.method == 'POST':
            client_ip = self.get_client_ip(request)
            
            # Check if IP is currently locked out
            lockout_key = f"login_lockout:{client_ip}"
            if cache.get(lockout_key):
                KubepanelLogger.log_system_event(
                    message=f"Login attempt from locked out IP {client_ip}",
                    level="WARNING",
                    actor="rate_limiter",
                    data={
                        "ip_address": client_ip,
                        "reason": "rate_limit_lockout"
                    }
                )
                return HttpResponse(
                    "Too many failed login attempts. Please try again later.",
                    status=429
                )
            
            # Check current attempt count
            attempts_key = f"login_attempts:{client_ip}"
            attempts = cache.get(attempts_key, 0)
            
            if attempts >= self.max_attempts:
                # Lock out the IP
                cache.set(lockout_key, True, self.lockout_time)
                cache.delete(attempts_key)
                
                KubepanelLogger.log_system_event(
                    message=f"IP {client_ip} locked out due to excessive login attempts",
                    level="ERROR",
                    actor="rate_limiter",
                    data={
                        "ip_address": client_ip,
                        "attempts": attempts,
                        "lockout_duration": self.lockout_time
                    }
                )
                
                return HttpResponse(
                    "Too many failed login attempts. Your IP has been temporarily blocked.",
                    status=429
                )
            
            # Process the request
            response = self.get_response(request)
            
            # If login failed (redirect to login page with error), increment counter
            if (response.status_code == 200 and 
                hasattr(response, 'content') and 
                b'Invalid' in response.content):
                
                cache.set(attempts_key, attempts + 1, self.time_window)
            
            # If login succeeded (redirect), clear the counter
            elif response.status_code == 302:
                cache.delete(attempts_key)
            
            return response
        
        return self.get_response(request)
    
    def get_client_ip(self, request):
        """Get the real IP address of the client"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'Unknown')
        return ip

