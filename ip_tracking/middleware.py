from .models import RequestLog, BlockedIP
from django.utils.deprecation import MiddlewareMixin

from django.http import HttpResponseForbidden

class RequestLogMiddleware(MiddlewareMixin):
    def process_request(self, request):
        ip_address = request.META.get('REMOTE_ADDR')
        path = request.path
        # Block request if IP is blacklisted
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Forbidden: Your IP is blocked.")
        RequestLog.objects.create(
            ip_address=ip_address,
            path=path
        )
        # Optionally, log to console
        print(f"IP: {ip_address}, Path: {path}")
