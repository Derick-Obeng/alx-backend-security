from .models import RequestLog, BlockedIP
from ipgeolocation import IpGeolocationAPI
from django.core.cache import cache
from django.utils.deprecation import MiddlewareMixin

from django.http import HttpResponseForbidden

class RequestLogMiddleware(MiddlewareMixin):
    def process_request(self, request):
        ip_address = request.META.get('REMOTE_ADDR')
        path = request.path
        country = None
        city = None
        cache_key = f"geo_{ip_address}"
        geo_data = cache.get(cache_key)
        if geo_data:
            country = geo_data.get('country')
            city = geo_data.get('city')
        else:
            api = IpGeolocationAPI()
            try:
                response = api.get_geolocation_data(ip_address)
                country = response.get('country_name')
                city = response.get('city')
                cache.set(cache_key, {'country': country, 'city': city}, 60 * 60 * 24)  # 24 hours
            except Exception:
                country = None
                city = None
        # Block request if IP is blacklisted
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Forbidden: Your IP is blocked.")
        RequestLog.objects.create(
            ip_address=ip_address,
            path=path,
            country=country,
            city=city
        )
        # Optionally, log to console
        print(f"IP: {ip_address}, Path: {path}, Country: {country}, City: {city}")
