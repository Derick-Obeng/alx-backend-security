from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from ip_tracking.models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ['/admin', '/login']

@shared_task
def flag_suspicious_ips():
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)
    # Find IPs with >100 requests in the last hour
    ip_counts = (RequestLog.objects
                 .filter(timestamp__gte=one_hour_ago)
                 .values('ip_address')
                 .annotate(count=models.Count('id'))
                 .filter(count__gt=100))
    for entry in ip_counts:
        SuspiciousIP.objects.get_or_create(
            ip_address=entry['ip_address'],
            reason='High request volume (>100/hr)'
        )
    # Find IPs accessing sensitive paths
    suspicious_logs = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago,
        path__in=SENSITIVE_PATHS
    )
    for log in suspicious_logs:
        SuspiciousIP.objects.get_or_create(
            ip_address=log.ip_address,
            reason=f"Accessed sensitive path: {log.path}"
        )
