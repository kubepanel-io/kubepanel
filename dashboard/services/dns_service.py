import logging
import time
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass
from django.db import transaction
from cloudflare import Cloudflare

logger = logging.getLogger(__name__)

@dataclass
class DNSRecordData:
    """Data class for DNS record information"""
    record_type: str
    name: str
    content: str
    ttl: int = 1
    proxied: bool = False
    priority: Optional[int] = None

class CloudflareAPIException(Exception):
    """Custom exception for Cloudflare API errors"""
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

class CloudflareDNSService:
    """Service class for managing Cloudflare DNS operations"""

    def __init__(self, api_token: str):
        self.client = Cloudflare(api_token=api_token)
        self.max_retries = 3
        self.retry_delay = 1  # seconds

    def _handle_cloudflare_error(self, error) -> CloudflareAPIException:
        """Convert various Cloudflare errors to our custom exception"""
        if hasattr(error, 'status_code'):
            status_code = error.status_code
        else:
            status_code = None

        if hasattr(error, 'message'):
            message = error.message
        else:
            message = str(error)

        return CloudflareAPIException(message, status_code)

    def _retry_api_call(self, func, *args, **kwargs):
        """Retry API calls with exponential backoff"""
        last_exception = None

        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e

                # Check if it's a client error (4xx) - don't retry these
                if hasattr(e, 'status_code') and e.status_code and 400 <= e.status_code < 500:
                    logger.error(f"Client error, not retrying: {e}")
                    raise self._handle_cloudflare_error(e)

                if attempt < self.max_retries - 1:
                    delay = self.retry_delay * (2 ** attempt)
                    logger.warning(f"API call failed, retrying in {delay}s: {e}")
                    time.sleep(delay)
                else:
                    logger.error(f"API call failed after {self.max_retries} attempts: {e}")

        raise self._handle_cloudflare_error(last_exception)

    def get_account_id(self) -> str:
        """Get the first available account ID"""
        try:
            accounts_response = self._retry_api_call(self.client.accounts.list)
            # Handle different response formats
            if hasattr(accounts_response, 'result'):
                accounts = accounts_response.result
            else:
                accounts = accounts_response

            if not accounts:
                raise ValueError("No accounts found for this token")
            return accounts[0].id
        except Exception as e:
            logger.error(f"Failed to get account ID: {e}")
            raise

    def create_zone(self, zone_name: str) -> str:
        """Create a new DNS zone in Cloudflare"""
        try:
            account_id = self.get_account_id()

            result = self._retry_api_call(
                self.client.zones.create,
                account={"id": account_id},
                name=zone_name,
                type="full"
            )

            zone_id = result.id if hasattr(result, 'id') else result['id']
            logger.info(f"Created Cloudflare zone: {zone_name} (ID: {zone_id})")
            return zone_id

        except Exception as e:
            logger.error(f"Failed to create zone {zone_name}: {e}")
            raise

    def create_dns_record(self, zone_id: str, record_data: DNSRecordData) -> Any:
        """Create a single DNS record"""
        try:
            record_params = {
                'zone_id': zone_id,
                'type': record_data.record_type,
                'name': record_data.name,
                'content': record_data.content,
                'ttl': record_data.ttl,
                'proxied': record_data.proxied,
            }

            # Only add priority for record types that support it
            if record_data.priority is not None and record_data.record_type in ['MX', 'SRV']:
                record_params['priority'] = record_data.priority

            response = self._retry_api_call(
                self.client.dns.records.create,
                **record_params
            )

            logger.info(f"Created DNS record: {record_data.record_type} {record_data.name} -> {record_data.content}")
            return response

        except Exception as e:
            logger.error(f"Failed to create DNS record {record_data.name}: {e}")
            raise

    def create_multiple_dns_records(self, zone_id: str, records: List[DNSRecordData]) -> List[Tuple[DNSRecordData, Any, Optional[Exception]]]:
        """Create multiple DNS records, returning results and any errors"""
        results = []

        for record_data in records:
            try:
                cf_record = self.create_dns_record(zone_id, record_data)
                results.append((record_data, cf_record, None))
            except Exception as e:
                logger.error(f"Failed to create DNS record {record_data.name}: {e}")
                results.append((record_data, None, e))

        return results

class DNSZoneManager:
    """High-level manager for DNS zones and records"""

    def __init__(self, user_token):
        self.user_token = user_token
        self.dns_service = CloudflareDNSService(user_token.api_token)

    @transaction.atomic
    def create_zone_with_records(self, zone_name: str, dns_records: List[DNSRecordData]) -> Tuple[Any, List[Any]]:
        """Create a zone and its DNS records atomically"""
        # Import here to avoid circular imports
        from ..models import DNSZone, DNSRecord

        try:
            # Create zone in Cloudflare
            cf_zone_id = self.dns_service.create_zone(zone_name)

            # Create zone in database
            zone_obj = DNSZone.objects.create(
                name=zone_name,
                zone_id=cf_zone_id,
                token=self.user_token
            )

            # Create DNS records if any provided
            created_records = []
            if dns_records:
                cf_results = self.dns_service.create_multiple_dns_records(cf_zone_id, dns_records)

                failed_records = []

                for record_data, cf_record, error in cf_results:
                    if error:
                        failed_records.append((record_data, error))
                        continue

                    # Extract record ID from response
                    record_id = cf_record.id if hasattr(cf_record, 'id') else cf_record.get('id')

                    # Save successful records to database
                    db_record = DNSRecord.objects.create(
                        zone=zone_obj,
                        record_type=record_data.record_type,
                        name=record_data.name,
                        content=record_data.content,
                        ttl=record_data.ttl,
                        proxied=record_data.proxied,
                        priority=record_data.priority,
                        cf_record_id=record_id
                    )
                    created_records.append(db_record)

                if failed_records:
                    error_msg = f"Failed to create {len(failed_records)} DNS records"
                    logger.warning(error_msg)
                    # You might want to raise an exception here depending on your requirements

            logger.info(f"Successfully created zone '{zone_name}' with {len(created_records)} DNS records")
            return zone_obj, created_records

        except Exception as e:
            logger.error(f"Failed to create zone '{zone_name}': {e}")
            raise

def generate_email_dns_records(domain_name: str, cluster_ips: List[str]) -> List[DNSRecordData]:
    """Generate standard email DNS records for a domain"""
    records = []

    # SPF Record
    spf_content = "v=spf1 " + " ".join(f"ip4:{ip}" for ip in cluster_ips) + " -all"
    records.append(DNSRecordData(
        record_type="TXT",
        name="@",
        content=spf_content
    ))

    # DMARC Record
    records.append(DNSRecordData(
        record_type="TXT",
        name="_dmarc",
        content="v=DMARC1; p=none;"
    ))

    # A Records and MX Records for each IP
    for i, ip in enumerate(cluster_ips):
        # A records
        records.extend([
            DNSRecordData(record_type="A", name="@", content=ip),
            DNSRecordData(record_type="A", name="www", content=ip),
            DNSRecordData(record_type="A", name=f"mx{i}", content=ip),
        ])

        # MX record
        records.append(DNSRecordData(
            record_type="MX",
            name="@",
            content=f"mx{i}.{domain_name}",
            priority=i
        ))

    return records
