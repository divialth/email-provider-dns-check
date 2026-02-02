"""DNS resolver wrapper used by the DNS checker.

The resolver is intentionally thin so it can be replaced in tests.
"""

from __future__ import annotations

import logging
from typing import List, Optional

try:
    import dns.exception
    import dns.resolver
except ImportError as exc:  # pragma: no cover - handled at runtime
    raise SystemExit("dnspython is required. Install with `pip install dnspython`.") from exc

LOGGER = logging.getLogger(__name__)


class DnsLookupError(RuntimeError):
    """Raised when a DNS lookup fails."""

    def __init__(self, record_type: str, name: str, error: Exception) -> None:
        """Initialize a DNS lookup error.

        Args:
            record_type (str): DNS record type being queried.
            name (str): DNS name that failed to resolve.
            error (Exception): Underlying exception.
        """
        super().__init__(f"{record_type} lookup failed for {name}: {error}")
        self.record_type = record_type
        self.name = name
        self.error = error


class DnsResolver:
    """Perform DNS lookups using dnspython."""

    def __init__(self) -> None:
        """Initialize the DNS resolver."""
        self._resolver = dns.resolver.Resolver()

    def get_mx(self, domain: str) -> List[tuple[str, int]]:
        """Resolve MX records for a domain.

        Args:
            domain (str): Domain name to query.

        Returns:
            List[tuple[str, int]]: List of (host, priority) tuples.

        Raises:
            DnsLookupError: If a DNS error occurs during lookup.
        """
        try:
            answers = self._resolver.resolve(domain, "MX")
            records: List[tuple[str, int]] = []
            for rdata in answers:
                host = str(rdata.exchange).lower().rstrip(".") + "."
                records.append((host, int(rdata.preference)))
            return records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException as err:
            LOGGER.warning("MX lookup failed for %s: %s", domain, err)
            raise DnsLookupError("MX", domain, err) from err

    def get_txt(self, domain: str) -> List[str]:
        """Resolve TXT records for a domain.

        Args:
            domain (str): Domain name to query.

        Returns:
            List[str]: TXT record strings.

        Raises:
            DnsLookupError: If a DNS error occurs during lookup.
        """
        try:
            answers = self._resolver.resolve(domain, "TXT")
            records: List[str] = []
            for rdata in answers:
                record = "".join(
                    part.decode() if isinstance(part, bytes) else str(part)
                    for part in rdata.strings
                )
                records.append(record)
            return records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException as err:
            LOGGER.warning("TXT lookup failed for %s: %s", domain, err)
            raise DnsLookupError("TXT", domain, err) from err

    def get_cname(self, name: str) -> Optional[str]:
        """Resolve a CNAME record for a DNS name.

        Args:
            name (str): DNS name to query.

        Returns:
            Optional[str]: CNAME target with trailing dot or None if not found.

        Raises:
            DnsLookupError: If a DNS error occurs during lookup.
        """
        try:
            answers = self._resolver.resolve(name, "CNAME")
            target = str(answers[0].target).lower().rstrip(".") + "."
            return target
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except dns.exception.DNSException as err:
            LOGGER.warning("CNAME lookup failed for %s: %s", name, err)
            raise DnsLookupError("CNAME", name, err) from err

    def get_srv(self, name: str) -> List[tuple[int, int, int, str]]:
        """Resolve SRV records for a DNS name.

        Args:
            name (str): DNS name to query.

        Returns:
            List[tuple[int, int, int, str]]: (priority, weight, port, target) tuples.

        Raises:
            DnsLookupError: If a DNS error occurs during lookup.
        """
        try:
            answers = self._resolver.resolve(name, "SRV")
            records: List[tuple[int, int, int, str]] = []
            for rdata in answers:
                target = str(rdata.target).lower().rstrip(".") + "."
                records.append((int(rdata.priority), int(rdata.weight), int(rdata.port), target))
            return records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException as err:
            LOGGER.warning("SRV lookup failed for %s: %s", name, err)
            raise DnsLookupError("SRV", name, err) from err
