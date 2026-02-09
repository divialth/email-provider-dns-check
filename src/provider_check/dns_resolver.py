"""DNS resolver wrapper used by the DNS checker.

The resolver is intentionally thin so it can be replaced in tests.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Iterable, List, Optional

try:
    import dns.exception
    import dns.flags
    import dns.resolver
except ImportError as exc:  # pragma: no cover - handled at runtime
    raise SystemExit("dnspython is required. Install with `pip install dnspython`.") from exc

LOGGER = logging.getLogger(__name__)


def _is_ip_address(value: str) -> bool:
    """Check whether a string is a valid IP address.

    Args:
        value (str): Input string to validate.

    Returns:
        bool: True if the value is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _append_unique(items: List[str], value: str) -> None:
    """Append a value to a list if it is not already present.

    Args:
        items (List[str]): Target list to mutate.
        value (str): Value to append when missing.
    """
    if value in items:
        return
    items.append(value)


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

    supports_live_tls_verification = True

    def __init__(
        self,
        nameservers: Optional[Iterable[str]] = None,
        timeout: Optional[float] = None,
        lifetime: Optional[float] = None,
        use_tcp: bool = False,
    ) -> None:
        """Initialize the DNS resolver.

        Args:
            nameservers (Optional[Iterable[str]]): Optional nameserver IPs or hostnames.
            timeout (Optional[float]): Per-query timeout in seconds.
            lifetime (Optional[float]): Total timeout across retries in seconds.
            use_tcp (bool): Whether to force TCP for DNS lookups.

        Raises:
            ValueError: If a nameserver is invalid or cannot be resolved.
        """
        self._resolver = dns.resolver.Resolver()
        if timeout is not None:
            if timeout <= 0:
                raise ValueError("DNS timeout must be a positive number")
            self._resolver.timeout = timeout
        if lifetime is not None:
            if lifetime <= 0:
                raise ValueError("DNS lifetime must be a positive number")
            self._resolver.lifetime = lifetime
        self._resolver.use_tcp = bool(use_tcp)
        if nameservers:
            self._resolver.nameservers = self._resolve_nameservers(nameservers)

    def _resolve_nameservers(self, nameservers: Iterable[str]) -> List[str]:
        """Resolve nameserver hostnames into IP addresses.

        Args:
            nameservers (Iterable[str]): Nameserver IPs or hostnames.

        Returns:
            List[str]: Resolved IP addresses in input order.

        Raises:
            ValueError: If a nameserver is invalid or cannot be resolved.
        """
        resolved: List[str] = []
        for server in nameservers:
            server_text = str(server).strip()
            if not server_text:
                raise ValueError("DNS server entries cannot be empty")
            if _is_ip_address(server_text):
                _append_unique(resolved, server_text)
                continue
            addresses = self._resolve_nameserver_hostname(server_text)
            if not addresses:
                raise ValueError(f"DNS server '{server_text}' did not resolve to any IP addresses")
            for address in addresses:
                _append_unique(resolved, address)
        if not resolved:
            raise ValueError("At least one DNS server must be provided")
        return resolved

    def _resolve_nameserver_hostname(self, hostname: str) -> List[str]:
        """Resolve a nameserver hostname into A/AAAA records.

        Args:
            hostname (str): Hostname to resolve.

        Returns:
            List[str]: Resolved IP addresses.

        Raises:
            ValueError: If the hostname cannot be resolved due to DNS errors.
        """
        addresses: List[str] = []
        for record_type in ("A", "AAAA"):
            try:
                answers = self._resolver.resolve(hostname, record_type)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except dns.exception.DNSException as err:
                raise ValueError(f"DNS server '{hostname}' could not be resolved: {err}") from err
            for rdata in answers:
                address = str(rdata.address)
                addresses.append(address)
        if addresses:
            LOGGER.debug("Resolved DNS server %s to %s", hostname, addresses)
        return addresses

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

    def get_caa(self, name: str) -> List[tuple[int, str, str]]:
        """Resolve CAA records for a DNS name.

        Args:
            name (str): DNS name to query.

        Returns:
            List[tuple[int, str, str]]: (flags, tag, value) tuples.

        Raises:
            DnsLookupError: If a DNS error occurs during lookup.
        """
        try:
            answers = self._resolver.resolve(name, "CAA")
            records: List[tuple[int, str, str]] = []
            for rdata in answers:
                value = rdata.value
                if isinstance(value, bytes):
                    value_text = value.decode()
                else:
                    value_text = str(value)
                records.append((int(rdata.flags), str(rdata.tag), value_text))
            return records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException as err:
            LOGGER.warning("CAA lookup failed for %s: %s", name, err)
            raise DnsLookupError("CAA", name, err) from err

    def _parse_tlsa_records(self, answers: object) -> List[tuple[int, int, int, str]]:
        """Parse TLSA answers into normalized tuples.

        Args:
            answers (object): dnspython answer iterable.

        Returns:
            List[tuple[int, int, int, str]]: Parsed TLSA tuples.
        """
        records: List[tuple[int, int, int, str]] = []
        for rdata in answers:
            usage = int(rdata.usage)
            selector = int(rdata.selector)
            matching_type_value = (
                rdata.matching_type if hasattr(rdata, "matching_type") else rdata.mtype
            )
            matching_type = int(matching_type_value)
            certificate_association = (
                rdata.certificate_association
                if hasattr(rdata, "certificate_association")
                else rdata.cert
            )
            if isinstance(certificate_association, bytes):
                certificate_association_text = certificate_association.hex()
            else:
                certificate_association_text = str(certificate_association)
            records.append(
                (
                    usage,
                    selector,
                    matching_type,
                    "".join(certificate_association_text.split()).lower(),
                )
            )
        return records

    def get_tlsa_with_status(
        self, name: str
    ) -> tuple[List[tuple[int, int, int, str]], Optional[bool]]:
        """Resolve TLSA records and return DNSSEC authentication status.

        Args:
            name (str): DNS name to query.

        Returns:
            tuple[List[tuple[int, int, int, str]], Optional[bool]]: Parsed TLSA tuples and whether
                the response was authenticated by DNSSEC (AD bit). ``None`` means no TLSA answer.

        Raises:
            DnsLookupError: If a DNS error occurs during lookup.
        """
        try:
            answers = self._resolver.resolve(name, "TLSA")
            response = getattr(answers, "response", None)
            authenticated = bool(response.flags & dns.flags.AD) if response else False
            return self._parse_tlsa_records(answers), authenticated
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return [], None
        except dns.exception.DNSException as err:
            LOGGER.warning("TLSA lookup failed for %s: %s", name, err)
            raise DnsLookupError("TLSA", name, err) from err

    def get_tlsa(self, name: str) -> List[tuple[int, int, int, str]]:
        """Resolve TLSA records for a DNS name.

        Args:
            name (str): DNS name to query.

        Returns:
            List[tuple[int, int, int, str]]: (usage, selector, matching_type,
                certificate_association) tuples.

        Raises:
            DnsLookupError: If a DNS error occurs during lookup.
        """
        records, _authenticated = self.get_tlsa_with_status(name)
        return records

    def get_a(self, name: str) -> List[str]:
        """Resolve A records for a DNS name.

        Args:
            name (str): DNS name to query.

        Returns:
            List[str]: IPv4 address strings.

        Raises:
            DnsLookupError: If a DNS error occurs during lookup.
        """
        try:
            answers = self._resolver.resolve(name, "A")
            return [str(rdata.address) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException as err:
            LOGGER.warning("A lookup failed for %s: %s", name, err)
            raise DnsLookupError("A", name, err) from err

    def get_aaaa(self, name: str) -> List[str]:
        """Resolve AAAA records for a DNS name.

        Args:
            name (str): DNS name to query.

        Returns:
            List[str]: IPv6 address strings.

        Raises:
            DnsLookupError: If a DNS error occurs during lookup.
        """
        try:
            answers = self._resolver.resolve(name, "AAAA")
            return [str(rdata.address) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException as err:
            LOGGER.warning("AAAA lookup failed for %s: %s", name, err)
            raise DnsLookupError("AAAA", name, err) from err

    def get_ptr(self, name: str) -> List[str]:
        """Resolve PTR records for a DNS name.

        Args:
            name (str): DNS name to query.

        Returns:
            List[str]: PTR target hostnames.

        Raises:
            DnsLookupError: If a DNS error occurs during lookup.
        """
        try:
            answers = self._resolver.resolve(name, "PTR")
            records: List[str] = []
            for rdata in answers:
                target = str(rdata.target).lower().rstrip(".") + "."
                records.append(target)
            return records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException as err:
            LOGGER.warning("PTR lookup failed for %s: %s", name, err)
            raise DnsLookupError("PTR", name, err) from err


class CachingResolver:
    """Cache DNS lookup results for a resolver instance.

    Attributes:
        resolver (object): Wrapped resolver providing DNS lookup methods.
    """

    def __init__(self, resolver: object) -> None:
        """Initialize the caching resolver wrapper.

        Args:
            resolver (object): Base resolver providing DNS lookup methods.
        """
        self._resolver = resolver
        self._cache: dict[tuple[str, str], object] = {}
        self.supports_live_tls_verification = bool(
            getattr(resolver, "supports_live_tls_verification", False)
        )

    def _cached(self, key: tuple[str, str], fn, name: str):
        """Execute a lookup and cache the result or exception.

        Args:
            key (tuple[str, str]): Cache key for the lookup.
            fn (callable): Lookup function to invoke.
            name (str): Lookup name.

        Returns:
            object: Lookup result.

        Raises:
            Exception: Any exception raised by the lookup function.
        """
        if key in self._cache:
            cached = self._cache[key]
            if isinstance(cached, Exception):
                raise cached
            return cached
        try:
            result = fn(name)
        except Exception as exc:
            self._cache[key] = exc
            raise
        self._cache[key] = result
        return result

    def get_mx(self, domain: str):
        """Resolve MX records with caching.

        Args:
            domain (str): Domain name to query.

        Returns:
            list: MX record tuples.
        """
        return self._cached(("MX", domain), self._resolver.get_mx, domain)

    def get_txt(self, domain: str):
        """Resolve TXT records with caching.

        Args:
            domain (str): Domain name to query.

        Returns:
            list: TXT record values.
        """
        return self._cached(("TXT", domain), self._resolver.get_txt, domain)

    def get_cname(self, name: str):
        """Resolve CNAME records with caching.

        Args:
            name (str): DNS name to query.

        Returns:
            object: CNAME result.
        """
        return self._cached(("CNAME", name), self._resolver.get_cname, name)

    def get_srv(self, name: str):
        """Resolve SRV records with caching.

        Args:
            name (str): DNS name to query.

        Returns:
            list: SRV record tuples.
        """
        return self._cached(("SRV", name), self._resolver.get_srv, name)

    def get_caa(self, name: str):
        """Resolve CAA records with caching.

        Args:
            name (str): DNS name to query.

        Returns:
            list: CAA record tuples.
        """
        return self._cached(("CAA", name), self._resolver.get_caa, name)

    def get_tlsa(self, name: str):
        """Resolve TLSA records with caching.

        Args:
            name (str): DNS name to query.

        Returns:
            list: TLSA record tuples.
        """
        return self._cached(("TLSA", name), self._resolver.get_tlsa, name)

    def get_tlsa_with_status(self, name: str):
        """Resolve TLSA records and DNSSEC status with caching.

        Args:
            name (str): DNS name to query.

        Returns:
            tuple: TLSA record tuples and DNSSEC authentication status.
        """
        return self._cached(("TLSA_STATUS", name), self._resolver.get_tlsa_with_status, name)

    def get_a(self, name: str):
        """Resolve A records with caching.

        Args:
            name (str): DNS name to query.

        Returns:
            list: A record values.
        """
        return self._cached(("A", name), self._resolver.get_a, name)

    def get_aaaa(self, name: str):
        """Resolve AAAA records with caching.

        Args:
            name (str): DNS name to query.

        Returns:
            list: AAAA record values.
        """
        return self._cached(("AAAA", name), self._resolver.get_aaaa, name)

    def get_ptr(self, name: str):
        """Resolve PTR records with caching.

        Args:
            name (str): DNS name to query.

        Returns:
            list: PTR target values.
        """
        return self._cached(("PTR", name), self._resolver.get_ptr, name)
