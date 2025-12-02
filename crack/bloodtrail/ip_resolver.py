"""
BloodHound Trail - IP Address Resolution

Provides DNS-based IP resolution for computer hostnames with caching
and parallel batch processing. Used during BloodHound import to enrich
Neo4j with IP addresses for command generation.

Usage:
    # System DNS resolution (default)
    resolver = IPResolver(timeout=2.0, max_workers=20)

    # DC-based DNS resolution (uses Domain Controller as DNS server)
    resolver = IPResolver(timeout=2.0, max_workers=20, dc_ip="192.168.50.70")

    # Single resolution
    ip = resolver.resolve("FILES04.CORP.COM")  # -> "10.0.0.15" or None

    # Batch resolution (parallel)
    computers = ["FILES04.CORP.COM", "CLIENT74.CORP.COM", "DC1.CORP.COM"]
    ip_map = resolver.resolve_batch(computers)
    # -> {"FILES04.CORP.COM": "10.0.0.15", "CLIENT74.CORP.COM": "10.0.0.23", ...}
"""

import socket
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set
from contextlib import contextmanager

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


class TimeoutError(Exception):
    """DNS resolution timed out."""
    pass


@contextmanager
def timeout(seconds: float):
    """Context manager for timeout with signal (Unix-only)."""
    def _timeout_handler(signum, frame):
        raise TimeoutError(f"Operation timed out after {seconds}s")

    # Set the signal handler
    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)

    try:
        yield
    finally:
        # Restore old handler and cancel alarm
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)


class IPResolver:
    """
    DNS-based IP address resolver with caching and parallel batch processing.

    Features:
    - Parallel resolution using ThreadPoolExecutor
    - Per-lookup timeout to prevent hanging
    - In-memory cache to avoid duplicate lookups
    - IPv4 focus (AF_INET) for pentesting tool compatibility
    - Graceful error handling (returns None on failure)
    - Optional DC-based DNS resolution using dnspython

    Attributes:
        timeout: DNS lookup timeout in seconds (default: 2.0)
        max_workers: Number of parallel resolution threads (default: 20)
        dc_ip: Optional Domain Controller IP for DNS queries (default: None)
    """

    def __init__(self, timeout: float = 2.0, max_workers: int = 20, dc_ip: Optional[str] = None):
        """
        Initialize IP resolver with timeout and concurrency settings.

        Args:
            timeout: DNS lookup timeout per hostname (seconds)
            max_workers: Number of parallel threads for batch resolution
            dc_ip: Optional DC IP address to use as DNS server (requires dnspython)
        """
        self._cache: Dict[str, Optional[str]] = {}
        self.timeout = timeout
        self.max_workers = max_workers
        self.dc_ip = dc_ip
        self._stats = {
            "resolved": 0,
            "failed": 0,
            "cached": 0,
        }

        # Configure dnspython resolver if DC IP provided
        if self.dc_ip and HAS_DNSPYTHON:
            self._dns_resolver = dns.resolver.Resolver()
            self._dns_resolver.nameservers = [self.dc_ip]
            self._dns_resolver.timeout = timeout
            self._dns_resolver.lifetime = timeout
        else:
            self._dns_resolver = None

    def resolve(self, fqdn: str) -> Optional[str]:
        """
        Resolve a single FQDN to IPv4 address.

        Uses dnspython with custom DNS server if dc_ip provided, otherwise
        falls back to socket.getaddrinfo() with system DNS. Results are cached.

        Args:
            fqdn: Fully qualified domain name (e.g., "FILES04.CORP.COM")

        Returns:
            IPv4 address string (e.g., "10.0.0.15") or None on failure

        Examples:
            >>> resolver = IPResolver()
            >>> resolver.resolve("localhost")
            '127.0.0.1'
            >>> resolver = IPResolver(dc_ip="192.168.50.70")
            >>> resolver.resolve("DC1.CORP.COM")
            '192.168.50.70'
        """
        if not fqdn:
            return None

        # Check cache
        if fqdn in self._cache:
            self._stats["cached"] += 1
            return self._cache[fqdn]

        # Try DC-based DNS resolution first
        if self._dns_resolver:
            ip = self._resolve_with_dnspython(fqdn)
            if ip:
                return ip
            # If dnspython fails, fall through to socket resolution

        # Fallback to system DNS resolution
        return self._resolve_with_socket(fqdn)

    def _resolve_with_dnspython(self, fqdn: str) -> Optional[str]:
        """
        Resolve FQDN using dnspython with custom DNS server (DC).

        Args:
            fqdn: Fully qualified domain name

        Returns:
            IPv4 address or None on failure
        """
        try:
            # Query for A records
            answers = self._dns_resolver.resolve(fqdn, 'A')
            if answers:
                # Get first IPv4 address
                ip_address = str(answers[0])
                self._cache[fqdn] = ip_address
                self._stats["resolved"] += 1
                return ip_address
        except Exception:
            # DNS query failed (NXDOMAIN, timeout, etc.)
            pass

        # Cache failure
        self._cache[fqdn] = None
        self._stats["failed"] += 1
        return None

    def _resolve_with_socket(self, fqdn: str) -> Optional[str]:
        """
        Resolve FQDN using socket.getaddrinfo() with system DNS.

        Args:
            fqdn: Fully qualified domain name

        Returns:
            IPv4 address or None on failure
        """
        try:
            with timeout(self.timeout):
                # getaddrinfo returns: [(family, type, proto, canonname, sockaddr), ...]
                # sockaddr for IPv4 is (host, port)
                result = socket.getaddrinfo(
                    fqdn,
                    None,  # port (not needed for DNS lookup)
                    socket.AF_INET,  # IPv4 only
                    socket.SOCK_STREAM  # TCP (most common)
                )

                if result:
                    # Extract first IPv4 address
                    ip_address = result[0][4][0]  # result[0][4] = sockaddr, [0] = host
                    self._cache[fqdn] = ip_address
                    self._stats["resolved"] += 1
                    return ip_address
                else:
                    # No results
                    self._cache[fqdn] = None
                    self._stats["failed"] += 1
                    return None

        except (socket.gaierror, socket.herror, socket.timeout, TimeoutError, OSError):
            # DNS resolution failed (timeout, no such host, network error, etc.)
            self._cache[fqdn] = None
            self._stats["failed"] += 1
            return None

    def resolve_batch(self, fqdns: List[str]) -> Dict[str, Optional[str]]:
        """
        Resolve multiple FQDNs in parallel.

        Uses ThreadPoolExecutor to resolve hostnames concurrently.
        Much faster than sequential resolution for large batches.

        Args:
            fqdns: List of fully qualified domain names

        Returns:
            Dict mapping FQDN -> IP address (or None if failed)

        Examples:
            >>> resolver = IPResolver(max_workers=10)
            >>> computers = ["DC1.CORP.COM", "FILES04.CORP.COM", "CLIENT74.CORP.COM"]
            >>> ip_map = resolver.resolve_batch(computers)
            >>> ip_map["DC1.CORP.COM"]
            '192.168.50.70'
        """
        results: Dict[str, Optional[str]] = {}

        # Remove empty strings and duplicates
        unique_fqdns = [fqdn for fqdn in set(fqdns) if fqdn]

        if not unique_fqdns:
            return results

        # Check cache first (avoid thread pool for cached entries)
        to_resolve = []
        for fqdn in unique_fqdns:
            if fqdn in self._cache:
                results[fqdn] = self._cache[fqdn]
                self._stats["cached"] += 1
            else:
                to_resolve.append(fqdn)

        # Resolve uncached entries in parallel
        if to_resolve:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all resolution tasks
                future_to_fqdn = {
                    executor.submit(self.resolve, fqdn): fqdn
                    for fqdn in to_resolve
                }

                # Collect results as they complete
                for future in as_completed(future_to_fqdn):
                    fqdn = future_to_fqdn[future]
                    try:
                        ip = future.result()
                        results[fqdn] = ip
                    except Exception:
                        # Should not happen (resolve() handles exceptions)
                        # But defensive programming
                        results[fqdn] = None
                        self._cache[fqdn] = None

        return results

    def get_stats(self) -> Dict[str, int]:
        """
        Get resolution statistics.

        Returns:
            Dict with keys: resolved, failed, cached
        """
        return dict(self._stats)

    def clear_cache(self):
        """Clear the resolution cache."""
        self._cache.clear()

    def get_cache_size(self) -> int:
        """Get number of entries in cache."""
        return len(self._cache)
