"""
Protocol parsers for DNS and ICMP tunnel data extraction.

Provides utilities for:
- DNS query/response parsing and encoding
- ICMP packet data extraction
- Hex encoding/decoding for tunneled data
- Base64 encoding for binary data

Used by DNS and ICMP listeners to extract tunneled payloads.
"""

import struct
import base64
from typing import Dict, Any, Optional


class DNSProtocolParser:
    """Parse DNS queries and responses for tunneled data.

    DNS tunneling techniques:
    1. Subdomain encoding: data.hex.tunnel.com
    2. TXT record responses: encoded data in TXT records
    3. NULL record tunneling: binary data in NULL records

    Example DNS query with encoded data:
        48656c6c6f.tunnel.evil.com
        └─ "Hello" in hex

    Example:
        >>> parser = DNSProtocolParser()
        >>> result = parser.parse_query('48656c6c6f.tunnel.evil.com')
        >>> print(result['data'])  # "Hello"
        >>>
        >>> response = parser.encode_response('World')
        >>> print(response)  # "576f726c64"
    """

    @staticmethod
    def parse_query(query: str, domain: str = None) -> Dict[str, Any]:
        """Parse DNS query for tunneled data.

        Extracts data from subdomain encoding:
        - Hex-encoded subdomains
        - Base32-encoded subdomains
        - Base64-encoded subdomains

        Args:
            query: Full DNS query (e.g., 48656c6c6f.tunnel.evil.com)
            domain: Base domain to strip (e.g., tunnel.evil.com)

        Returns:
            Dictionary with parsing results:
            {
                'data': str,        # Decoded data
                'encoding': str,    # Detected encoding (hex, base32, base64)
                'valid': bool,      # Whether parsing succeeded
                'raw_subdomain': str  # Original subdomain
            }

        Example:
            >>> # Hex encoding
            >>> result = parser.parse_query('48656c6c6f.tunnel.evil.com', 'tunnel.evil.com')
            >>> print(result)
            {'data': 'Hello', 'encoding': 'hex', 'valid': True, 'raw_subdomain': '48656c6c6f'}
            >>>
            >>> # Base64 encoding
            >>> result = parser.parse_query('SGVsbG8=.tunnel.evil.com', 'tunnel.evil.com')
            >>> print(result)
            {'data': 'Hello', 'encoding': 'base64', 'valid': True, 'raw_subdomain': 'SGVsbG8='}
        """
        # Strip domain suffix if provided
        if domain:
            query = query.replace(f'.{domain}', '')

        # Extract first subdomain (data payload)
        parts = query.split('.')
        if not parts:
            return {'valid': False, 'error': 'Empty query'}

        subdomain = parts[0]

        # Try different encodings
        result = {
            'raw_subdomain': subdomain,
            'valid': False,
            'data': None,
            'encoding': None
        }

        # Try hex decoding first (most common)
        try:
            data = bytes.fromhex(subdomain).decode('utf-8')
            result['data'] = data
            result['encoding'] = 'hex'
            result['valid'] = True
            return result
        except (ValueError, UnicodeDecodeError):
            pass

        # Try base64 decoding
        try:
            # Add padding if needed
            padding = (4 - len(subdomain) % 4) % 4
            subdomain_padded = subdomain + '=' * padding
            data = base64.b64decode(subdomain_padded).decode('utf-8')
            result['data'] = data
            result['encoding'] = 'base64'
            result['valid'] = True
            return result
        except (ValueError, UnicodeDecodeError):
            pass

        # Try base32 decoding
        try:
            # Add padding if needed
            padding = (8 - len(subdomain.upper()) % 8) % 8
            subdomain_padded = subdomain.upper() + '=' * padding
            data = base64.b32decode(subdomain_padded).decode('utf-8')
            result['data'] = data
            result['encoding'] = 'base32'
            result['valid'] = True
            return result
        except (ValueError, UnicodeDecodeError):
            pass

        # No valid encoding found
        result['error'] = 'Could not decode subdomain'
        return result

    @staticmethod
    def encode_response(data: str, encoding: str = 'hex') -> str:
        """Encode data for DNS response.

        Args:
            data: Data to encode
            encoding: Encoding method ('hex', 'base64', 'base32')

        Returns:
            Encoded string suitable for DNS response

        Example:
            >>> response = parser.encode_response('Hello', 'hex')
            >>> print(response)
            '48656c6c6f'
            >>>
            >>> response = parser.encode_response('Hello', 'base64')
            >>> print(response)
            'SGVsbG8='
        """
        if encoding == 'hex':
            return data.encode('utf-8').hex()
        elif encoding == 'base64':
            return base64.b64encode(data.encode('utf-8')).decode('ascii')
        elif encoding == 'base32':
            return base64.b32encode(data.encode('utf-8')).decode('ascii')
        else:
            raise ValueError(f"Unknown encoding: {encoding}")

    @staticmethod
    def chunk_data(data: str, chunk_size: int = 63) -> list[str]:
        """Split data into DNS-safe chunks.

        DNS labels (subdomains) have max length of 63 characters.
        This splits data into multiple labels if needed.

        Args:
            data: Data to chunk
            chunk_size: Maximum chunk size (default: 63, DNS label limit)

        Returns:
            List of data chunks

        Example:
            >>> long_data = 'A' * 200
            >>> chunks = parser.chunk_data(long_data.encode().hex())
            >>> print(len(chunks))  # 4 chunks
            >>> all(len(c) <= 63 for c in chunks)  # True
        """
        return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

    @staticmethod
    def validate_dns_label(label: str) -> bool:
        """Validate DNS label format.

        DNS labels must:
        - Be 1-63 characters
        - Contain only alphanumeric and hyphens
        - Not start or end with hyphen

        Args:
            label: DNS label to validate

        Returns:
            True if valid DNS label

        Example:
            >>> parser.validate_dns_label('valid-label')
            True
            >>> parser.validate_dns_label('-invalid')
            False
        """
        if not label or len(label) > 63:
            return False

        if label.startswith('-') or label.endswith('-'):
            return False

        # Check allowed characters
        allowed = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-')
        return all(c in allowed for c in label)


class ICMPProtocolParser:
    """Parse ICMP packets for tunneled data.

    ICMP Echo Request/Reply structure:
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     Type      |     Code      |          Checksum             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           Identifier          |        Sequence Number        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     Data ...
       +-+-+-+-+-

    Data tunneling in ICMP payload:
    - Type 8 (Echo Request): Client -> Server
    - Type 0 (Echo Reply): Server -> Client
    - Payload: Arbitrary data (up to 65507 bytes)

    Example:
        >>> parser = ICMPProtocolParser()
        >>> packet = b'\\x08\\x00\\x00\\x00\\x00\\x01\\x00\\x01' + b'Hello'
        >>> result = parser.parse_packet(packet)
        >>> print(result)
        {
            'type': 8,
            'code': 0,
            'identifier': 1,
            'sequence': 1,
            'data': 'Hello',
            'valid': True
        }
    """

    # ICMP message types
    ICMP_ECHO_REPLY = 0
    ICMP_ECHO_REQUEST = 8

    @staticmethod
    def parse_packet(packet: bytes) -> Dict[str, Any]:
        """Parse ICMP packet and extract payload.

        Args:
            packet: Raw ICMP packet bytes

        Returns:
            Dictionary with packet fields:
            {
                'type': int,        # ICMP type (0=reply, 8=request)
                'code': int,        # ICMP code
                'checksum': int,    # Packet checksum
                'identifier': int,  # ICMP identifier
                'sequence': int,    # ICMP sequence number
                'data': str,        # Payload data (decoded)
                'raw_data': bytes,  # Raw payload bytes
                'valid': bool       # Whether parsing succeeded
            }

        Example:
            >>> packet = b'\\x08\\x00\\xf7\\xff\\x00\\x01\\x00\\x01' + b'Hello World'
            >>> result = parser.parse_packet(packet)
            >>> print(f"Type: {result['type']}, Data: {result['data']}")
            Type: 8, Data: Hello World
        """
        if len(packet) < 8:
            return {'valid': False, 'error': 'Packet too short (< 8 bytes)'}

        try:
            # Parse ICMP header (8 bytes)
            # Format: !BBHHH (type, code, checksum, identifier, sequence)
            type_byte, code, checksum, identifier, sequence = struct.unpack('!BBHHH', packet[:8])

            # Extract payload (everything after header)
            payload = packet[8:]

            # Try to decode payload as UTF-8
            try:
                data = payload.decode('utf-8', errors='ignore')
            except:
                data = None

            return {
                'type': type_byte,
                'code': code,
                'checksum': checksum,
                'identifier': identifier,
                'sequence': sequence,
                'data': data,
                'raw_data': payload,
                'valid': True
            }

        except struct.error as e:
            return {'valid': False, 'error': f'Parse error: {e}'}

    @staticmethod
    def create_packet(
        packet_type: int,
        code: int = 0,
        identifier: int = 0,
        sequence: int = 0,
        data: bytes = b''
    ) -> bytes:
        """Create ICMP packet with data payload.

        Args:
            packet_type: ICMP type (0=reply, 8=request)
            code: ICMP code (usually 0)
            identifier: ICMP identifier
            sequence: ICMP sequence number
            data: Payload data

        Returns:
            Raw ICMP packet bytes

        Example:
            >>> packet = parser.create_packet(
            ...     packet_type=8,  # Echo request
            ...     identifier=1,
            ...     sequence=1,
            ...     data=b'Hello'
            ... )
            >>> len(packet)
            13  # 8-byte header + 5-byte payload
        """
        # Calculate checksum (initially 0)
        checksum = 0

        # Pack header
        header = struct.pack('!BBHHH', packet_type, code, checksum, identifier, sequence)

        # Calculate checksum
        packet = header + data
        checksum = ICMPProtocolParser.calculate_checksum(packet)

        # Repack with correct checksum
        header = struct.pack('!BBHHH', packet_type, code, checksum, identifier, sequence)

        return header + data

    @staticmethod
    def calculate_checksum(data: bytes) -> int:
        """Calculate ICMP checksum.

        Checksum algorithm:
        1. Sum all 16-bit words
        2. Add carry bits
        3. Take one's complement

        Args:
            data: Packet data

        Returns:
            Checksum value (16-bit)

        Example:
            >>> packet = b'\\x08\\x00\\x00\\x00\\x00\\x01\\x00\\x01Hello'
            >>> checksum = parser.calculate_checksum(packet)
            >>> print(hex(checksum))
        """
        # Pad to even length
        if len(data) % 2 == 1:
            data += b'\x00'

        # Sum all 16-bit words
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            total += word

        # Add carry bits
        while total > 0xFFFF:
            total = (total & 0xFFFF) + (total >> 16)

        # One's complement
        return ~total & 0xFFFF

    @staticmethod
    def validate_checksum(packet: bytes) -> bool:
        """Validate ICMP packet checksum.

        Args:
            packet: Raw ICMP packet

        Returns:
            True if checksum is valid

        Example:
            >>> packet = parser.create_packet(8, 0, 1, 1, b'Test')
            >>> parser.validate_checksum(packet)
            True
        """
        if len(packet) < 8:
            return False

        # Extract checksum
        stored_checksum = struct.unpack('!H', packet[2:4])[0]

        # Zero out checksum field
        packet_copy = bytearray(packet)
        packet_copy[2:4] = b'\x00\x00'

        # Calculate checksum
        calculated_checksum = ICMPProtocolParser.calculate_checksum(bytes(packet_copy))

        return stored_checksum == calculated_checksum

    @staticmethod
    def extract_shell_data(packet: bytes) -> Optional[str]:
        """Extract shell command/output from ICMP payload.

        Convenience method for shell-over-ICMP use case.

        Args:
            packet: Raw ICMP packet

        Returns:
            Decoded shell data or None

        Example:
            >>> packet = parser.create_packet(8, 0, 1, 1, b'whoami\\n')
            >>> cmd = parser.extract_shell_data(packet)
            >>> print(cmd)
            'whoami'
        """
        result = ICMPProtocolParser.parse_packet(packet)

        if not result.get('valid'):
            return None

        data = result.get('data')
        if not data:
            return None

        # Strip whitespace and null bytes
        return data.strip('\x00\r\n\t ')


# Convenience functions
def decode_dns_data(query: str, domain: str = None) -> Optional[str]:
    """Decode data from DNS query.

    Args:
        query: DNS query string
        domain: Base domain to strip

    Returns:
        Decoded data or None

    Example:
        >>> data = decode_dns_data('48656c6c6f.tunnel.com', 'tunnel.com')
        >>> print(data)
        'Hello'
    """
    parser = DNSProtocolParser()
    result = parser.parse_query(query, domain)
    return result.get('data') if result.get('valid') else None


def encode_dns_data(data: str, encoding: str = 'hex') -> str:
    """Encode data for DNS query/response.

    Args:
        data: Data to encode
        encoding: Encoding method ('hex', 'base64', 'base32')

    Returns:
        Encoded string

    Example:
        >>> encoded = encode_dns_data('Hello', 'hex')
        >>> print(encoded)
        '48656c6c6f'
    """
    parser = DNSProtocolParser()
    return parser.encode_response(data, encoding)


def parse_icmp_payload(packet: bytes) -> Optional[str]:
    """Extract payload from ICMP packet.

    Args:
        packet: Raw ICMP packet bytes

    Returns:
        Decoded payload or None

    Example:
        >>> packet = b'\\x08\\x00\\x00\\x00\\x00\\x01\\x00\\x01Hello'
        >>> payload = parse_icmp_payload(packet)
        >>> print(payload)
        'Hello'
    """
    parser = ICMPProtocolParser()
    return parser.extract_shell_data(packet)
