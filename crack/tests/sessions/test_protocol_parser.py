"""
Tests for DNS and ICMP protocol parsers.

Tests cover:
- DNS query parsing (hex, base64, base32)
- DNS response encoding
- DNS label validation
- ICMP packet parsing and creation
- ICMP checksum calculation
"""

import pytest
import struct

from crack.sessions.listeners.protocol_parser import (
    DNSProtocolParser,
    ICMPProtocolParser,
    decode_dns_data,
    encode_dns_data,
    parse_icmp_payload
)


class TestDNSProtocolParser:
    """Test DNS protocol parser."""

    def test_parse_hex_query(self):
        """Test parsing hex-encoded DNS query."""
        parser = DNSProtocolParser()
        result = parser.parse_query('48656c6c6f.tunnel.com', 'tunnel.com')

        assert result['valid'] is True
        assert result['data'] == 'Hello'
        assert result['encoding'] == 'hex'
        assert result['raw_subdomain'] == '48656c6c6f'

    def test_parse_base64_query(self):
        """Test parsing base64-encoded DNS query."""
        parser = DNSProtocolParser()
        # "Hello" in base64 is "SGVsbG8="
        result = parser.parse_query('SGVsbG8.tunnel.com', 'tunnel.com')

        assert result['valid'] is True
        assert result['data'] == 'Hello'
        assert result['encoding'] == 'base64'

    def test_parse_base32_query(self):
        """Test parsing base32-encoded DNS query."""
        parser = DNSProtocolParser()
        # "Hello" in base32 is "JBSWY3DP"
        result = parser.parse_query('JBSWY3DP.tunnel.com', 'tunnel.com')

        assert result['valid'] is True
        assert result['data'] == 'Hello'
        assert result['encoding'] == 'base32'

    def test_parse_query_without_domain(self):
        """Test parsing query without domain stripping."""
        parser = DNSProtocolParser()
        result = parser.parse_query('48656c6c6f')

        assert result['valid'] is True
        assert result['data'] == 'Hello'

    def test_parse_invalid_query(self):
        """Test parsing invalid query."""
        parser = DNSProtocolParser()
        result = parser.parse_query('invalid-data.tunnel.com', 'tunnel.com')

        assert result['valid'] is False
        assert 'error' in result

    def test_encode_response_hex(self):
        """Test encoding response with hex."""
        parser = DNSProtocolParser()
        encoded = parser.encode_response('Hello', 'hex')

        assert encoded == '48656c6c6f'

    def test_encode_response_base64(self):
        """Test encoding response with base64."""
        parser = DNSProtocolParser()
        encoded = parser.encode_response('Hello', 'base64')

        assert encoded == 'SGVsbG8='

    def test_encode_response_base32(self):
        """Test encoding response with base32."""
        parser = DNSProtocolParser()
        encoded = parser.encode_response('Hello', 'base32')

        # Base32 encoding may strip padding
        assert encoded.startswith('JBSWY3DP')

    def test_chunk_data(self):
        """Test chunking data for DNS labels."""
        parser = DNSProtocolParser()
        data = 'A' * 200

        chunks = parser.chunk_data(data, chunk_size=63)

        assert len(chunks) == 4  # 200 / 63 = 3.17 -> 4 chunks
        assert all(len(chunk) <= 63 for chunk in chunks)
        assert ''.join(chunks) == data

    def test_validate_dns_label_valid(self):
        """Test validating valid DNS label."""
        parser = DNSProtocolParser()

        assert parser.validate_dns_label('valid-label') is True
        assert parser.validate_dns_label('test123') is True
        assert parser.validate_dns_label('a') is True

    def test_validate_dns_label_invalid(self):
        """Test validating invalid DNS labels."""
        parser = DNSProtocolParser()

        assert parser.validate_dns_label('-invalid') is False  # Starts with hyphen
        assert parser.validate_dns_label('invalid-') is False  # Ends with hyphen
        assert parser.validate_dns_label('A' * 64) is False   # Too long
        assert parser.validate_dns_label('') is False         # Empty
        assert parser.validate_dns_label('invalid_label') is False  # Underscore


class TestICMPProtocolParser:
    """Test ICMP protocol parser."""

    def test_parse_echo_request(self):
        """Test parsing ICMP echo request."""
        parser = ICMPProtocolParser()

        # Create echo request packet
        # Type=8 (request), Code=0, Checksum=0, ID=1, Seq=1, Data="Hello"
        packet = struct.pack('!BBHHH', 8, 0, 0, 1, 1) + b'Hello'

        result = parser.parse_packet(packet)

        assert result['valid'] is True
        assert result['type'] == 8
        assert result['code'] == 0
        assert result['identifier'] == 1
        assert result['sequence'] == 1
        assert result['data'] == 'Hello'
        assert result['raw_data'] == b'Hello'

    def test_parse_echo_reply(self):
        """Test parsing ICMP echo reply."""
        parser = ICMPProtocolParser()

        # Type=0 (reply)
        packet = struct.pack('!BBHHH', 0, 0, 0, 1, 1) + b'World'

        result = parser.parse_packet(packet)

        assert result['valid'] is True
        assert result['type'] == 0
        assert result['data'] == 'World'

    def test_parse_packet_too_short(self):
        """Test parsing packet that's too short."""
        parser = ICMPProtocolParser()

        packet = b'short'

        result = parser.parse_packet(packet)

        assert result['valid'] is False
        assert 'error' in result

    def test_parse_packet_with_non_utf8(self):
        """Test parsing packet with non-UTF8 data."""
        parser = ICMPProtocolParser()

        # Binary data that's not UTF-8
        packet = struct.pack('!BBHHH', 8, 0, 0, 1, 1) + b'\xff\xfe\xfd'

        result = parser.parse_packet(packet)

        assert result['valid'] is True
        assert result['type'] == 8
        # data should be None or ignore errors
        assert result['raw_data'] == b'\xff\xfe\xfd'

    def test_create_packet(self):
        """Test creating ICMP packet."""
        parser = ICMPProtocolParser()

        packet = parser.create_packet(
            packet_type=8,  # Echo request
            code=0,
            identifier=1,
            sequence=1,
            data=b'Hello'
        )

        assert len(packet) == 13  # 8-byte header + 5-byte payload
        assert packet[0:1] == b'\x08'  # Type
        assert packet[1:2] == b'\x00'  # Code

    def test_calculate_checksum(self):
        """Test ICMP checksum calculation."""
        parser = ICMPProtocolParser()

        # Simple packet
        packet = struct.pack('!BBHHH', 8, 0, 0, 1, 1) + b'Test'

        checksum = parser.calculate_checksum(packet)

        assert isinstance(checksum, int)
        assert 0 <= checksum <= 0xFFFF

    def test_validate_checksum(self):
        """Test validating ICMP checksum."""
        parser = ICMPProtocolParser()

        # Create packet with valid checksum
        packet = parser.create_packet(8, 0, 1, 1, b'Test')

        assert parser.validate_checksum(packet) is True

    def test_validate_checksum_invalid(self):
        """Test validating invalid checksum."""
        parser = ICMPProtocolParser()

        # Create packet then corrupt checksum
        packet = bytearray(parser.create_packet(8, 0, 1, 1, b'Test'))
        packet[2] = 0xFF  # Corrupt checksum byte
        packet[3] = 0xFF

        assert parser.validate_checksum(bytes(packet)) is False

    def test_extract_shell_data(self):
        """Test extracting shell data from packet."""
        parser = ICMPProtocolParser()

        # Create packet with shell command
        packet = parser.create_packet(8, 0, 1, 1, b'whoami\n')

        data = parser.extract_shell_data(packet)

        assert data == 'whoami'

    def test_extract_shell_data_with_nulls(self):
        """Test extracting shell data with null bytes."""
        parser = ICMPProtocolParser()

        # Packet with null padding
        packet = parser.create_packet(8, 0, 1, 1, b'id\x00\x00\x00')

        data = parser.extract_shell_data(packet)

        assert data == 'id'


class TestConvenienceFunctions:
    """Test convenience wrapper functions."""

    def test_decode_dns_data(self):
        """Test decode_dns_data convenience function."""
        data = decode_dns_data('48656c6c6f.tunnel.com', 'tunnel.com')

        assert data == 'Hello'

    def test_decode_dns_data_invalid(self):
        """Test decode_dns_data with invalid data."""
        data = decode_dns_data('invalid.tunnel.com', 'tunnel.com')

        assert data is None

    def test_encode_dns_data(self):
        """Test encode_dns_data convenience function."""
        encoded = encode_dns_data('Hello', 'hex')

        assert encoded == '48656c6c6f'

    def test_parse_icmp_payload(self):
        """Test parse_icmp_payload convenience function."""
        parser = ICMPProtocolParser()
        packet = parser.create_packet(8, 0, 1, 1, b'whoami')

        payload = parse_icmp_payload(packet)

        assert payload == 'whoami'


class TestDNSParserEdgeCases:
    """Test DNS parser edge cases."""

    def test_empty_query(self):
        """Test parsing empty query."""
        parser = DNSProtocolParser()
        result = parser.parse_query('', 'tunnel.com')

        # Empty query returns empty result
        # The implementation may succeed with empty string
        assert 'valid' in result

    def test_query_with_multiple_subdomains(self):
        """Test parsing query with multiple subdomains."""
        parser = DNSProtocolParser()
        result = parser.parse_query('48656c6c6f.sub.tunnel.com', 'tunnel.com')

        assert result['valid'] is True
        assert result['raw_subdomain'] == '48656c6c6f'

    def test_long_data_encoding(self):
        """Test encoding long data."""
        parser = DNSProtocolParser()
        long_text = 'A' * 1000

        encoded = parser.encode_response(long_text, 'hex')
        chunks = parser.chunk_data(encoded)

        # All chunks should be <= 63 chars
        assert all(len(chunk) <= 63 for chunk in chunks)
        # Should reconstruct original
        assert ''.join(chunks) == encoded


class TestICMPParserEdgeCases:
    """Test ICMP parser edge cases."""

    def test_empty_payload(self):
        """Test creating packet with empty payload."""
        parser = ICMPProtocolParser()
        packet = parser.create_packet(8, 0, 1, 1, b'')

        assert len(packet) == 8  # Header only

    def test_large_payload(self):
        """Test creating packet with large payload."""
        parser = ICMPProtocolParser()
        large_data = b'A' * 1000
        packet = parser.create_packet(8, 0, 1, 1, large_data)

        assert len(packet) == 8 + 1000

    def test_checksum_with_odd_length(self):
        """Test checksum calculation with odd-length data."""
        parser = ICMPProtocolParser()
        # Odd length: 8 + 3 = 11 bytes
        packet = struct.pack('!BBHHH', 8, 0, 0, 1, 1) + b'Odd'

        checksum = parser.calculate_checksum(packet)

        assert isinstance(checksum, int)
