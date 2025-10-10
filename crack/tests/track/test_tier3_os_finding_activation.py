"""
Tests for Tier 3 OS & Environment Plugin Finding-Based Activation

Validates that OS-specific and environment-specific plugins activate correctly
based on findings like OS detection, shell acquisition, and container detection.

Coverage:
- Linux enumeration (OS_LINUX, OS_UNIX, distros)
- Linux persistence (ROOT_SHELL, HIGH_PRIVILEGE_SHELL, SUDO_PERMISSION_FOUND)
- Container escape (CONTAINER_DETECTED, DOCKER_DETECTED, KUBERNETES_DETECTED)
- Kernel exploits (KERNEL_VULNERABLE)
- Windows core (OS_WINDOWS, Windows shells)
- Windows DLL/IPC privesc (LOW_PRIVILEGE_SHELL)
- Windows extended privesc (LOW_PRIVILEGE_SHELL)
- macOS privesc (OS_MACOS, macOS shells)
- macOS enumeration (OS_MACOS, macOS shells)
"""

import pytest
from crack.track.core.constants import FindingTypes


class TestLinuxEnumerationActivation:
    """Test linux_enumeration.py finding-based activation"""

    def test_activates_on_os_linux(self):
        """PROVES: Linux enumeration activates on OS_LINUX finding"""
        from crack.track.services.linux_enumeration import LinuxEnumerationPlugin

        plugin = LinuxEnumerationPlugin()
        finding = {
            'type': FindingTypes.OS_LINUX,
            'description': 'Linux operating system detected'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 95, "Should activate with high confidence on OS_LINUX"

    def test_activates_on_linux_shell(self):
        """PROVES: Linux enumeration activates on shell with Linux hints"""
        from crack.track.services.linux_enumeration import LinuxEnumerationPlugin

        plugin = LinuxEnumerationPlugin()
        finding = {
            'type': FindingTypes.SHELL_OBTAINED,
            'description': 'Shell obtained: bash on Ubuntu 20.04'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 90, "Should activate on shell with Linux/bash hints"

    def test_activates_on_distro_mention(self):
        """PROVES: Linux enumeration activates on distro mentions"""
        from crack.track.services.linux_enumeration import LinuxEnumerationPlugin

        plugin = LinuxEnumerationPlugin()
        finding = {
            'type': FindingTypes.OS_DETECTED,
            'description': 'Debian GNU/Linux 11 detected'
        }

        score = plugin.detect_from_finding(finding)

        assert score >= 70, "Should activate on distro mention"


class TestLinuxPersistenceActivation:
    """Test linux_persistence.py finding-based activation"""

    def test_activates_on_root_shell(self):
        """PROVES: Linux persistence activates on root shell"""
        from crack.track.services.linux_persistence import LinuxPersistencePlugin

        plugin = LinuxPersistencePlugin()
        finding = {
            'type': FindingTypes.ROOT_SHELL,
            'description': 'Root shell obtained (uid=0)'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 100, "Should activate with perfect confidence on root shell"

    def test_activates_on_sudo_permissions(self):
        """PROVES: Linux persistence activates on sudo permissions"""
        from crack.track.services.linux_persistence import LinuxPersistencePlugin

        plugin = LinuxPersistencePlugin()
        finding = {
            'type': FindingTypes.SUDO_PERMISSION_FOUND,
            'description': 'User has sudo NOPASSWD for /usr/bin/python3'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 80, "Should activate on sudo permissions"


class TestContainerEscapeActivation:
    """Test linux_container_escape.py finding-based activation"""

    def test_activates_on_docker_detected(self):
        """PROVES: Container escape activates on Docker detection"""
        from crack.track.services.linux_container_escape import LinuxContainerEscapePlugin

        plugin = LinuxContainerEscapePlugin()
        finding = {
            'type': FindingTypes.DOCKER_DETECTED,
            'description': 'Docker container environment detected'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 100, "Should activate perfectly on Docker detection"

    def test_activates_on_container_hints(self):
        """PROVES: Container escape activates on container hints in description"""
        from crack.track.services.linux_container_escape import LinuxContainerEscapePlugin

        plugin = LinuxContainerEscapePlugin()
        finding = {
            'type': FindingTypes.SHELL_OBTAINED,
            'description': 'Shell in Kubernetes pod detected'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 90, "Should activate on shell with container hints"


class TestKernelExploitActivation:
    """Test linux_kernel_exploit.py finding-based activation"""

    def test_activates_on_kernel_vulnerable(self):
        """PROVES: Kernel exploit activates on KERNEL_VULNERABLE finding"""
        from crack.track.services.linux_kernel_exploit import LinuxKernelExploitPlugin

        plugin = LinuxKernelExploitPlugin()
        finding = {
            'type': FindingTypes.KERNEL_VULNERABLE,
            'description': 'Linux kernel 5.4.0-42 vulnerable to DirtyPipe (CVE-2022-0847)'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 100, "Should activate perfectly on kernel vulnerability"

    def test_activates_on_kernel_mention(self):
        """PROVES: Kernel exploit activates on kernel vulnerability mention"""
        from crack.track.services.linux_kernel_exploit import LinuxKernelExploitPlugin

        plugin = LinuxKernelExploitPlugin()
        finding = {
            'type': FindingTypes.OS_LINUX,
            'description': 'Linux kernel 3.13.0 - potential privilege escalation'
        }

        score = plugin.detect_from_finding(finding)

        # Medium confidence since it's OS_LINUX not KERNEL_VULNERABLE
        assert score >= 60, "Should activate on Linux OS (kernel exploits may be relevant)"


class TestWindowsCoreActivation:
    """Test windows_core.py finding-based activation"""

    def test_activates_on_os_windows(self):
        """PROVES: Windows core activates on OS_WINDOWS finding"""
        from crack.track.services.windows_core import WindowsCorePlugin

        plugin = WindowsCorePlugin()
        finding = {
            'type': FindingTypes.OS_WINDOWS,
            'description': 'Windows Server 2019 detected'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 95, "Should activate with high confidence on OS_WINDOWS"

    def test_activates_on_windows_shell(self):
        """PROVES: Windows core activates on shell with Windows hints"""
        from crack.track.services.windows_core import WindowsCorePlugin

        plugin = WindowsCorePlugin()
        finding = {
            'type': FindingTypes.SHELL_OBTAINED,
            'description': 'PowerShell session established on Windows 10'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 90, "Should activate on shell with PowerShell/Windows hints"


class TestWindowsDLLIPCPrivescActivation:
    """Test windows_dll_ipc_privesc.py finding-based activation"""

    def test_activates_on_low_privilege_windows_shell(self):
        """PROVES: Windows DLL/IPC privesc activates on low privilege shell"""
        from crack.track.services.windows_dll_ipc_privesc import WindowsDllIpcPrivescPlugin

        plugin = WindowsDllIpcPrivescPlugin()
        finding = {
            'type': FindingTypes.LOW_PRIVILEGE_SHELL,
            'description': 'Standard user shell on Windows Server 2016'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 90, "Should activate on low privilege Windows shell"

    def test_activates_on_windows_shell_for_dll_opportunities(self):
        """PROVES: Windows DLL/IPC privesc activates on any Windows shell"""
        from crack.track.services.windows_dll_ipc_privesc import WindowsDllIpcPrivescPlugin

        plugin = WindowsDllIpcPrivescPlugin()
        finding = {
            'type': FindingTypes.SHELL_OBTAINED,
            'description': 'cmd.exe shell on Windows 10'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 85, "Should activate on Windows shell (DLL hijacking opportunities)"


class TestWindowsPrivescExtendedActivation:
    """Test windows_privesc_extended.py finding-based activation"""

    def test_activates_on_low_privilege_windows_shell(self):
        """PROVES: Windows extended privesc activates on low privilege shell"""
        from crack.track.services.windows_privesc_extended import WindowsPrivescExtendedPlugin

        plugin = WindowsPrivescExtendedPlugin()
        finding = {
            'type': FindingTypes.LOW_PRIVILEGE_SHELL,
            'description': 'Limited user shell on Windows Server 2019'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 95, "Should activate with high confidence on low privilege Windows shell"

    def test_activates_on_standard_windows_shell(self):
        """PROVES: Windows extended privesc activates on standard Windows shell"""
        from crack.track.services.windows_privesc_extended import WindowsPrivescExtendedPlugin

        plugin = WindowsPrivescExtendedPlugin()
        finding = {
            'type': FindingTypes.SHELL_OBTAINED,
            'description': 'Shell obtained on Windows 10 Pro'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 80, "Should activate on standard Windows shell"


class TestMacOSPrivescActivation:
    """Test macos_privesc.py finding-based activation"""

    def test_activates_on_os_macos(self):
        """PROVES: macOS privesc activates on OS_MACOS finding"""
        from crack.track.services.macos_privesc import MacOSPrivEscPlugin

        plugin = MacOSPrivEscPlugin()
        finding = {
            'type': FindingTypes.OS_MACOS,
            'description': 'macOS Monterey 12.6 detected'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 95, "Should activate with high confidence on OS_MACOS"

    def test_activates_on_macos_shell(self):
        """PROVES: macOS privesc activates on shell with macOS hints"""
        from crack.track.services.macos_privesc import MacOSPrivEscPlugin

        plugin = MacOSPrivEscPlugin()
        finding = {
            'type': FindingTypes.SHELL_OBTAINED,
            'description': 'Shell obtained on Darwin 21.6.0 (macOS)'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 90, "Should activate on shell with macOS/Darwin hints"


class TestMacOSEnumerationActivation:
    """Test macos_enumeration.py finding-based activation"""

    def test_activates_on_os_macos(self):
        """PROVES: macOS enumeration activates on OS_MACOS finding"""
        from crack.track.services.macos_enumeration import MacOSEnumerationPlugin

        plugin = MacOSEnumerationPlugin()
        finding = {
            'type': FindingTypes.OS_MACOS,
            'description': 'macOS Big Sur 11.7 detected'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 95, "Should activate with high confidence on OS_MACOS"

    def test_activates_on_macos_shell(self):
        """PROVES: macOS enumeration activates on shell with macOS hints"""
        from crack.track.services.macos_enumeration import MacOSEnumerationPlugin

        plugin = MacOSEnumerationPlugin()
        finding = {
            'type': FindingTypes.SHELL_OBTAINED,
            'description': 'zsh shell on macOS Ventura'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 90, "Should activate on shell with macOS hints"


class TestNoFalsePositives:
    """Test that plugins don't activate on irrelevant findings"""

    def test_linux_plugins_ignore_windows(self):
        """PROVES: Linux plugins don't activate on Windows findings"""
        from crack.track.services.linux_enumeration import LinuxEnumerationPlugin

        plugin = LinuxEnumerationPlugin()
        finding = {
            'type': FindingTypes.OS_WINDOWS,
            'description': 'Windows Server 2019'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 0, "Linux plugin should not activate on Windows OS"

    def test_windows_plugins_ignore_linux(self):
        """PROVES: Windows plugins don't activate on Linux findings"""
        from crack.track.services.windows_core import WindowsCorePlugin

        plugin = WindowsCorePlugin()
        finding = {
            'type': FindingTypes.OS_LINUX,
            'description': 'Ubuntu 20.04 LTS'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 0, "Windows plugin should not activate on Linux OS"

    def test_macos_plugins_ignore_linux(self):
        """PROVES: macOS plugins don't activate on Linux findings"""
        from crack.track.services.macos_privesc import MacOSPrivEscPlugin

        plugin = MacOSPrivEscPlugin()
        finding = {
            'type': FindingTypes.OS_LINUX,
            'description': 'Debian 11'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 0, "macOS plugin should not activate on Linux OS"

    def test_container_plugin_ignores_non_container(self):
        """PROVES: Container escape doesn't activate without container indicators"""
        from crack.track.services.linux_container_escape import LinuxContainerEscapePlugin

        plugin = LinuxContainerEscapePlugin()
        finding = {
            'type': FindingTypes.SHELL_OBTAINED,
            'description': 'Standard bash shell on Ubuntu server'
        }

        score = plugin.detect_from_finding(finding)

        assert score == 0, "Container plugin should not activate without container hints"
