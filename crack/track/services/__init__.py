"""Service-specific enumeration plugins"""

from .base import ServicePlugin
from .registry import ServiceRegistry

# Phase 1: Core OSCP (Linux, Binary, Generic)
from . import linux_privesc
from . import linux_privesc_advanced
from . import linux_kernel_exploit
# from . import linux_capabilities  # TEMP: has syntax errors
from . import linux_shell_escaping
from . import linux_container_escape
from . import linux_persistence
from . import linux_enumeration
from . import binary_exploitation
from . import binary_advanced_exploit
from . import binary_exploit
from . import binary_arm_exploit
from . import reverse_shells
from . import generic_attack_techniques

# Phase 2: Platform-Specific (macOS, iOS, Android, Mobile)
from . import macos_enumeration
from . import macos_privesc
from . import macos_process_abuse
from . import macos_ipc_exploitation
from . import macos_sandbox_bypass
from . import macos_kernel_security
from . import macos_filesystem
from . import macos_security_features
from . import macos_red_teaming
from . import macos_mdm_exploitation
from . import macos_app_security
from . import macos_programming
from . import ios_pentesting
from . import ios_testing_environment
from . import ios_app_analysis
from . import ios_hooking
from . import ios_protocols
from . import ios_binary_exploit
from . import android_pentesting
from . import mobile_hybrid_apps

# Phase 3: Specialized (Crypto, Hardware, Reversing, Blockchain)
from . import cryptography
from . import blockchain_security
from . import hardware_physical_access
from . import reversing

# Network Services (Original)
from . import http
from . import iis
from . import smb
from . import ssh
from . import ftp
from . import sql
from . import mysql
from . import postgresql
from . import smtp
from . import nfs
from . import memcache
from . import rabbitmq
from . import splunk
from . import snmp
from . import ntp
from . import rpcbind
from . import ipsec_ike

# Web Technologies
from . import php
from . import php_bypass
from . import python_web
from . import nodejs
from . import nextjs
from . import apache
from . import nginx
from . import web_security
from . import web_methodology
from . import cms
from . import wordpress
from . import graphql
from . import java_app_servers
from . import spring_boot
from . import ruby_on_rails
from . import nosql

# Web Attack Vectors
from . import injection_attacks
# from . import xss_attacks  # TEMP: syntax errors (line 554) - needs manual fix
from . import ssrf_attacks
from . import ssti_attacks
from . import deserialization_attacks
from . import jwt_attacks
from . import session_attacks
from . import auth_bypass
from . import redirect_attacks
from . import sso_attacks
from . import http_smuggling
from . import server_side_inclusion
from . import api_attacks
from . import data_format_attacks
from . import cache_timing_attacks
from . import client_side_attacks

# Windows & Active Directory
from . import windows_bof
from . import windows_privesc
from . import windows_privesc_extended
from . import windows_privesc_full
from . import windows_core
from . import windows_dll_ipc_privesc
from . import ad_attacks
from . import ad_certificates
from . import ad_persistence
from . import ad_enumeration
from . import lateral_movement
from . import credential_theft

# Exploitation & Post-Exploitation
from . import post_exploit
from . import heap_exploit
from . import lua_exploit
from . import browser_exploit
from . import electron_desktop_apps

# Network & Infrastructure
from . import network_poisoning
from . import ipv6_attacks
from . import wifi_attack
from . import legacy_protocols
from . import legacy_file_services

# C2, Recon, and Advanced
from . import c2_operations
from . import external_recon
from . import phishing
from . import anti_forensics
from . import telecom_exploit
from . import industrial_iot
from . import remote_access
from . import dev_tools
from . import business_logic

__all__ = ['ServicePlugin', 'ServiceRegistry']
