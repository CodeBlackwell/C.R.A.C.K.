"""
Finding Type Constants for Plugin Activation

Standardized finding types that plugins can activate on.
These constants ensure consistency across the codebase.
"""


class FindingTypes:
    """Standard finding types for plugin activation and tracking"""

    # ===== ACCESS & SHELL TYPES =====
    SHELL_OBTAINED = 'shell_obtained'
    LOW_PRIVILEGE_SHELL = 'low_privilege_shell'
    HIGH_PRIVILEGE_SHELL = 'high_privilege_shell'
    ROOT_SHELL = 'root_shell'
    SYSTEM_SHELL = 'system_shell'
    ADMIN_SHELL = 'admin_shell'
    ACCESS_GAINED = 'access_gained'
    REMOTE_CODE_EXECUTION = 'remote_code_execution'

    # ===== OPERATING SYSTEM DETECTION =====
    OS_DETECTED = 'os_detected'
    OS_LINUX = 'os_linux'
    OS_WINDOWS = 'os_windows'
    OS_MACOS = 'os_macos'
    OS_BSD = 'os_bsd'
    OS_UNIX = 'os_unix'

    # ===== CMS & FRAMEWORKS =====
    CMS_DETECTED = 'cms_detected'
    CMS_WORDPRESS = 'cms_wordpress'
    CMS_JOOMLA = 'cms_joomla'
    CMS_DRUPAL = 'cms_drupal'
    CMS_MAGENTO = 'cms_magento'
    CMS_TYPO3 = 'cms_typo3'
    CMS_CONCRETE5 = 'cms_concrete5'
    FRAMEWORK_DETECTED = 'framework_detected'
    FRAMEWORK_DJANGO = 'framework_django'
    FRAMEWORK_FLASK = 'framework_flask'
    FRAMEWORK_RAILS = 'framework_rails'
    FRAMEWORK_SPRING = 'framework_spring'
    FRAMEWORK_NODEJS = 'framework_nodejs'
    FRAMEWORK_NEXTJS = 'framework_nextjs'
    FRAMEWORK_LARAVEL = 'framework_laravel'
    FRAMEWORK_EXPRESS = 'framework_express'

    # ===== CREDENTIALS & AUTHENTICATION =====
    CREDENTIAL_FOUND = 'credential_found'
    SSH_CREDENTIAL = 'ssh_credential'
    DATABASE_CREDENTIAL = 'database_credential'
    WEB_CREDENTIAL = 'web_credential'
    API_KEY_FOUND = 'api_key_found'
    PASSWORD_FOUND = 'password_found'
    HASH_FOUND = 'hash_found'
    TOKEN_FOUND = 'token_found'
    EMAIL_ACCESS = 'email_access'
    SMTP_ACCESS = 'smtp_access'

    # ===== VULNERABILITIES =====
    VULNERABILITY_FOUND = 'vulnerability'
    CVE_FOUND = 'cve_found'
    MISCONFIGURATION = 'misconfiguration'
    SQL_INJECTION = 'sql_injection'
    XSS_FOUND = 'xss_found'
    SSRF_FOUND = 'ssrf_found'
    SSTI_FOUND = 'ssti_found'
    XXE_FOUND = 'xxe_found'
    DESERIALIZATION_VULN = 'deserialization_vulnerability'
    LFI_FOUND = 'lfi_found'
    RFI_FOUND = 'rfi_found'
    COMMAND_INJECTION = 'command_injection'
    PATH_TRAVERSAL = 'path_traversal'

    # ===== ENVIRONMENT & CONTEXT =====
    CONTAINER_DETECTED = 'container_detected'
    DOCKER_DETECTED = 'docker_detected'
    KUBERNETES_DETECTED = 'kubernetes_detected'
    DOMAIN_JOINED = 'domain_joined'
    DOMAIN_CONTROLLER_FOUND = 'domain_controller_found'
    CLOUD_DETECTED = 'cloud_detected'
    CLOUD_AWS = 'cloud_aws'
    CLOUD_AZURE = 'cloud_azure'
    CLOUD_GCP = 'cloud_gcp'

    # ===== SERVICE & VERSION =====
    SERVICE_VERSION = 'service_version'
    SERVICE_BANNER = 'service_banner'
    DATABASE_ACCESS = 'database_access'
    API_ACCESS = 'api_access'
    ADMIN_PANEL_FOUND = 'admin_panel_found'

    # ===== TECHNOLOGIES =====
    TECH_PHP = 'tech_php'
    TECH_PYTHON = 'tech_python'
    TECH_NODEJS = 'tech_nodejs'
    TECH_JAVA = 'tech_java'
    TECH_DOTNET = 'tech_dotnet'
    TECH_RUBY = 'tech_ruby'
    TECH_GO = 'tech_go'

    # ===== ACTIVE DIRECTORY =====
    AD_DETECTED = 'ad_detected'
    AD_USER_FOUND = 'ad_user_found'
    AD_ADMIN_FOUND = 'ad_admin_found'
    AD_COMPUTER_FOUND = 'ad_computer_found'
    KERBEROASTABLE_USER = 'kerberoastable_user'
    AS_REP_ROASTABLE = 'as_rep_roastable'
    ADCS_DETECTED = 'adcs_detected'
    DOMAIN_ADMIN_OBTAINED = 'domain_admin_obtained'
    ADCS_VULNERABLE = 'adcs_vulnerable'
    GPO_VULNERABLE = 'gpo_vulnerable'

    # ===== FILES & DIRECTORIES =====
    DIRECTORY_FOUND = 'directory'
    FILE_FOUND = 'file'
    BACKUP_FILE_FOUND = 'backup_file'
    CONFIG_FILE_FOUND = 'config_file'
    LOG_FILE_FOUND = 'log_file'
    SOURCE_CODE_FOUND = 'source_code'

    # ===== BINARY & EXPLOITATION =====
    BINARY_VULNERABLE = 'binary_vulnerable'
    SUID_BINARY_FOUND = 'suid_binary_found'
    SGID_BINARY_FOUND = 'sgid_binary_found'
    WRITABLE_BINARY = 'writable_binary'
    CAPABILITY_FOUND = 'capability_found'
    KERNEL_VULNERABLE = 'kernel_vulnerable'
    BUFFER_OVERFLOW = 'buffer_overflow'
    FORMAT_STRING_VULN = 'format_string_vulnerability'
    USE_AFTER_FREE = 'use_after_free'
    RACE_CONDITION = 'race_condition'

    # ===== LATERAL MOVEMENT =====
    PIVOT_OPPORTUNITY = 'pivot_opportunity'
    NETWORK_SHARE_FOUND = 'network_share_found'
    WRITABLE_SHARE = 'writable_share'
    PERSISTENT_ACCESS_NEEDED = 'persistent_access_needed'
    C2_RECOMMENDED = 'c2_recommended'

    # ===== USER & GROUPS =====
    USER_FOUND = 'user'
    PRIVILEGED_USER_FOUND = 'privileged_user'
    SUDO_PERMISSION_FOUND = 'sudo_permission'
    GROUP_MEMBERSHIP = 'group_membership'


class FindingPriority:
    """Priority levels for findings (for UI display)"""
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'
