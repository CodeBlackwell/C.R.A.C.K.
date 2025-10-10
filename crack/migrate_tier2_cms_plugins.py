#!/usr/bin/env python3
"""
Script to migrate Tier 2 CMS/Framework plugins to finding-based activation.
Adds detect_from_finding() method to 8 plugins.
"""

import sys
from pathlib import Path

# Plugin detection logic mapping
PLUGIN_MIGRATIONS = {
    'wordpress.py': '''
    def detect_from_finding(self, finding: Dict[str, Any], profile=None) -> int:
        """Detect WordPress from findings (whatweb, wappalyzer, manual verification)"""
        from ..core.constants import FindingTypes
        import logging
        logger = logging.getLogger(__name__)

        finding_type = finding.get('type', '').lower()
        description = finding.get('description', '').lower()

        # Perfect match - CMS_WORDPRESS detected
        if finding_type == FindingTypes.CMS_WORDPRESS:
            logger.info(f"WordPress plugin activating: CMS detected via {finding.get('source', 'unknown')}")
            return 100

        # High confidence - WordPress indicators in description
        wp_indicators = ['wordpress', 'wp-content', 'wp-admin', 'wp-login',
                         'wp-includes', 'wp-json', '/wp/', 'wordpress.org', 'wpscan']
        if any(ind in description for ind in wp_indicators):
            logger.info(f"WordPress plugin activating: Found indicator in '{description[:50]}'")
            return 90

        # Medium - Generic CMS that might be WordPress
        if finding_type == FindingTypes.CMS_DETECTED and 'php' in description:
            logger.debug("Generic CMS with PHP detected, possible WordPress")
            return 40

        return 0
''',

    'cms.py': '''
    def detect_from_finding(self, finding: Dict[str, Any], profile=None) -> int:
        """Detect any CMS (Joomla, Drupal, Magento, TYPO3, Concrete5)"""
        from ..core.constants import FindingTypes
        import logging
        logger = logging.getLogger(__name__)

        finding_type = finding.get('type', '').lower()
        description = finding.get('description', '').lower()

        # High confidence - Specific CMS detected
        cms_types = [FindingTypes.CMS_DETECTED, FindingTypes.CMS_JOOMLA,
                     FindingTypes.CMS_DRUPAL, FindingTypes.CMS_MAGENTO,
                     FindingTypes.CMS_TYPO3, FindingTypes.CMS_CONCRETE5]
        if finding_type in cms_types:
            logger.info(f"CMS plugin activating: {finding_type} detected")
            return 95

        # Medium - CMS indicators in description
        cms_indicators = ['joomla', 'drupal', 'magento', 'typo3', 'concrete5',
                          'administrator/index.php', 'user/login', 'admin/login']
        if any(ind in description for ind in cms_indicators):
            logger.info(f"CMS plugin activating: Found indicator '{description[:50]}'")
            return 85

        return 0
''',

    'nodejs.py': '''
    def detect_from_finding(self, finding: Dict[str, Any], profile=None) -> int:
        """Detect Node.js/Express from technology findings"""
        from ..core.constants import FindingTypes
        import logging
        logger = logging.getLogger(__name__)

        finding_type = finding.get('type', '').lower()
        description = finding.get('description', '').lower()

        # Perfect match - Node.js framework detected
        if finding_type in [FindingTypes.FRAMEWORK_NODEJS, FindingTypes.TECH_NODEJS]:
            logger.info("Node.js plugin activating: Framework detected")
            return 100

        # High confidence - Node.js/Express indicators
        nodejs_indicators = ['node.js', 'nodejs', 'express.js', 'express',
                             'npm', 'package.json', 'x-powered-by: express']
        if any(ind in description for ind in nodejs_indicators):
            logger.info(f"Node.js plugin activating: Found '{description[:50]}'")
            return 90

        # Express framework
        if finding_type == FindingTypes.FRAMEWORK_EXPRESS:
            return 100

        return 0
''',

    'php.py': '''
    def detect_from_finding(self, finding: Dict[str, Any], profile=None) -> int:
        """Detect PHP technology"""
        from ..core.constants import FindingTypes

        finding_type = finding.get('type', '').lower()
        description = finding.get('description', '').lower()

        # Perfect match - PHP detected
        if finding_type == FindingTypes.TECH_PHP:
            return 100

        # High confidence - PHP indicators
        php_indicators = ['php', 'index.php', 'phpinfo', 'composer.json',
                          'x-powered-by: php', '.php']
        if any(ind in description for ind in php_indicators):
            return 90

        return 0
''',

    'ruby_on_rails.py': '''
    def detect_from_finding(self, finding: Dict[str, Any], profile=None) -> int:
        """Detect Ruby on Rails from technology findings"""
        from ..core.constants import FindingTypes
        import logging
        logger = logging.getLogger(__name__)

        finding_type = finding.get('type', '').lower()
        description = finding.get('description', '').lower()

        # Perfect match - Rails framework detected
        if finding_type in [FindingTypes.FRAMEWORK_RAILS, FindingTypes.TECH_RUBY]:
            logger.info("Rails plugin activating: Framework detected")
            return 100

        # High confidence - Rails indicators
        rails_indicators = ['ruby on rails', 'rails', 'puma', 'unicorn',
                            'passenger', 'gemfile', '/rails/info']
        if any(ind in description for ind in rails_indicators):
            logger.info(f"Rails plugin activating: Found '{description[:50]}'")
            return 90

        return 0
''',

    'spring_boot.py': '''
    def detect_from_finding(self, finding: Dict[str, Any], profile=None) -> int:
        """Detect Spring Boot/Tomcat from technology findings"""
        from ..core.constants import FindingTypes
        import logging
        logger = logging.getLogger(__name__)

        finding_type = finding.get('type', '').lower()
        description = finding.get('description', '').lower()

        # Perfect match - Spring framework detected
        if finding_type in [FindingTypes.FRAMEWORK_SPRING, FindingTypes.TECH_JAVA]:
            logger.info("Spring Boot plugin activating: Framework detected")
            return 100

        # High confidence - Spring/Tomcat indicators
        spring_indicators = ['spring', 'actuator', 'tomcat', 'apache tomcat',
                             'jboss', '/actuator/', 'spring boot']
        if any(ind in description for ind in spring_indicators):
            logger.info(f"Spring plugin activating: Found '{description[:50]}'")
            return 90

        return 0
''',

    'nextjs.py': '''
    def detect_from_finding(self, finding: Dict[str, Any], profile=None) -> int:
        """Detect Next.js from technology findings"""
        from ..core.constants import FindingTypes
        import logging
        logger = logging.getLogger(__name__)

        finding_type = finding.get('type', '').lower()
        description = finding.get('description', '').lower()

        # Perfect match - Next.js framework detected
        if finding_type == FindingTypes.FRAMEWORK_NEXTJS:
            logger.info("Next.js plugin activating: Framework detected")
            return 100

        # High confidence - Next.js indicators
        nextjs_indicators = ['next.js', 'nextjs', '_next/', '__next_data__',
                             'vercel', 'x-powered-by: next.js']
        if any(ind in description for ind in nextjs_indicators):
            logger.info(f"Next.js plugin activating: Found '{description[:50]}'")
            return 90

        return 0
''',

    'python_web.py': '''
    def detect_from_finding(self, finding: Dict[str, Any], profile=None) -> int:
        """Detect Python web frameworks (Django, Flask, FastAPI)"""
        from ..core.constants import FindingTypes
        import logging
        logger = logging.getLogger(__name__)

        finding_type = finding.get('type', '').lower()
        description = finding.get('description', '').lower()

        # Perfect match - Python web frameworks detected
        python_frameworks = [FindingTypes.FRAMEWORK_DJANGO, FindingTypes.FRAMEWORK_FLASK,
                             FindingTypes.TECH_PYTHON]
        if finding_type in python_frameworks:
            logger.info(f"Python web plugin activating: {finding_type} detected")
            return 100

        # High confidence - Python framework indicators
        python_indicators = ['django', 'flask', 'fastapi', 'werkzeug',
                             'pyramid', 'bottle', 'tornado', 'gunicorn', 'uvicorn']
        if any(ind in description for ind in python_indicators):
            logger.info(f"Python web plugin activating: Found '{description[:50]}'")
            return 90

        return 0
'''
}


def inject_method_after_detect(file_path: Path, plugin_name: str, method_code: str):
    """Inject detect_from_finding() method after detect() method"""
    content = file_path.read_text()

    # Check if already migrated
    if 'def detect_from_finding(' in content:
        print(f"  [SKIP] {plugin_name} already has detect_from_finding()")
        return False

    # Find the end of detect() method
    lines = content.split('\n')
    detect_end_idx = None
    in_detect = False
    indent_level = 0

    for i, line in enumerate(lines):
        if 'def detect(self, port_info' in line:
            in_detect = True
            # Calculate indent level
            indent_level = len(line) - len(line.lstrip())
        elif in_detect and line.strip() and not line.strip().startswith('#'):
            # Check if we're back to class-level indent (method ended)
            current_indent = len(line) - len(line.lstrip())
            if current_indent == indent_level and (line.strip().startswith('def ') or line.strip().startswith('@')):
                detect_end_idx = i
                break

    if detect_end_idx is None:
        print(f"  [ERROR] Could not find detect() method end in {plugin_name}")
        return False

    # Insert the new method
    lines.insert(detect_end_idx, method_code)
    file_path.write_text('\n'.join(lines))
    print(f"  [OK] Migrated {plugin_name}")
    return True


def main():
    services_dir = Path('/home/kali/OSCP/crack/track/services')

    if not services_dir.exists():
        print(f"ERROR: Services directory not found: {services_dir}")
        return 1

    print("=" * 60)
    print("TIER 2 CMS/FRAMEWORK PLUGIN MIGRATION")
    print("=" * 60)
    print()

    migrated_count = 0
    for plugin_name, method_code in PLUGIN_MIGRATIONS.items():
        plugin_path = services_dir / plugin_name

        if not plugin_path.exists():
            print(f"  [WARN] Plugin not found: {plugin_name}")
            continue

        if inject_method_after_detect(plugin_path, plugin_name, method_code):
            migrated_count += 1

    print()
    print("=" * 60)
    print(f"MIGRATION COMPLETE: {migrated_count}/8 plugins migrated")
    print("=" * 60)

    return 0 if migrated_count == 8 else 1


if __name__ == '__main__':
    sys.exit(main())
