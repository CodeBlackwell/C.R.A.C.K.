"""
Unit tests for Tier 2 CMS/Framework plugins finding-based activation

Tests that plugins correctly detect and activate based on CMS/framework findings
from whatweb, wappalyzer, or manual verification.

Plugins tested:
1. WordPressPlugin
2. CMSPlugin
3. NodeJSPlugin
4. PHPPlugin
5. RubyOnRailsPlugin
6. SpringBootPlugin
7. NextJSPlugin
8. PythonWebPlugin
"""

import pytest
from crack.track.services.wordpress import WordPressPlugin
from crack.track.services.cms import CMSPlugin
from crack.track.services.nodejs import NodeJSPlugin
from crack.track.services.php import PHPPlugin
from crack.track.services.ruby_on_rails import RubyOnRailsPlugin
from crack.track.services.spring_boot import SpringBootPlugin
from crack.track.services.nextjs import NextJSPlugin
from crack.track.services.python_web import PythonWebPlugin
from crack.track.core.constants import FindingTypes


# ===== WORDPRESS PLUGIN TESTS =====

def test_wordpress_activates_on_cms_wordpress():
    """WordPress plugin activates on CMS_WORDPRESS finding type"""
    plugin = WordPressPlugin()
    finding = {
        'type': FindingTypes.CMS_WORDPRESS,
        'description': 'WordPress 6.4.2 detected',
        'source': 'whatweb'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 100, "Perfect match should return 100"


def test_wordpress_activates_on_wp_content_in_description():
    """WordPress plugin activates when 'wp-content' found in description"""
    plugin = WordPressPlugin()
    finding = {
        'type': 'directory',
        'description': 'Found directory: /wp-content/themes/twentytwentythree',
        'source': 'gobuster'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 90, "WP indicator should return 90"


def test_wordpress_activates_on_wpscan_indicator():
    """WordPress plugin activates on wpscan mention"""
    plugin = WordPressPlugin()
    finding = {
        'type': 'vulnerability',
        'description': 'wpscan reports vulnerable plugin: contact-form-7',
        'source': 'manual'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 90


def test_wordpress_medium_confidence_generic_cms():
    """WordPress plugin medium confidence on generic PHP CMS"""
    plugin = WordPressPlugin()
    finding = {
        'type': FindingTypes.CMS_DETECTED,
        'description': 'Generic PHP CMS detected',
        'source': 'whatweb'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 40, "Generic PHP CMS should return 40"


# ===== CMS PLUGIN TESTS =====

def test_cms_plugin_activates_on_joomla():
    """CMS plugin activates on Joomla detection"""
    plugin = CMSPlugin()
    finding = {
        'type': FindingTypes.CMS_JOOMLA,
        'description': 'Joomla 4.0 detected',
        'source': 'whatweb'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 95


def test_cms_plugin_activates_on_drupal():
    """CMS plugin activates on Drupal detection"""
    plugin = CMSPlugin()
    finding = {
        'type': FindingTypes.CMS_DRUPAL,
        'description': 'Drupal 9.x detected',
        'source': 'whatweb'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 95


def test_cms_plugin_activates_on_magento():
    """CMS plugin activates on Magento detection"""
    plugin = CMSPlugin()
    finding = {
        'type': FindingTypes.CMS_MAGENTO,
        'description': 'Magento e-commerce platform detected',
        'source': 'manual'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 95


def test_cms_plugin_activates_on_indicator_in_description():
    """CMS plugin activates when 'joomla' found in description"""
    plugin = CMSPlugin()
    finding = {
        'type': 'directory',
        'description': 'Found /administrator/index.php (Joomla admin panel)',
        'source': 'gobuster'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 85


# ===== NODEJS PLUGIN TESTS =====

def test_nodejs_activates_on_framework_nodejs():
    """Node.js plugin activates on FRAMEWORK_NODEJS"""
    plugin = NodeJSPlugin()
    finding = {
        'type': FindingTypes.FRAMEWORK_NODEJS,
        'description': 'Node.js v18.16.0 detected',
        'source': 'whatweb'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 100


def test_nodejs_activates_on_express_framework():
    """Node.js plugin activates on FRAMEWORK_EXPRESS"""
    plugin = NodeJSPlugin()
    finding = {
        'type': FindingTypes.FRAMEWORK_EXPRESS,
        'description': 'Express.js framework detected',
        'source': 'whatweb'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 100


def test_nodejs_activates_on_package_json():
    """Node.js plugin activates when package.json found"""
    plugin = NodeJSPlugin()
    finding = {
        'type': 'file',
        'description': 'Found exposed package.json with dependencies',
        'source': 'manual'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 90


def test_nodejs_activates_on_express_header():
    """Node.js plugin activates on X-Powered-By: Express"""
    plugin = NodeJSPlugin()
    finding = {
        'type': 'service_banner',
        'description': 'HTTP headers: X-Powered-By: Express',
        'source': 'curl'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 90


# ===== PHP PLUGIN TESTS =====

def test_php_activates_on_tech_php():
    """PHP plugin activates on TECH_PHP"""
    plugin = PHPPlugin()
    finding = {
        'type': FindingTypes.TECH_PHP,
        'description': 'PHP/8.1.0 detected',
        'source': 'nmap'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 100


def test_php_activates_on_phpinfo():
    """PHP plugin activates when phpinfo detected"""
    plugin = PHPPlugin()
    finding = {
        'type': 'file',
        'description': 'Found phpinfo.php exposing configuration',
        'source': 'ffuf'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 90


def test_php_activates_on_composer_json():
    """PHP plugin activates on composer.json"""
    plugin = PHPPlugin()
    finding = {
        'type': 'file',
        'description': 'composer.json found with dependencies',
        'source': 'gobuster'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 90


# ===== RUBY ON RAILS PLUGIN TESTS =====

def test_rails_activates_on_framework_rails():
    """Rails plugin activates on FRAMEWORK_RAILS"""
    plugin = RubyOnRailsPlugin()
    finding = {
        'type': FindingTypes.FRAMEWORK_RAILS,
        'description': 'Ruby on Rails 7.0.4 detected',
        'source': 'whatweb'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 100


def test_rails_activates_on_tech_ruby():
    """Rails plugin activates on TECH_RUBY"""
    plugin = RubyOnRailsPlugin()
    finding = {
        'type': FindingTypes.TECH_RUBY,
        'description': 'Ruby 3.1.0 application server',
        'source': 'nmap'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 100


def test_rails_activates_on_puma_server():
    """Rails plugin activates when Puma server detected"""
    plugin = RubyOnRailsPlugin()
    finding = {
        'type': 'service_banner',
        'description': 'Server: Puma 5.6.4',
        'source': 'curl'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 90


def test_rails_activates_on_gemfile():
    """Rails plugin activates on Gemfile discovery"""
    plugin = RubyOnRailsPlugin()
    finding = {
        'type': 'file',
        'description': 'Found exposed Gemfile with rails gem',
        'source': 'manual'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 90


# ===== SPRING BOOT PLUGIN TESTS =====

def test_spring_activates_on_framework_spring():
    """Spring Boot plugin activates on FRAMEWORK_SPRING"""
    plugin = SpringBootPlugin()
    finding = {
        'type': FindingTypes.FRAMEWORK_SPRING,
        'description': 'Spring Boot 3.0.0 detected',
        'source': 'whatweb'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 100


def test_spring_activates_on_tech_java():
    """Spring Boot plugin activates on TECH_JAVA"""
    plugin = SpringBootPlugin()
    finding = {
        'type': FindingTypes.TECH_JAVA,
        'description': 'Java application server detected',
        'source': 'nmap'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 100


def test_spring_activates_on_actuator_endpoint():
    """Spring Boot plugin activates on /actuator/ discovery"""
    plugin = SpringBootPlugin()
    finding = {
        'type': 'directory',
        'description': 'Found /actuator/health endpoint exposed',
        'source': 'gobuster'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 90


def test_spring_activates_on_tomcat():
    """Spring Boot plugin activates on Apache Tomcat"""
    plugin = SpringBootPlugin()
    finding = {
        'type': 'service_banner',
        'description': 'Server: Apache Tomcat/9.0.50',
        'source': 'nmap'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 90


# ===== NEXTJS PLUGIN TESTS =====

def test_nextjs_activates_on_framework_nextjs():
    """Next.js plugin activates on FRAMEWORK_NEXTJS"""
    plugin = NextJSPlugin()
    finding = {
        'type': FindingTypes.FRAMEWORK_NEXTJS,
        'description': 'Next.js 13.4.0 detected',
        'source': 'whatweb'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 100


def test_nextjs_activates_on_next_directory():
    """Next.js plugin activates on /_next/ discovery"""
    plugin = NextJSPlugin()
    finding = {
        'type': 'directory',
        'description': 'Found /_next/static/chunks/ directory',
        'source': 'gobuster'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 90


def test_nextjs_activates_on_vercel():
    """Next.js plugin activates on Vercel deployment"""
    plugin = NextJSPlugin()
    finding = {
        'type': 'service_banner',
        'description': 'Server: Vercel',
        'source': 'curl'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 90


def test_nextjs_activates_on_next_data():
    """Next.js plugin activates on __NEXT_DATA__ discovery"""
    plugin = NextJSPlugin()
    finding = {
        'type': 'vulnerability',
        'description': '__NEXT_DATA__ JSON blob exposes internal routes',
        'source': 'manual'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 90


# ===== PYTHON WEB PLUGIN TESTS =====

def test_python_web_activates_on_framework_django():
    """Python web plugin activates on FRAMEWORK_DJANGO"""
    plugin = PythonWebPlugin()
    finding = {
        'type': FindingTypes.FRAMEWORK_DJANGO,
        'description': 'Django 4.2.0 detected',
        'source': 'whatweb'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 100


def test_python_web_activates_on_framework_flask():
    """Python web plugin activates on FRAMEWORK_FLASK"""
    plugin = PythonWebPlugin()
    finding = {
        'type': FindingTypes.FRAMEWORK_FLASK,
        'description': 'Flask application detected',
        'source': 'whatweb'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 100


def test_python_web_activates_on_tech_python():
    """Python web plugin activates on TECH_PYTHON"""
    plugin = PythonWebPlugin()
    finding = {
        'type': FindingTypes.TECH_PYTHON,
        'description': 'Python 3.11.0 web application',
        'source': 'nmap'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 100


def test_python_web_activates_on_werkzeug():
    """Python web plugin activates on Werkzeug detection"""
    plugin = PythonWebPlugin()
    finding = {
        'type': 'service_banner',
        'description': 'Server: Werkzeug/2.3.0 Python/3.11.0',
        'source': 'curl'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 90


def test_python_web_activates_on_gunicorn():
    """Python web plugin activates on Gunicorn server"""
    plugin = PythonWebPlugin()
    finding = {
        'type': 'service_banner',
        'description': 'Server: gunicorn/20.1.0',
        'source': 'nmap'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 90


def test_python_web_activates_on_fastapi():
    """Python web plugin activates on FastAPI framework"""
    plugin = PythonWebPlugin()
    finding = {
        'type': 'vulnerability',
        'description': 'FastAPI /docs endpoint exposed',
        'source': 'manual'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 90


# ===== EDGE CASES =====

def test_all_plugins_return_zero_on_irrelevant_finding():
    """All plugins return 0 confidence for irrelevant findings"""
    plugins = [
        WordPressPlugin(),
        CMSPlugin(),
        NodeJSPlugin(),
        PHPPlugin(),
        RubyOnRailsPlugin(),
        SpringBootPlugin(),
        NextJSPlugin(),
        PythonWebPlugin()
    ]

    irrelevant_finding = {
        'type': 'smb_share',
        'description': 'Found SMB share \\\\server\\backup',
        'source': 'enum4linux'
    }

    for plugin in plugins:
        confidence = plugin.detect_from_finding(irrelevant_finding)
        assert confidence == 0, f"{plugin.name} should return 0 for irrelevant finding"


def test_plugins_handle_missing_description():
    """Plugins handle findings without description field"""
    plugin = WordPressPlugin()
    finding = {
        'type': FindingTypes.CMS_WORDPRESS,
        'source': 'whatweb'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 100  # Should still match on type


def test_plugins_handle_case_insensitive():
    """Plugins match indicators case-insensitively"""
    plugin = NodeJSPlugin()
    finding = {
        'type': 'file',
        'description': 'Found PACKAGE.JSON with Node.JS dependencies',
        'source': 'manual'
    }

    confidence = plugin.detect_from_finding(finding)
    assert confidence == 90  # Should match despite uppercase


# ===== INTEGRATION TESTS =====

def test_wordpress_vs_generic_cms_priority():
    """WordPress plugin has higher confidence than generic CMS"""
    wp_plugin = WordPressPlugin()
    cms_plugin = CMSPlugin()

    wordpress_finding = {
        'type': FindingTypes.CMS_WORDPRESS,
        'description': 'WordPress 6.4 detected',
        'source': 'whatweb'
    }

    wp_confidence = wp_plugin.detect_from_finding(wordpress_finding)
    cms_confidence = cms_plugin.detect_from_finding(wordpress_finding)

    # Both should activate, but WordPress plugin should be more confident
    assert wp_confidence == 100
    assert cms_confidence == 0  # CMS plugin doesn't match CMS_WORDPRESS specifically


def test_nodejs_vs_nextjs_differentiation():
    """Node.js and Next.js plugins differentiate correctly"""
    nodejs_plugin = NodeJSPlugin()
    nextjs_plugin = NextJSPlugin()

    nextjs_finding = {
        'type': FindingTypes.FRAMEWORK_NEXTJS,
        'description': 'Next.js application detected',
        'source': 'whatweb'
    }

    nodejs_confidence = nodejs_plugin.detect_from_finding(nextjs_finding)
    nextjs_confidence = nextjs_plugin.detect_from_finding(nextjs_finding)

    # Next.js plugin should be more confident for Next.js finding
    assert nextjs_confidence == 100
    assert nodejs_confidence == 0  # Node.js plugin doesn't match FRAMEWORK_NEXTJS


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
