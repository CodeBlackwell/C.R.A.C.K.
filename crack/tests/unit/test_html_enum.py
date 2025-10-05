#!/usr/bin/env python3
"""
Unit tests for HTMLEnumerator module
Tests HTML parsing, form extraction, and content discovery
"""

import pytest
from unittest.mock import Mock, patch
from collections import defaultdict

from crack.web.html_enum import HTMLEnumerator


class TestHTMLEnumerator:
    """Test HTMLEnumerator functionality"""

    @pytest.mark.unit
    @pytest.mark.web
    @pytest.mark.fast
    def test_init(self, sample_html_with_forms):
        """Test HTMLEnumerator initialization"""
        enumerator = HTMLEnumerator(sample_html_with_forms, base_url="http://test.com", full_output=True)

        assert enumerator.base_url == "http://test.com"
        assert enumerator.full_output is True
        assert enumerator.forms == []
        assert enumerator.comments == []
        assert isinstance(enumerator.endpoints, set)
        assert isinstance(enumerator.interesting, defaultdict)
        assert isinstance(enumerator.internal_links, set)

    @pytest.mark.unit
    @pytest.mark.web
    def test_extract_forms(self, sample_html_with_forms):
        """Test form extraction from HTML"""
        enumerator = HTMLEnumerator(sample_html_with_forms, base_url="http://test.com")
        enumerator.extract_forms()

        assert len(enumerator.forms) == 3

        # Check login form
        login_form = enumerator.forms[0]
        assert login_form['action'] == '/login.php'
        assert login_form['method'] == 'POST'
        assert len(login_form['inputs']) == 4  # username, password, csrf_token, submit

        # Check for password field detection
        password_input = next((i for i in login_form['inputs'] if i['type'] == 'password'), None)
        assert password_input is not None
        assert password_input['name'] == 'password'

        # Check for hidden field detection
        hidden_input = next((i for i in login_form['inputs'] if i['type'] == 'hidden'), None)
        assert hidden_input is not None
        assert hidden_input['name'] == 'csrf_token'
        assert hidden_input['value'] == 'abc123def456'

        # Check file upload form
        upload_form = enumerator.forms[1]
        assert upload_form['action'] == '/upload.php'
        assert upload_form['method'] == 'POST'

        file_input = next((i for i in upload_form['inputs'] if i['type'] == 'file'), None)
        assert file_input is not None

        # Check search form (GET method)
        search_form = enumerator.forms[2]
        assert search_form['action'] == '/search.php'
        assert search_form['method'] == 'GET'

    @pytest.mark.unit
    @pytest.mark.web
    def test_extract_forms_interesting_findings(self, sample_html_with_forms):
        """Test detection of interesting form elements"""
        enumerator = HTMLEnumerator(sample_html_with_forms)
        enumerator.extract_forms()

        # Check interesting findings
        assert len(enumerator.interesting['passwords']) > 0
        assert 'Password field: password' in enumerator.interesting['passwords']

        assert len(enumerator.interesting['file_uploads']) > 0
        assert any('upload_file' in item for item in enumerator.interesting['file_uploads'])

        assert len(enumerator.interesting['hidden_fields']) > 0
        assert 'csrf_token=abc123def456' in enumerator.interesting['hidden_fields']

    @pytest.mark.unit
    @pytest.mark.web
    def test_extract_forms_endpoints(self, sample_html_with_forms):
        """Test that form actions are added to endpoints"""
        enumerator = HTMLEnumerator(sample_html_with_forms)
        enumerator.extract_forms()

        assert '/login.php' in enumerator.endpoints
        assert '/upload.php' in enumerator.endpoints
        assert '/search.php' in enumerator.endpoints

    @pytest.mark.unit
    @pytest.mark.web
    def test_extract_comments(self, sample_html_with_forms):
        """Test comment extraction from HTML"""
        enumerator = HTMLEnumerator(sample_html_with_forms)
        enumerator.extract_comments()

        assert len(enumerator.comments) >= 2

        # Check for specific comments
        comments_text = ' '.join(enumerator.comments)
        assert 'TODO: Fix SQL injection' in comments_text
        assert 'admin password is admin123' in comments_text

    @pytest.mark.unit
    @pytest.mark.web
    def test_extract_endpoints_ajax(self, sample_html_with_forms):
        """Test AJAX endpoint extraction from JavaScript"""
        enumerator = HTMLEnumerator(sample_html_with_forms)
        enumerator.extract_endpoints()

        # Should find AJAX endpoints from JavaScript
        assert '/api/v1/users' in enumerator.endpoints
        assert '/ajax/data.json' in enumerator.endpoints
        assert '/ajax/validate.php' in enumerator.endpoints

    @pytest.mark.unit
    @pytest.mark.web
    def test_extract_links(self, sample_html_with_forms):
        """Test link extraction"""
        enumerator = HTMLEnumerator(sample_html_with_forms, base_url="http://test.com")
        enumerator.extract_links()

        # Should categorize internal vs external links
        assert '/admin.php' in enumerator.internal_links
        # External links are not added to internal_links
        assert 'http://external.com' not in enumerator.internal_links

    @pytest.mark.unit
    @pytest.mark.web
    def test_minimal_html(self, sample_html_minimal):
        """Test parsing minimal HTML with no forms"""
        enumerator = HTMLEnumerator(sample_html_minimal)
        enumerator.extract_forms()
        enumerator.extract_comments()
        enumerator.extract_endpoints()

        assert len(enumerator.forms) == 0
        assert len(enumerator.comments) == 0
        # Might still have endpoints from links
        assert isinstance(enumerator.endpoints, set)

    @pytest.mark.unit
    @pytest.mark.web
    def test_form_with_select_and_textarea(self):
        """Test form extraction with select and textarea elements"""
        html = """
        <html>
        <body>
            <form action="/submit" method="POST">
                <select name="category">
                    <option value="1">Option 1</option>
                    <option value="2">Option 2</option>
                </select>
                <textarea name="comment">Default text</textarea>
                <input type="text" name="text_field" value="default">
            </form>
        </body>
        </html>
        """

        enumerator = HTMLEnumerator(html)
        enumerator.extract_forms()

        assert len(enumerator.forms) == 1
        form = enumerator.forms[0]

        # Check all input types are captured
        input_names = [inp['name'] for inp in form['inputs']]
        assert 'category' in input_names
        assert 'comment' in input_names
        assert 'text_field' in input_names

        # Check tags are preserved
        select_input = next((i for i in form['inputs'] if i['name'] == 'category'), None)
        assert select_input['tag'] == 'select'

        textarea_input = next((i for i in form['inputs'] if i['name'] == 'comment'), None)
        assert textarea_input['tag'] == 'textarea'

    @pytest.mark.unit
    @pytest.mark.web
    def test_form_without_action(self):
        """Test form with missing action attribute"""
        html = """
        <html>
        <body>
            <form method="POST">
                <input type="text" name="field1">
            </form>
        </body>
        </html>
        """

        enumerator = HTMLEnumerator(html)
        enumerator.extract_forms()

        assert len(enumerator.forms) == 1
        # Should default to '/' when action is missing
        assert enumerator.forms[0]['action'] == '/'

    @pytest.mark.unit
    @pytest.mark.web
    def test_form_without_method(self):
        """Test form with missing method attribute"""
        html = """
        <html>
        <body>
            <form action="/submit">
                <input type="text" name="field1">
            </form>
        </body>
        </html>
        """

        enumerator = HTMLEnumerator(html)
        enumerator.extract_forms()

        assert len(enumerator.forms) == 1
        # Should default to 'GET' when method is missing
        assert enumerator.forms[0]['method'] == 'GET'

    @pytest.mark.unit
    @pytest.mark.web
    def test_unnamed_inputs(self):
        """Test handling of inputs without name attributes"""
        html = """
        <html>
        <body>
            <form action="/submit">
                <input type="text">
                <input type="submit" value="Submit">
            </form>
        </body>
        </html>
        """

        enumerator = HTMLEnumerator(html)
        enumerator.extract_forms()

        form = enumerator.forms[0]
        # Should use 'unnamed' for inputs without name
        unnamed_inputs = [i for i in form['inputs'] if i['name'] == 'unnamed']
        assert len(unnamed_inputs) > 0

    @pytest.mark.unit
    @pytest.mark.web
    def test_javascript_comments(self):
        """Test extraction of JavaScript comments"""
        html = """
        <html>
        <body>
            <script>
            // This is a JS comment with sensitive info
            /* Multi-line JS comment
               with API key: sk_test_123456 */
            var apiKey = 'exposed_key';
            </script>
        </body>
        </html>
        """

        enumerator = HTMLEnumerator(html)
        enumerator.extract_comments()

        # Should extract JS comments
        comments_text = ' '.join(enumerator.comments)
        assert 'sensitive info' in comments_text or 'API key' in comments_text

    @pytest.mark.unit
    @pytest.mark.web
    @pytest.mark.fast
    def test_endpoint_deduplication(self):
        """Test that endpoints are deduplicated"""
        html = """
        <html>
        <body>
            <form action="/submit" method="POST"></form>
            <form action="/submit" method="GET"></form>
            <a href="/submit">Link</a>
            <script>
            fetch('/submit');
            fetch('/submit');
            </script>
        </body>
        </html>
        """

        enumerator = HTMLEnumerator(html)
        enumerator.extract_forms()
        enumerator.extract_endpoints()

        # Should only have one '/submit' despite multiple references
        submit_count = list(enumerator.endpoints).count('/submit')
        assert submit_count == 1

    @pytest.mark.unit
    @pytest.mark.web
    def test_relative_url_handling(self):
        """Test handling of relative URLs with base_url"""
        html = """
        <html>
        <body>
            <a href="/page1">Absolute path</a>
            <a href="page2">Relative path</a>
            <a href="../page3">Parent path</a>
            <a href="http://external.com/page">External</a>
        </body>
        </html>
        """

        enumerator = HTMLEnumerator(html, base_url="http://test.com/dir/")
        enumerator.extract_links()

        # Check internal links are properly resolved
        assert '/page1' in enumerator.internal_links
        # Relative URLs should be resolved relative to base_url
        # The exact resolution depends on implementation

    @pytest.mark.unit
    @pytest.mark.web
    def test_malformed_html(self):
        """Test handling of malformed HTML"""
        malformed_html = """
        <html>
        <body>
            <form action="/test" method="POST"
                <input type="text" name="field1">
                <input type="text name="field2">
            </form
        </body>
        """

        # Should not raise an exception
        enumerator = HTMLEnumerator(malformed_html)
        enumerator.extract_forms()

        # BeautifulSoup should handle malformed HTML gracefully
        assert isinstance(enumerator.forms, list)

    @pytest.mark.unit
    @pytest.mark.web
    def test_empty_html(self):
        """Test handling of empty HTML content"""
        enumerator = HTMLEnumerator("")

        enumerator.extract_forms()
        enumerator.extract_comments()
        enumerator.extract_endpoints()

        assert enumerator.forms == []
        assert enumerator.comments == []
        assert len(enumerator.endpoints) == 0

    @pytest.mark.unit
    @pytest.mark.web
    def test_interesting_findings_categorization(self):
        """Test categorization of interesting findings"""
        html = """
        <html>
        <body>
            <form action="/admin" method="POST">
                <input type="password" name="admin_pass">
                <input type="hidden" name="token" value="secret123">
                <input type="file" name="upload">
                <input type="hidden" name="debug" value="true">
            </form>
        </body>
        </html>
        """

        enumerator = HTMLEnumerator(html)
        enumerator.extract_forms()

        # Should categorize interesting findings
        assert len(enumerator.interesting['passwords']) >= 1
        assert len(enumerator.interesting['hidden_fields']) >= 2
        assert len(enumerator.interesting['file_uploads']) >= 1

        # Check specific categorizations
        assert any('admin_pass' in item for item in enumerator.interesting['passwords'])
        assert any('debug=true' in item for item in enumerator.interesting['hidden_fields'])