"""
Unit tests for Docker parser.

Tests parsing logic for groups, containers, images, and socket access.
"""

import pytest
from crack.reference.chains.parsing.docker_parser import DockerParser
from crack.reference.chains.parsing.registry import ParserRegistry


# Sample outputs for testing
GROUPS_OUTPUT_WITH_DOCKER = "kali docker sudo"
GROUPS_OUTPUT_NO_DOCKER = "www-data adm"
ID_OUTPUT_WITH_DOCKER = "uid=1000(kali) gid=1000(kali) groups=1000(kali),999(docker),27(sudo)"
ID_OUTPUT_NO_DOCKER = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"

DOCKER_PS_EMPTY = """CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES"""

DOCKER_PS_OUTPUT = """CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
abc123def456   alpine    "sh"      2 hours   Up 2 hrs            test
def456abc123   ubuntu    "bash"    1 day     Up 1 day            webapp"""

DOCKER_IMAGES_EMPTY = """REPOSITORY   TAG       IMAGE ID       CREATED       SIZE"""

DOCKER_IMAGES_OUTPUT = """REPOSITORY   TAG       IMAGE ID       CREATED       SIZE
alpine       latest    abc123def456   2 weeks ago   5.6MB
ubuntu       20.04     def456abc123   3 weeks ago   72.8MB
busybox      latest    789abc123def   1 month ago   1.2MB"""

SOCKET_PERMISSIONS_ACCESSIBLE = "srw-rw---- 1 root docker 0 Oct 13 10:00 /var/run/docker.sock"
SOCKET_PERMISSIONS_DENIED = "srw------- 1 root root 0 Oct 13 10:00 /var/run/docker.sock"

ERROR_OUTPUT = "docker: Cannot connect to the Docker daemon. Is the docker daemon running?"


class TestDockerParser:
    """Test Docker parser functionality"""

    @pytest.fixture
    def parser(self):
        """Create parser instance"""
        return DockerParser()

    @pytest.fixture
    def empty_step(self):
        """Empty step dict for testing"""
        return {}

    def test_parser_registration(self):
        """PROVES: DockerParser auto-registers via decorator"""
        # Parser should be in registry
        parser = ParserRegistry.get_parser_by_name('docker')
        assert parser is not None
        assert isinstance(parser, DockerParser)

    def test_parser_name(self, parser):
        """PROVES: Parser has correct name"""
        assert parser.name == "docker"

    def test_can_parse_groups_command(self, parser, empty_step):
        """PROVES: Detects groups command"""
        assert parser.can_parse(empty_step, "groups")
        assert parser.can_parse(empty_step, "GROUPS")  # Case insensitive
        assert parser.can_parse(empty_step, "groups && id")

    def test_can_parse_docker_ps_command(self, parser, empty_step):
        """PROVES: Detects docker ps command"""
        assert parser.can_parse(empty_step, "docker ps")
        assert parser.can_parse(empty_step, "docker ps -a")
        assert parser.can_parse(empty_step, "DOCKER PS")  # Case insensitive

    def test_can_parse_docker_images_command(self, parser, empty_step):
        """PROVES: Detects docker images command"""
        assert parser.can_parse(empty_step, "docker images")
        assert parser.can_parse(empty_step, "docker image ls")

    def test_can_parse_socket_check_command(self, parser, empty_step):
        """PROVES: Detects socket permission check"""
        assert parser.can_parse(empty_step, "ls -la /var/run/docker.sock")
        assert parser.can_parse(empty_step, "stat /var/run/docker.sock")

    def test_cannot_parse_unrelated_command(self, parser, empty_step):
        """PROVES: Rejects unrelated commands"""
        assert not parser.can_parse(empty_step, "cat /etc/passwd")
        assert not parser.can_parse(empty_step, "sudo -l")
        assert not parser.can_parse(empty_step, "find / -perm -4000")

    def test_parse_groups_with_docker(self, parser, empty_step):
        """PROVES: Extracts docker group membership from groups command"""
        result = parser.parse(GROUPS_OUTPUT_WITH_DOCKER, empty_step, "groups")

        assert result.success
        assert result.findings['in_docker_group'] is True
        assert 'docker' in result.findings['user_groups']
        assert 'kali' in result.findings['user_groups']
        assert 'sudo' in result.findings['user_groups']

    def test_parse_groups_no_docker(self, parser, empty_step):
        """PROVES: Handles missing docker group"""
        result = parser.parse(GROUPS_OUTPUT_NO_DOCKER, empty_step, "groups")

        assert not result.success  # No docker group = failure
        assert result.findings['in_docker_group'] is False
        assert 'docker' not in result.findings['user_groups']
        assert 'www-data' in result.findings['user_groups']
        assert len(result.warnings) > 0

    def test_parse_id_with_docker(self, parser, empty_step):
        """PROVES: Extracts docker group from id command output"""
        result = parser.parse(ID_OUTPUT_WITH_DOCKER, empty_step, "id")

        assert result.success
        assert result.findings['in_docker_group'] is True
        assert 'docker' in result.findings['user_groups']
        assert 'kali' in result.findings['user_groups']
        assert 'sudo' in result.findings['user_groups']

    def test_parse_id_no_docker(self, parser, empty_step):
        """PROVES: Handles id output without docker group"""
        result = parser.parse(ID_OUTPUT_NO_DOCKER, empty_step, "id")

        assert not result.success
        assert result.findings['in_docker_group'] is False
        assert 'docker' not in result.findings['user_groups']

    def test_parse_docker_ps_empty(self, parser, empty_step):
        """PROVES: Handles docker ps with no running containers"""
        result = parser.parse(DOCKER_PS_EMPTY, empty_step, "docker ps")

        assert result.success  # Empty is success (daemon accessible)
        assert result.findings['docker_socket_accessible'] is True
        assert result.findings['running_containers'] == []
        assert result.findings['container_count'] == 0

    def test_parse_docker_ps_with_containers(self, parser, empty_step):
        """PROVES: Extracts running container info"""
        result = parser.parse(DOCKER_PS_OUTPUT, empty_step, "docker ps")

        assert result.success
        assert result.findings['docker_socket_accessible'] is True
        assert len(result.findings['running_containers']) == 2
        assert result.findings['container_count'] == 2

        # Check first container
        container1 = result.findings['running_containers'][0]
        assert container1['id'] == 'abc123def456'
        assert container1['image'] == 'alpine'
        assert container1['name'] == 'test'

        # Check second container
        container2 = result.findings['running_containers'][1]
        assert container2['id'] == 'def456abc123'
        assert container2['image'] == 'ubuntu'
        assert container2['name'] == 'webapp'

    def test_parse_docker_images_empty(self, parser, empty_step):
        """PROVES: Handles docker images with no cached images"""
        result = parser.parse(DOCKER_IMAGES_EMPTY, empty_step, "docker images")

        assert result.findings['available_images'] == []
        assert result.findings['image_count'] == 0
        # Should default to alpine
        assert result.variables['<IMAGE_NAME>'] == 'alpine'
        assert len(result.warnings) > 0  # Should warn about default

    def test_parse_docker_images_with_images(self, parser, empty_step):
        """PROVES: Extracts available images"""
        result = parser.parse(DOCKER_IMAGES_OUTPUT, empty_step, "docker images")

        assert result.success
        assert len(result.findings['available_images']) == 3
        assert result.findings['image_count'] == 3

        # Check image parsing
        images = result.findings['available_images']
        assert any(img['repository'] == 'alpine' for img in images)
        assert any(img['repository'] == 'ubuntu' for img in images)
        assert any(img['repository'] == 'busybox' for img in images)

        # Check names
        alpine = next(img for img in images if img['repository'] == 'alpine')
        assert alpine['name'] == 'alpine'  # latest tag uses short name
        assert alpine['tag'] == 'latest'

        ubuntu = next(img for img in images if img['repository'] == 'ubuntu')
        assert ubuntu['name'] == 'ubuntu:20.04'  # non-latest includes tag
        assert ubuntu['tag'] == '20.04'

    def test_auto_select_first_image(self, parser, empty_step):
        """PROVES: Auto-fills <IMAGE_NAME> with first available image"""
        result = parser.parse(DOCKER_IMAGES_OUTPUT, empty_step, "docker images")

        # Should auto-select first image (alpine)
        assert result.variables['<IMAGE_NAME>'] == 'alpine'

    def test_default_alpine_fallback(self, parser, empty_step):
        """PROVES: Defaults to 'alpine' if no images available"""
        result = parser.parse(DOCKER_IMAGES_EMPTY, empty_step, "docker images")

        # No images available, should default to alpine
        assert result.variables['<IMAGE_NAME>'] == 'alpine'
        assert 'alpine' in result.warnings[0].lower()

    def test_socket_access_detection_accessible(self, parser, empty_step):
        """PROVES: Detects accessible socket permissions"""
        result = parser.parse(
            SOCKET_PERMISSIONS_ACCESSIBLE,
            empty_step,
            "ls -la /var/run/docker.sock"
        )

        assert result.findings['docker_socket_accessible'] is True

    def test_socket_access_detection_denied(self, parser, empty_step):
        """PROVES: Detects inaccessible socket permissions"""
        result = parser.parse(
            SOCKET_PERMISSIONS_DENIED,
            empty_step,
            "ls -la /var/run/docker.sock"
        )

        assert result.findings['docker_socket_accessible'] is False

    def test_docker_socket_path_variable(self, parser, empty_step):
        """PROVES: Always sets <DOCKER_SOCKET_PATH> variable"""
        result = parser.parse(GROUPS_OUTPUT_WITH_DOCKER, empty_step, "groups")

        # Socket path should always be set
        assert '<DOCKER_SOCKET_PATH>' in result.variables
        assert result.variables['<DOCKER_SOCKET_PATH>'] == '/var/run/docker.sock'

    def test_error_output_detection(self, parser, empty_step):
        """PROVES: Detects error output"""
        result = parser.parse(ERROR_OUTPUT, empty_step, "docker ps")

        assert not result.success
        assert len(result.warnings) > 0
        # Check that warnings indicate no docker access
        warnings_text = ' '.join(result.warnings).lower()
        assert 'not in docker group' in warnings_text or 'not accessible' in warnings_text

    def test_combined_group_and_socket_check(self, parser, empty_step):
        """PROVES: Handles combined commands (groups && docker ps)"""
        combined_output = f"{GROUPS_OUTPUT_WITH_DOCKER}\n{DOCKER_PS_OUTPUT}"
        result = parser.parse(combined_output, empty_step, "groups && docker ps")

        # Should extract both group membership and container info
        assert result.success
        assert result.findings['in_docker_group'] is True
        assert result.findings['docker_socket_accessible'] is True
        assert len(result.findings['running_containers']) == 2

    def test_no_docker_group_and_no_socket(self, parser, empty_step):
        """PROVES: Handles failure case (no docker access at all)"""
        result = parser.parse(GROUPS_OUTPUT_NO_DOCKER, empty_step, "groups")

        assert not result.success
        assert result.findings['in_docker_group'] is False
        assert result.findings['docker_socket_accessible'] is False
        assert len(result.warnings) > 0

    def test_image_name_variable_priority(self, parser, empty_step):
        """PROVES: Uses first available image, falls back to alpine"""
        # Test with busybox as first image
        custom_output = """REPOSITORY   TAG       IMAGE ID       CREATED       SIZE
busybox      latest    789abc123def   1 month ago   1.2MB
alpine       latest    abc123def456   2 weeks ago   5.6MB"""

        result = parser.parse(custom_output, empty_step, "docker images")

        # Should select busybox (first in list)
        assert result.variables['<IMAGE_NAME>'] == 'busybox'

    def test_findings_structure_completeness(self, parser, empty_step):
        """PROVES: Findings dict has all expected keys"""
        result = parser.parse(GROUPS_OUTPUT_WITH_DOCKER, empty_step, "groups")

        # Check all expected keys present
        required_keys = [
            'in_docker_group',
            'user_groups',
            'running_containers',
            'available_images',
            'docker_socket_accessible',
            'container_count',
            'image_count'
        ]

        for key in required_keys:
            assert key in result.findings, f"Missing finding key: {key}"
