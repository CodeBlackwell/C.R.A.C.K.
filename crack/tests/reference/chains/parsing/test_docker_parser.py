"""
Tests for Docker Parser

Business Value Focus:
- Parse Docker group membership for privilege escalation opportunities
- Identify running containers and available images
- Detect Docker socket accessibility for exploitation

Test Priority: TIER 1 - CRITICAL (Core PrivEsc Detection)
"""

import pytest


# =============================================================================
# Sample Output Data
# =============================================================================

# Groups command showing docker group membership
GROUPS_WITH_DOCKER = """kali adm sudo docker"""

# Groups command without docker
GROUPS_WITHOUT_DOCKER = """kali adm sudo cdrom"""

# Id command with docker group
ID_WITH_DOCKER = """uid=1000(kali) gid=1000(kali) groups=1000(kali),999(docker),27(sudo)"""

# Id command without docker
ID_WITHOUT_DOCKER = """uid=1000(kali) gid=1000(kali) groups=1000(kali),27(sudo)"""

# Docker ps output with running containers
DOCKER_PS_OUTPUT = """CONTAINER ID   IMAGE     COMMAND   CREATED      STATUS       PORTS     NAMES
abc123def456   alpine    "/bin/sh"   2 hours ago   Up 2 hours             test_container
def789ghi012   ubuntu    "bash"      3 days ago    Up 3 days              web_server
"""

# Docker ps with no containers
DOCKER_PS_EMPTY = """CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
"""

# Docker ps error (daemon not running)
DOCKER_PS_ERROR = """Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?"""

# Docker images output
DOCKER_IMAGES_OUTPUT = """REPOSITORY   TAG       IMAGE ID       CREATED       SIZE
alpine       latest    abc123def456   2 weeks ago   5.6MB
ubuntu       20.04     def456abc123   3 weeks ago   72.8MB
debian       bullseye  ghi789jkl012   1 month ago   124MB
"""

# Docker images with untagged
DOCKER_IMAGES_WITH_NONE = """REPOSITORY   TAG       IMAGE ID       CREATED       SIZE
alpine       latest    abc123def456   2 weeks ago   5.6MB
<none>       <none>    def456abc123   3 weeks ago   72.8MB
"""

# Docker socket permissions (accessible)
DOCKER_SOCKET_ACCESSIBLE = """srw-rw---- 1 root docker 0 Jan  1 00:00 /var/run/docker.sock"""

# Docker socket permissions (not accessible)
DOCKER_SOCKET_NOT_ACCESSIBLE = """srw------- 1 root root 0 Jan  1 00:00 /var/run/docker.sock"""


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def docker_parser():
    """
    DockerParser instance.

    BV: Consistent parser for Docker enumeration tests.
    """
    from reference.chains.parsing.docker_parser import DockerParser
    return DockerParser()


@pytest.fixture
def step():
    """Default step dictionary."""
    return {'command': 'groups'}


# =============================================================================
# Parser Detection Tests
# =============================================================================

class TestDockerParserDetection:
    """Tests for Docker command detection"""

    def test_can_parse_groups_command(self, docker_parser, step):
        """
        BV: Detect 'groups' command

        Scenario:
          Given: Command is 'groups'
          When: can_parse() is called
          Then: Returns True
        """
        assert docker_parser.can_parse(step, 'groups') is True

    def test_can_parse_id_command(self, docker_parser, step):
        """
        BV: Detect 'id' command

        Scenario:
          Given: Command is 'id'
          When: can_parse() is called
          Then: Returns True
        """
        assert docker_parser.can_parse(step, 'id') is True

    def test_can_parse_docker_ps(self, docker_parser, step):
        """
        BV: Detect 'docker ps' command

        Scenario:
          Given: Command is 'docker ps'
          When: can_parse() is called
          Then: Returns True
        """
        assert docker_parser.can_parse(step, 'docker ps') is True

    def test_can_parse_docker_ps_with_flags(self, docker_parser, step):
        """
        BV: Detect 'docker ps -a' command

        Scenario:
          Given: Command is 'docker ps -a'
          When: can_parse() is called
          Then: Returns True
        """
        assert docker_parser.can_parse(step, 'docker ps -a') is True

    def test_can_parse_docker_images(self, docker_parser, step):
        """
        BV: Detect 'docker images' command

        Scenario:
          Given: Command is 'docker images'
          When: can_parse() is called
          Then: Returns True
        """
        assert docker_parser.can_parse(step, 'docker images') is True

    def test_can_parse_docker_image_ls(self, docker_parser, step):
        """
        BV: Detect 'docker image ls' command

        Scenario:
          Given: Command is 'docker image ls'
          When: can_parse() is called
          Then: Returns True
        """
        assert docker_parser.can_parse(step, 'docker image ls') is True

    def test_can_parse_docker_socket_ls(self, docker_parser, step):
        """
        BV: Detect socket permission check

        Scenario:
          Given: Command checks docker.sock
          When: can_parse() is called
          Then: Returns True
        """
        assert docker_parser.can_parse(step, 'ls -la /var/run/docker.sock') is True

    def test_cannot_parse_unrelated_command(self, docker_parser, step):
        """
        BV: Reject unrelated commands

        Scenario:
          Given: Unrelated command
          When: can_parse() is called
          Then: Returns False
        """
        assert docker_parser.can_parse(step, 'cat /etc/passwd') is False


# =============================================================================
# Group Membership Tests
# =============================================================================

class TestGroupMembershipParsing:
    """Tests for Docker group detection"""

    def test_parse_groups_with_docker(self, docker_parser, step):
        """
        BV: Detect docker group from 'groups' command

        Scenario:
          Given: groups output with docker
          When: parse() is called
          Then: in_docker_group is True
        """
        result = docker_parser.parse(GROUPS_WITH_DOCKER, step, 'groups')

        assert result.findings['in_docker_group'] is True

    def test_parse_groups_without_docker(self, docker_parser, step):
        """
        BV: Handle groups output without docker

        Scenario:
          Given: groups output without docker
          When: parse() is called
          Then: in_docker_group is False
        """
        result = docker_parser.parse(GROUPS_WITHOUT_DOCKER, step, 'groups')

        assert result.findings['in_docker_group'] is False

    def test_parse_id_with_docker(self, docker_parser, step):
        """
        BV: Detect docker group from 'id' command

        Scenario:
          Given: id output with docker group
          When: parse() is called
          Then: in_docker_group is True
        """
        result = docker_parser.parse(ID_WITH_DOCKER, step, 'id')

        assert result.findings['in_docker_group'] is True

    def test_parse_id_extracts_all_groups(self, docker_parser, step):
        """
        BV: Extract all groups from id output

        Scenario:
          Given: id output with multiple groups
          When: parse() is called
          Then: All groups extracted
        """
        result = docker_parser.parse(ID_WITH_DOCKER, step, 'id')

        assert 'kali' in result.findings['user_groups']
        assert 'docker' in result.findings['user_groups']
        assert 'sudo' in result.findings['user_groups']


# =============================================================================
# Docker PS Tests
# =============================================================================

class TestDockerPsParsing:
    """Tests for docker ps output parsing"""

    def test_parse_docker_ps_extracts_containers(self, docker_parser, step):
        """
        BV: Extract running container info

        Scenario:
          Given: docker ps output with containers
          When: parse() is called
          Then: Containers extracted
        """
        result = docker_parser.parse(DOCKER_PS_OUTPUT, step, 'docker ps')

        assert result.findings['container_count'] == 2

    def test_parse_docker_ps_extracts_container_names(self, docker_parser, step):
        """
        BV: Extract container names

        Scenario:
          Given: docker ps output with named containers
          When: parse() is called
          Then: Container names extracted
        """
        result = docker_parser.parse(DOCKER_PS_OUTPUT, step, 'docker ps')

        names = [c['name'] for c in result.findings['running_containers']]
        assert 'test_container' in names
        assert 'web_server' in names

    def test_parse_docker_ps_extracts_images(self, docker_parser, step):
        """
        BV: Extract container images

        Scenario:
          Given: docker ps output
          When: parse() is called
          Then: Container images extracted
        """
        result = docker_parser.parse(DOCKER_PS_OUTPUT, step, 'docker ps')

        images = [c['image'] for c in result.findings['running_containers']]
        assert 'alpine' in images
        assert 'ubuntu' in images

    def test_parse_docker_ps_empty(self, docker_parser, step):
        """
        BV: Handle empty docker ps

        Scenario:
          Given: docker ps with no containers
          When: parse() is called
          Then: container_count is 0
        """
        result = docker_parser.parse(DOCKER_PS_EMPTY, step, 'docker ps')

        assert result.findings['container_count'] == 0

    def test_parse_docker_ps_error(self, docker_parser, step):
        """
        BV: Handle docker daemon error

        Scenario:
          Given: docker ps with daemon error
          When: parse() is called
          Then: socket_accessible is False
        """
        result = docker_parser.parse(DOCKER_PS_ERROR, step, 'docker ps')

        assert result.findings['docker_socket_accessible'] is False


# =============================================================================
# Docker Images Tests
# =============================================================================

class TestDockerImagesParsing:
    """Tests for docker images output parsing"""

    def test_parse_docker_images_extracts_images(self, docker_parser, step):
        """
        BV: Extract available images

        Scenario:
          Given: docker images output
          When: parse() is called
          Then: Images extracted
        """
        result = docker_parser.parse(DOCKER_IMAGES_OUTPUT, step, 'docker images')

        assert result.findings['image_count'] == 3

    def test_parse_docker_images_extracts_names(self, docker_parser, step):
        """
        BV: Extract image names

        Scenario:
          Given: docker images output
          When: parse() is called
          Then: Image names extracted correctly
        """
        result = docker_parser.parse(DOCKER_IMAGES_OUTPUT, step, 'docker images')

        names = [i['name'] for i in result.findings['available_images']]
        assert 'alpine' in names  # latest tag uses short name
        assert 'ubuntu:20.04' in names
        assert 'debian:bullseye' in names

    def test_parse_docker_images_skips_none_tag(self, docker_parser, step):
        """
        BV: Skip untagged images

        Scenario:
          Given: docker images with <none> tags
          When: parse() is called
          Then: Untagged images skipped
        """
        result = docker_parser.parse(DOCKER_IMAGES_WITH_NONE, step, 'docker images')

        # Only alpine should be included (not the <none> image)
        assert result.findings['image_count'] == 1


# =============================================================================
# Socket Permission Tests
# =============================================================================

class TestSocketPermissionParsing:
    """Tests for docker socket permission parsing"""

    def test_parse_socket_accessible(self, docker_parser, step):
        """
        BV: Detect accessible docker socket

        Scenario:
          Given: ls -la showing rw group permissions
          When: parse() is called
          Then: socket_accessible is True
        """
        result = docker_parser.parse(
            DOCKER_SOCKET_ACCESSIBLE, step, 'ls -la /var/run/docker.sock'
        )

        assert result.findings['docker_socket_accessible'] is True

    def test_parse_socket_not_accessible(self, docker_parser, step):
        """
        BV: Detect inaccessible docker socket

        Scenario:
          Given: ls -la showing no group permissions
          When: parse() is called
          Then: socket_accessible is False
        """
        result = docker_parser.parse(
            DOCKER_SOCKET_NOT_ACCESSIBLE, step, 'ls -la /var/run/docker.sock'
        )

        assert result.findings['docker_socket_accessible'] is False


# =============================================================================
# Variable Resolution Tests
# =============================================================================

class TestVariableResolution:
    """Tests for automatic variable resolution"""

    def test_sets_docker_socket_path(self, docker_parser, step):
        """
        BV: Auto-set docker socket path variable

        Scenario:
          Given: Any docker-related output
          When: parse() is called
          Then: <DOCKER_SOCKET_PATH> set
        """
        result = docker_parser.parse(GROUPS_WITH_DOCKER, step, 'groups')

        assert result.variables['<DOCKER_SOCKET_PATH>'] == '/var/run/docker.sock'

    def test_sets_image_name_from_available(self, docker_parser, step):
        """
        BV: Auto-set image name from first available

        Scenario:
          Given: docker images output
          When: parse() is called
          Then: <IMAGE_NAME> set to first image
        """
        result = docker_parser.parse(DOCKER_IMAGES_OUTPUT, step, 'docker images')

        assert result.variables['<IMAGE_NAME>'] == 'alpine'

    def test_sets_image_name_fallback(self, docker_parser, step):
        """
        BV: Fallback to alpine when no images

        Scenario:
          Given: No images available
          When: parse() is called
          Then: <IMAGE_NAME> defaults to alpine
        """
        result = docker_parser.parse(GROUPS_WITH_DOCKER, step, 'groups')

        assert result.variables['<IMAGE_NAME>'] == 'alpine'


# =============================================================================
# Success/Failure Tests
# =============================================================================

class TestSuccessDetection:
    """Tests for success/failure detection"""

    def test_success_when_in_docker_group(self, docker_parser, step):
        """
        BV: Success when user in docker group

        Scenario:
          Given: User in docker group
          When: parse() is called
          Then: success is True
        """
        result = docker_parser.parse(GROUPS_WITH_DOCKER, step, 'groups')

        assert result.success is True

    def test_success_when_socket_accessible(self, docker_parser, step):
        """
        BV: Success when socket accessible

        Scenario:
          Given: Docker socket is accessible
          When: parse() is called
          Then: success is True
        """
        result = docker_parser.parse(
            DOCKER_SOCKET_ACCESSIBLE, step, 'ls -la /var/run/docker.sock'
        )

        assert result.success is True

    def test_failure_when_not_in_group(self, docker_parser, step):
        """
        BV: Failure when not in docker group

        Scenario:
          Given: User not in docker group
          When: parse() is called
          Then: success is False with warning
        """
        result = docker_parser.parse(GROUPS_WITHOUT_DOCKER, step, 'groups')

        assert result.success is False
        assert any('not in docker group' in w.lower() for w in result.warnings)


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_parser_name(self, docker_parser):
        """
        BV: Parser has correct name

        Scenario:
          Given: DockerParser instance
          When: Accessing name property
          Then: Returns 'docker'
        """
        assert docker_parser.name == "docker"

    def test_empty_output(self, docker_parser, step):
        """
        BV: Handle empty output gracefully

        Scenario:
          Given: Empty output
          When: parse() is called
          Then: Returns result with defaults
        """
        result = docker_parser.parse("", step, 'groups')

        assert result.findings['in_docker_group'] is False
        assert result.findings['container_count'] == 0

    def test_error_output(self, docker_parser, step):
        """
        BV: Handle error output

        Scenario:
          Given: Error message in output
          When: parse() is called
          Then: success is False
        """
        error_output = "bash: groups: command not found"
        result = docker_parser.parse(error_output, step, 'groups')

        assert result.success is False
