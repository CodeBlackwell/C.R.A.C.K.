"""
Docker group and container parser.

Extracts Docker group membership, socket access, and container information.
"""

import re
from typing import Dict, Any, List
from .base import BaseOutputParser, ParsingResult
from .registry import ParserRegistry


@ParserRegistry.register
class DockerParser(BaseOutputParser):
    """
    Parse output from Docker-related enumeration commands.

    Handles commands like:
    - groups / id (group membership check)
    - docker ps (running containers)
    - docker images (available images)
    - ls -la /var/run/docker.sock (socket permissions)
    """

    @property
    def name(self) -> str:
        return "docker"

    def can_parse(self, step: Dict[str, Any], command: str) -> bool:
        """Detect Docker enumeration commands"""
        command_lower = command.lower()
        return (
            'groups' in command_lower or
            'docker ps' in command_lower or
            'docker images' in command_lower or
            'docker image' in command_lower or  # docker image ls
            'docker.sock' in command_lower or
            'id' in command_lower  # id command shows all groups
        )

    def parse(self, output: str, step: Dict[str, Any], command: str) -> ParsingResult:
        """
        Extract Docker group membership, containers, images, socket info.

        Returns ParsingResult with:
        - findings['in_docker_group']: Boolean
        - findings['user_groups']: List of all groups
        - findings['running_containers']: List of container info
        - findings['available_images']: List of Docker images
        - findings['docker_socket_accessible']: Boolean
        - variables['<DOCKER_SOCKET_PATH>']: Auto-set to /var/run/docker.sock
        - variables['<AVAILABLE_IMAGES>']: First available image (or 'alpine')
        """
        result = ParsingResult(parser_name=self.name)

        # Check for errors
        if self._is_error_output(output):
            result.success = False
            result.warnings.append("Command output contains errors")
            return result

        # Initialize findings
        in_docker_group = False
        user_groups = []
        running_containers = []
        available_images = []
        socket_accessible = False

        # Parse output based on command type
        command_lower = command.lower()

        # 1. Parse group membership (groups or id command)
        if 'groups' in command_lower or 'id' in command_lower:
            in_docker_group, user_groups = self._parse_group_output(output)

        # 2. Parse docker ps output (running containers)
        if 'docker ps' in command_lower:
            # Check for errors first
            if 'Cannot connect to' not in output and 'docker daemon' not in output.lower():
                running_containers = self._parse_docker_ps(output)
                socket_accessible = True  # Command succeeded
            else:
                running_containers = []
                socket_accessible = False

        # 3. Parse docker images output (available images)
        if 'docker images' in command_lower or 'docker image' in command_lower:
            available_images = self._parse_docker_images(output)

        # 4. Parse socket permissions (ls -la output)
        if 'docker.sock' in command_lower:
            socket_accessible = self._parse_socket_permissions(output)

        # Store findings
        result.findings = {
            'in_docker_group': in_docker_group,
            'user_groups': user_groups,
            'running_containers': running_containers if running_containers else [],
            'available_images': available_images,
            'docker_socket_accessible': socket_accessible,
            'container_count': len(running_containers) if running_containers else 0,
            'image_count': len(available_images),
        }

        # Set default socket path variable (always set for mount command)
        result.variables['<DOCKER_SOCKET_PATH>'] = '/var/run/docker.sock'

        # Determine image variable resolution
        if len(available_images) > 0:
            # Auto-select first available image
            result.variables['<IMAGE_NAME>'] = available_images[0]['name']
        else:
            # Fallback to alpine (most common, smallest image)
            result.variables['<IMAGE_NAME>'] = 'alpine'
            result.warnings.append("No images detected, defaulting to 'alpine'")

        # Determine overall success
        # Success if EITHER docker group OR socket accessible OR images available
        if in_docker_group or socket_accessible or len(available_images) > 0:
            result.success = True
        else:
            result.success = False
            result.warnings.append("User not in docker group and socket not accessible")

        return result

    def _parse_group_output(self, output: str) -> tuple:
        """
        Parse groups or id command output.

        Examples:
        - groups: "kali docker sudo"
        - id: "uid=1000(kali) gid=1000(kali) groups=1000(kali),999(docker),27(sudo)"

        Returns:
            (in_docker_group: bool, all_groups: List[str])
        """
        in_docker_group = False
        all_groups = []

        for line in self._extract_lines(output):
            # Parse id output: uid=1000(kali) gid=1000(kali) groups=1000(kali),999(docker)
            if 'groups=' in line.lower():
                # Extract groups section
                groups_match = re.search(r'groups?=([^\s]+)', line)
                if groups_match:
                    groups_str = groups_match.group(1)
                    # Extract group names from "1000(kali),999(docker)" format
                    group_names = re.findall(r'\(([^)]+)\)', groups_str)
                    all_groups.extend(group_names)
                    if 'docker' in [g.lower() for g in group_names]:
                        in_docker_group = True
            # Parse groups output: "kali docker sudo"
            elif line and not line.startswith('/'):  # Avoid parsing paths
                groups = line.split()
                all_groups.extend(groups)
                if 'docker' in [g.lower() for g in groups]:
                    in_docker_group = True

        return in_docker_group, list(set(all_groups))  # Deduplicate

    def _parse_docker_ps(self, output: str) -> List[Dict[str, str]]:
        """
        Parse docker ps output.

        Example:
        CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
        abc123def456   alpine    "sh"      2 hours   Up 2 hrs            test

        Returns:
            List of container info dicts
        """
        # Check for error output first
        if 'Cannot connect to' in output or 'docker daemon' in output.lower():
            return []  # Return empty list on error

        containers = []
        lines = self._extract_lines(output)

        # Skip header line (CONTAINER ID ...)
        data_lines = [l for l in lines if not l.startswith('CONTAINER ID')]

        for line in data_lines:
            # Parse container info (flexible whitespace)
            parts = line.split()
            if len(parts) >= 7:
                container = {
                    'id': parts[0],
                    'image': parts[1],
                    'name': parts[-1],  # NAMES is last column
                }
                containers.append(container)

        return containers

    def _parse_docker_images(self, output: str) -> List[Dict[str, str]]:
        """
        Parse docker images output.

        Example:
        REPOSITORY   TAG       IMAGE ID       CREATED       SIZE
        alpine       latest    abc123def456   2 weeks ago   5.6MB
        ubuntu       20.04     def456abc123   3 weeks ago   72.8MB

        Returns:
            List of image info dicts with 'name' field (REPOSITORY:TAG or REPOSITORY)
        """
        images = []
        lines = self._extract_lines(output)

        # Skip header line (REPOSITORY ...)
        data_lines = [l for l in lines if not l.startswith('REPOSITORY')]

        for line in data_lines:
            parts = line.split()
            if len(parts) >= 5:
                repo = parts[0]
                tag = parts[1]

                # Build image name
                if tag == 'latest':
                    image_name = repo  # Use short name for latest
                elif tag == '<none>':
                    continue  # Skip untagged images
                else:
                    image_name = f"{repo}:{tag}"

                image = {
                    'name': image_name,
                    'repository': repo,
                    'tag': tag,
                    'id': parts[2],
                }
                images.append(image)

        return images

    def _parse_socket_permissions(self, output: str) -> bool:
        """
        Parse ls -la /var/run/docker.sock output.

        Example:
        srw-rw---- 1 root docker 0 Jan  1 00:00 /var/run/docker.sock

        Returns:
            True if socket is accessible (readable/writable)
        """
        for line in self._extract_lines(output):
            if 'docker.sock' in line:
                # Check permissions (first 10 chars: srw-rw----)
                if line.startswith('srw-rw'):
                    return True  # Readable and writable by group
                elif line.startswith('srwxrw'):
                    return True  # Even more permissive
        return False
