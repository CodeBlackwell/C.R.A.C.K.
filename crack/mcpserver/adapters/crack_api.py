"""Stable adapter for CRACK internals - isolates MCP from internal changes."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


class CrackAPI:
    """Single point of access to CRACK functionality for MCP tools."""

    def __init__(self):
        self._registry = None
        self._config = None
        self._cheatsheet_registry = None
        self._theme = None
        self._crack_root = Path(__file__).parent.parent.parent

    # --- Lazy-loaded components ---

    @property
    def config(self):
        """Lazy-load ConfigManager."""
        if self._config is None:
            from crack.core.config.manager import ConfigManager
            self._config = ConfigManager()
        return self._config

    @property
    def theme(self):
        """Lazy-load ReferenceTheme."""
        if self._theme is None:
            from crack.core.themes import ReferenceTheme
            self._theme = ReferenceTheme()
        return self._theme

    @property
    def registry(self):
        """Lazy-load HybridCommandRegistry."""
        if self._registry is None:
            from crack.reference.core.registry import HybridCommandRegistry
            self._registry = HybridCommandRegistry(
                base_path=self._crack_root,
                config_manager=self.config,
                theme=self.theme
            )
        return self._registry

    @property
    def cheatsheet_registry(self):
        """Lazy-load CheatsheetRegistry."""
        if self._cheatsheet_registry is None:
            from crack.reference.core.cheatsheet_registry import CheatsheetRegistry
            self._cheatsheet_registry = CheatsheetRegistry(
                base_path=self._crack_root,
                command_registry=self.registry,
                theme=self.theme
            )
        return self._cheatsheet_registry

    # --- Knowledge methods ---

    def search_commands(
        self,
        query: str,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        oscp_only: bool = False
    ) -> List[Dict[str, Any]]:
        """Search commands, return list of dicts."""
        results = self.registry.search(query)

        # Apply filters
        if category:
            results = [c for c in results if c.category == category]
        if tags:
            results = [c for c in results if all(t in c.tags for t in tags)]
        if oscp_only:
            results = [c for c in results if c.oscp_relevance == "high"]

        # Convert to serializable dicts (summary only)
        return [
            {
                "id": c.id,
                "name": c.name,
                "description": c.description[:100] + "..." if len(c.description) > 100 else c.description,
                "category": c.category,
                "tags": c.tags[:5],
                "oscp_relevance": c.oscp_relevance
            }
            for c in results[:20]  # Limit results
        ]

    def get_command(self, command_id: str) -> Optional[Dict[str, Any]]:
        """Get full command details by ID."""
        cmd = self.registry.get_command(command_id)
        if not cmd:
            return None

        return {
            "id": cmd.id,
            "name": cmd.name,
            "command": cmd.command,
            "description": cmd.description,
            "category": cmd.category,
            "subcategory": cmd.subcategory,
            "tags": cmd.tags,
            "variables": [
                {"name": v.name, "description": v.description, "example": v.example, "required": v.required}
                for v in cmd.variables
            ],
            "flag_explanations": cmd.flag_explanations,
            "success_indicators": cmd.success_indicators,
            "failure_indicators": cmd.failure_indicators,
            "prerequisites": cmd.prerequisites,
            "alternatives": cmd.alternatives,
            "next_steps": cmd.next_steps,
            "troubleshooting": cmd.troubleshooting,
            "oscp_relevance": cmd.oscp_relevance,
            "notes": cmd.notes
        }

    def fill_command(self, command_id: str, variables: Optional[Dict[str, str]] = None) -> Optional[str]:
        """Fill command placeholders with values."""
        cmd = self.registry.get_command(command_id)
        if not cmd:
            return None

        # Build values dict: start with config, override with provided
        values = {}
        config_values = self.config.get_placeholder_values() if self.config else {}

        for var in cmd.variables:
            var_name = var.name.strip("<>")
            # Check provided variables (try with and without brackets)
            if variables:
                if var.name in variables:
                    values[var.name] = variables[var.name]
                elif var_name in variables:
                    values[var.name] = variables[var_name]
                    continue
            # Fall back to config
            if var.name in config_values:
                values[var.name] = config_values[var.name]
            elif f"<{var_name}>" in config_values:
                values[var.name] = config_values[f"<{var_name}>"]

        return cmd.fill_placeholders(values)

    def get_cheatsheet(self, topic: str) -> Optional[Dict[str, Any]]:
        """Get cheatsheet by topic (searches by ID or name)."""
        # Try exact ID match first
        sheet = self.cheatsheet_registry.get_cheatsheet(topic)
        if not sheet:
            # Search by name/description
            results = self.cheatsheet_registry.search(topic)
            if results:
                sheet = results[0]

        if not sheet:
            return None

        return {
            "id": sheet.id,
            "name": sheet.name,
            "description": sheet.description,
            "scenarios": [
                {"title": s.get("title", ""), "context": s.get("context", ""), "approach": s.get("approach", "")}
                for s in (sheet.scenarios or [])[:3]
            ],
            "sections": [
                {"title": sec.title, "commands": [c.id for c in sec.commands[:5]]}
                for sec in (sheet.sections or [])[:5]
            ],
            "tags": sheet.tags
        }

    def get_attack_chain(self, chain_id: str) -> Optional[Dict[str, Any]]:
        """Get attack chain by ID."""
        chain_path = self._crack_root / "db" / "data" / "chains"

        # Search all chain directories
        for json_file in chain_path.glob("**/*.json"):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    if data.get("id") == chain_id:
                        return {
                            "id": data.get("id"),
                            "name": data.get("name"),
                            "description": data.get("description"),
                            "difficulty": data.get("difficulty"),
                            "time_estimate": data.get("time_estimate"),
                            "prerequisites": data.get("prerequisites", []),
                            "steps": [
                                {
                                    "id": s.get("id"),
                                    "name": s.get("name"),
                                    "objective": s.get("objective"),
                                    "command_ref": s.get("command_ref"),
                                    "dependencies": s.get("dependencies", []),
                                    "next_steps": s.get("next_steps", [])
                                }
                                for s in data.get("steps", [])
                            ]
                        }
            except (json.JSONDecodeError, KeyError):
                continue
        return None

    def suggest_next_steps(self, command_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Suggest next commands based on current command."""
        suggestions = []

        if command_id:
            cmd = self.registry.get_command(command_id)
            if cmd and cmd.next_steps:
                for next_id in cmd.next_steps[:5]:
                    next_cmd = self.registry.get_command(next_id)
                    if next_cmd:
                        suggestions.append({
                            "id": next_cmd.id,
                            "name": next_cmd.name,
                            "description": next_cmd.description[:80],
                            "rationale": f"Follows from {command_id}"
                        })

        return suggestions

    # --- State methods ---

    def get_engagement_context(self) -> Dict[str, Any]:
        """Get current engagement state."""
        context = {
            "active": False,
            "engagement": None,
            "targets": [],
            "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "variables": {}
        }

        try:
            from crack.tools.engagement.integration import EngagementIntegration

            if EngagementIntegration.is_active():
                context["active"] = True
                eng = EngagementIntegration.get_active_engagement()
                if eng:
                    context["engagement"] = {"id": eng.get("id"), "name": eng.get("name")}

                # Get targets and findings via adapter if available
                try:
                    from crack.tools.engagement.adapter import EngagementAdapter
                    adapter = EngagementAdapter()
                    eng_id = EngagementIntegration.get_active_engagement_id()

                    if eng_id:
                        targets = adapter.get_targets(eng_id)
                        context["targets"] = [
                            {"id": t.id, "ip": t.ip_address, "hostname": t.hostname, "status": t.status.value}
                            for t in targets[:10]
                        ]

                        summary = adapter.get_finding_summary(eng_id)
                        context["findings"] = summary
                except Exception:
                    pass  # Neo4j may not be available

        except ImportError:
            pass

        # Add configured variables
        try:
            context["variables"] = {
                k.strip("<>"): v for k, v in self.config.get_placeholder_values().items()
            }
        except Exception:
            pass

        return context

    def add_target(self, ip_address: str, hostname: str = "", os_guess: str = "") -> Optional[str]:
        """Add target to active engagement. Returns target_id or None."""
        try:
            from crack.tools.engagement.integration import EngagementIntegration

            if not EngagementIntegration.is_active():
                return None

            return EngagementIntegration.ensure_target(ip_address, hostname, os_guess)
        except Exception:
            return None

    def add_finding(
        self,
        title: str,
        severity: str = "medium",
        description: str = "",
        cve_id: str = "",
        target_id: Optional[str] = None
    ) -> Optional[str]:
        """Add finding to active engagement. Returns finding_id or None."""
        try:
            from crack.tools.engagement.integration import EngagementIntegration

            if not EngagementIntegration.is_active():
                return None

            return EngagementIntegration.add_finding(
                title=title,
                severity=severity,
                description=description,
                cve_id=cve_id,
                target_id=target_id
            )
        except Exception:
            return None

    def add_credential(
        self,
        username: str,
        credential_type: str,
        value: str,
        target_id: Optional[str] = None,
        notes: str = ""
    ) -> Optional[str]:
        """Add credential to active engagement. Returns credential_id or None."""
        try:
            from crack.tools.engagement.adapter import EngagementAdapter
            from crack.tools.engagement.integration import EngagementIntegration

            if not EngagementIntegration.is_active():
                return None

            eng_id = EngagementIntegration.get_active_engagement_id()
            if not eng_id:
                return None

            adapter = EngagementAdapter()
            return adapter.add_credential(
                engagement_id=eng_id,
                username=username,
                credential_type=credential_type,
                value=value,
                target_id=target_id,
                notes=notes
            )
        except Exception:
            return None


    # --- Server info methods ---

    def get_server_info(self) -> Dict[str, Any]:
        """Get MCP server status and configuration."""
        info = {
            "version": "1.0.0",
            "tools_registered": 15,
            "backends": {"neo4j": False, "config": False},
            "engagement_active": False
        }

        # Check Neo4j availability
        try:
            from crack.tools.engagement.adapter import EngagementAdapter
            adapter = EngagementAdapter()
            info["backends"]["neo4j"] = adapter.driver is not None
        except Exception:
            pass

        # Check config availability
        try:
            info["backends"]["config"] = self.config is not None
        except Exception:
            pass

        # Check engagement status
        try:
            from crack.tools.engagement.integration import EngagementIntegration
            info["engagement_active"] = EngagementIntegration.is_active()
        except Exception:
            pass

        return info

    # --- Config methods ---

    def list_variables(self, category: str = None) -> List[Dict[str, Any]]:
        """List configured variables with their values."""
        variables = []
        try:
            from crack.core.config.variables import VARIABLE_REGISTRY

            config_values = self.config.get_placeholder_values() if self.config else {}

            for name, var in VARIABLE_REGISTRY.items():
                if category and var.category != category:
                    continue

                # Get current value
                value = config_values.get(f"<{name}>", "")

                variables.append({
                    "name": name,
                    "value": value,
                    "category": var.category,
                    "required": var.required
                })

            # Sort by category, then name
            variables.sort(key=lambda x: (x["category"], x["name"]))
        except Exception:
            pass

        return variables

    def describe_variable(self, name: str) -> Optional[Dict[str, Any]]:
        """Get full metadata for a variable."""
        try:
            from crack.core.config.variables import VARIABLE_REGISTRY, resolve_alias

            # Resolve alias and normalize
            canonical = resolve_alias(name.strip("<>").upper())

            if canonical not in VARIABLE_REGISTRY:
                return None

            var = VARIABLE_REGISTRY[canonical]
            config_values = self.config.get_placeholder_values() if self.config else {}

            return {
                "name": canonical,
                "category": var.category,
                "description": var.description,
                "example": var.example,
                "required": var.required,
                "validation": var.validation.pattern if var.validation else None,
                "aliases": list(var.aliases) if var.aliases else [],
                "current_value": config_values.get(f"<{canonical}>", "")
            }
        except Exception:
            return None

    # --- Graph query methods ---

    def get_target_graph(self, target_id: str, depth: int = 1) -> Dict[str, Any]:
        """Get all relationships for a target."""
        result = {
            "target": None,
            "services": [],
            "findings": [],
            "credentials": [],
            "sessions": [],
            "relationships": []
        }

        # Cap depth at 3
        depth = min(max(depth, 1), 3)

        try:
            from crack.tools.engagement.adapter import EngagementAdapter
            from crack.tools.engagement.integration import EngagementIntegration

            if not EngagementIntegration.is_active():
                return result

            adapter = EngagementAdapter()
            eng_id = EngagementIntegration.get_active_engagement_id()

            # Try to find target by ID or IP
            target = adapter.get_target(target_id)
            if not target:
                # Search by IP
                targets = adapter.get_targets(eng_id)
                for t in targets:
                    if t.ip_address == target_id or t.id == target_id:
                        target = t
                        break

            if not target:
                return result

            result["target"] = {
                "id": target.id,
                "ip": target.ip_address,
                "hostname": target.hostname,
                "os": target.os_guess,
                "status": target.status.value
            }

            # Get services
            services = adapter.get_services(target.id)
            result["services"] = [
                {"port": s.port, "protocol": s.protocol, "name": s.service_name, "version": s.version}
                for s in services[:20]
            ]

            # Get sessions for this target
            sessions = adapter.get_terminal_sessions(eng_id, target_id=target.id)
            result["sessions"] = [
                {"id": s.get("id"), "type": s.get("type"), "status": s.get("status")}
                for s in sessions[:10]
            ]

            # Build relationship summary
            result["relationships"] = [
                {"type": "HAS_SERVICE", "count": len(services)},
                {"type": "HAS_SESSION", "count": len(sessions)}
            ]

        except Exception:
            pass

        return result

    def get_engagement_relationships(self, summary: bool = True) -> Dict[str, Any]:
        """Get cross-node relationship summary for engagement."""
        result = {
            "credential_access": [],
            "session_targets": [],
            "finding_targets": [],
            "counts": {
                "targets": 0,
                "services": 0,
                "findings": 0,
                "credentials": 0,
                "sessions": 0
            }
        }

        try:
            from crack.tools.engagement.adapter import EngagementAdapter
            from crack.tools.engagement.integration import EngagementIntegration

            if not EngagementIntegration.is_active():
                return result

            adapter = EngagementAdapter()
            eng_id = EngagementIntegration.get_active_engagement_id()

            # Get counts
            targets = adapter.get_targets(eng_id)
            result["counts"]["targets"] = len(targets)

            findings = adapter.get_findings(eng_id)
            result["counts"]["findings"] = len(findings)

            # Aggregate services and sessions
            total_services = 0
            for t in targets[:50]:  # Limit to prevent explosion
                services = adapter.get_services(t.id)
                total_services += len(services)

            result["counts"]["services"] = total_services

            sessions = adapter.get_terminal_sessions(eng_id)
            result["counts"]["sessions"] = len(sessions)

            # Build session→target mappings (limited)
            if not summary:
                for s in sessions[:20]:
                    if s.get("target_id"):
                        result["session_targets"].append({
                            "session_id": s.get("id"),
                            "target_id": s.get("target_id"),
                            "type": s.get("type")
                        })

                # Build finding→target mappings
                for f in findings[:20]:
                    for t_id in (f.affected_targets or []):
                        result["finding_targets"].append({
                            "finding_id": f.id,
                            "target_id": t_id,
                            "severity": f.severity.value
                        })

        except Exception:
            pass

        return result


# Singleton instance for tools to use
api = CrackAPI()
