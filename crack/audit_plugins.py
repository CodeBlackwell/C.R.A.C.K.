#!/usr/bin/env python3
"""
Plugin System Audit Script
Analyzes all ServicePlugin implementations for completeness
"""

import ast
import os
from pathlib import Path
from typing import Dict, List, Any
import json

class PluginAuditor:
    def __init__(self):
        self.plugins_dir = Path("/home/kali/OSCP/crack/track/services")
        self.results = []

    def audit_file(self, filepath: Path) -> Dict[str, Any]:
        """Audit a single plugin file"""
        result = {
            "file": filepath.name,
            "plugin_name": None,
            "has_name": False,
            "has_detect": False,
            "has_get_task_tree": False,
            "has_on_task_complete": False,
            "has_default_ports": False,
            "has_service_names": False,
            "is_registered": False,
            "inherits_serviceplugin": False,
            "activation_method": "unclear",
            "status": "Unknown",
            "notes": []
        }

        try:
            with open(filepath, 'r') as f:
                content = f.read()

            # Parse AST
            tree = ast.parse(content)

            # Find classes that inherit from ServicePlugin
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    # Check if inherits from ServicePlugin
                    for base in node.bases:
                        if isinstance(base, ast.Name) and base.id == 'ServicePlugin':
                            result["inherits_serviceplugin"] = True

                            # Check for @ServiceRegistry.register decorator
                            for decorator in node.decorator_list:
                                if isinstance(decorator, ast.Attribute):
                                    if (isinstance(decorator.value, ast.Name) and
                                        decorator.value.id == 'ServiceRegistry' and
                                        decorator.attr == 'register'):
                                        result["is_registered"] = True

                            # Check for required methods and properties
                            for item in node.body:
                                if isinstance(item, ast.FunctionDef):
                                    if item.name == 'name' and any(d.id == 'property' for d in item.decorator_list if isinstance(d, ast.Name)):
                                        result["has_name"] = True
                                        # Try to extract the plugin name
                                        for stmt in item.body:
                                            if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant):
                                                result["plugin_name"] = stmt.value.value
                                    elif item.name == 'detect':
                                        result["has_detect"] = True
                                    elif item.name == 'get_task_tree':
                                        result["has_get_task_tree"] = True
                                    elif item.name == 'on_task_complete':
                                        result["has_on_task_complete"] = True
                                    elif item.name == 'default_ports' and any(d.id == 'property' for d in item.decorator_list if isinstance(d, ast.Name)):
                                        result["has_default_ports"] = True
                                    elif item.name == 'service_names' and any(d.id == 'property' for d in item.decorator_list if isinstance(d, ast.Name)):
                                        result["has_service_names"] = True

            # Determine activation method
            if result["has_default_ports"] or "port" in filepath.name.lower() or result["plugin_name"] and "port" in result["plugin_name"]:
                result["activation_method"] = "nmap-triggered"
            elif any(keyword in filepath.name.lower() for keyword in ['post_exploit', 'privesc', 'persistence', 'lateral', 'ad_']):
                result["activation_method"] = "manual/finding-triggered"
            elif any(keyword in filepath.name.lower() for keyword in ['attack', 'bypass', 'exploit']):
                result["activation_method"] = "finding-triggered"

            # Determine status
            if result["inherits_serviceplugin"] and result["is_registered"] and result["has_name"] and result["has_detect"] and result["has_get_task_tree"]:
                result["status"] = "Complete"
            elif result["inherits_serviceplugin"] and result["is_registered"]:
                missing = []
                if not result["has_name"]: missing.append("name")
                if not result["has_detect"]: missing.append("detect")
                if not result["has_get_task_tree"]: missing.append("get_task_tree")
                result["status"] = "Missing Logic"
                result["notes"].append(f"Missing: {', '.join(missing)}")
            elif result["inherits_serviceplugin"]:
                result["status"] = "Not Registered"
                result["notes"].append("Missing @ServiceRegistry.register decorator")
            else:
                # Check if it's a support file
                if filepath.name in ['__init__.py', 'base.py', 'registry.py', 'findings_processor.py']:
                    result["status"] = "Support File"
                else:
                    result["status"] = "Not a Plugin"

        except Exception as e:
            result["status"] = "Parse Error"
            result["notes"].append(str(e))

        return result

    def audit_all(self):
        """Audit all Python files in the services directory"""
        for filepath in sorted(self.plugins_dir.glob("*.py")):
            if filepath.name not in ['__pycache__']:
                result = self.audit_file(filepath)
                self.results.append(result)

    def generate_report(self):
        """Generate markdown report"""
        report = []
        report.append("# ServicePlugin System Audit Report\n")
        report.append(f"**Total Files Analyzed:** {len(self.results)}\n")

        # Statistics
        complete = sum(1 for r in self.results if r["status"] == "Complete")
        missing_logic = sum(1 for r in self.results if r["status"] == "Missing Logic")
        not_registered = sum(1 for r in self.results if r["status"] == "Not Registered")
        not_plugins = sum(1 for r in self.results if r["status"] == "Not a Plugin")
        support_files = sum(1 for r in self.results if r["status"] == "Support File")

        report.append("\n## Summary Statistics\n")
        report.append(f"- **Complete Plugins:** {complete}\n")
        report.append(f"- **Missing Logic:** {missing_logic}\n")
        report.append(f"- **Not Registered:** {not_registered}\n")
        report.append(f"- **Not Plugins:** {not_plugins}\n")
        report.append(f"- **Support Files:** {support_files}\n")

        # Detailed table
        report.append("\n## Detailed Plugin Audit\n")
        report.append("| File | Plugin Name | Has name()? | Has detect()? | Has get_task_tree()? | Has on_task_complete()? | Registered? | Activation | Status | Notes |\n")
        report.append("|------|-------------|-------------|---------------|----------------------|-------------------------|-------------|------------|--------|-------|\n")

        for r in sorted(self.results, key=lambda x: (x["status"], x["file"])):
            if r["status"] in ["Complete", "Missing Logic", "Not Registered"]:
                report.append(f"| {r['file']} | {r['plugin_name'] or 'N/A'} | {'✓' if r['has_name'] else '✗'} | {'✓' if r['has_detect'] else '✗'} | {'✓' if r['has_get_task_tree'] else '✗'} | {'✓' if r['has_on_task_complete'] else '✗'} | {'✓' if r['is_registered'] else '✗'} | {r['activation_method']} | **{r['status']}** | {'; '.join(r['notes'])} |\n")

        # Activation method analysis
        report.append("\n## Activation Method Analysis\n")
        nmap_triggered = [r for r in self.results if r["activation_method"] == "nmap-triggered" and r["status"] in ["Complete", "Missing Logic"]]
        manual_triggered = [r for r in self.results if "manual" in r["activation_method"] and r["status"] in ["Complete", "Missing Logic"]]
        finding_triggered = [r for r in self.results if r["activation_method"] == "finding-triggered" and r["status"] in ["Complete", "Missing Logic"]]

        report.append(f"- **Nmap-Triggered:** {len(nmap_triggered)} plugins\n")
        report.append(f"- **Manual/Finding-Triggered:** {len(manual_triggered)} plugins\n")
        report.append(f"- **Finding-Triggered:** {len(finding_triggered)} plugins\n")

        return "".join(report)

    def save_json(self, filepath="/home/kali/OSCP/crack/plugin_audit.json"):
        """Save results as JSON for further analysis"""
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)

if __name__ == "__main__":
    auditor = PluginAuditor()
    auditor.audit_all()

    # Save markdown report
    report = auditor.generate_report()
    with open("/home/kali/OSCP/crack/PLUGIN_AUDIT_REPORT.md", 'w') as f:
        f.write(report)

    # Save JSON for detailed analysis
    auditor.save_json()

    print("Audit complete! See PLUGIN_AUDIT_REPORT.md and plugin_audit.json")

    # Print quick summary
    complete = sum(1 for r in auditor.results if r["status"] == "Complete")
    missing = sum(1 for r in auditor.results if r["status"] == "Missing Logic")
    print(f"\nSummary: {complete} complete plugins, {missing} missing logic")