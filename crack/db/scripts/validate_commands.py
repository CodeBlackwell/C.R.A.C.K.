#!/usr/bin/env python3
"""
Validate Generated Command Definitions

Checks:
1. All JSON files are valid
2. All commands have required fields
3. Variables match placeholders in commands
4. Tags contain 'oscp'
5. No duplicate command IDs
"""

import json
from pathlib import Path
from typing import Dict, List, Set
import re

def validate_command(cmd: Dict, filename: str) -> List[str]:
    """Validate single command definition."""
    errors = []
    cmd_id = cmd.get('id', 'UNKNOWN')
    
    # Required fields
    required_fields = ['id', 'name', 'description', 'command', 'category', 'tags']
    for field in required_fields:
        if field not in cmd or not cmd[field]:
            errors.append(f"{filename}:{cmd_id} - Missing required field: {field}")
    
    # OSCP tag requirement
    if 'tags' in cmd and 'oscp' not in cmd.get('tags', []):
        errors.append(f"{filename}:{cmd_id} - Missing 'oscp' tag")
    
    # Variables match placeholders
    command_text = cmd.get('command', '')
    placeholders = set(re.findall(r'<([A-Z_]+)>', command_text))
    
    if 'variables' in cmd:
        defined_vars = set(cmd['variables'].keys())
        
        # Check for missing variable definitions
        missing_vars = placeholders - defined_vars
        if missing_vars:
            errors.append(f"{filename}:{cmd_id} - Placeholders without definitions: {missing_vars}")
        
        # Check for unused variable definitions
        unused_vars = defined_vars - placeholders
        if unused_vars:
            errors.append(f"{filename}:{cmd_id} - Defined but unused variables: {unused_vars}")
        
        # Validate variable structure
        for var_name, var_def in cmd['variables'].items():
            if not isinstance(var_def, dict):
                errors.append(f"{filename}:{cmd_id} - Variable {var_name} not a dict")
                continue
            
            if 'description' not in var_def:
                errors.append(f"{filename}:{cmd_id} - Variable {var_name} missing description")
            
            if 'default' not in var_def:
                errors.append(f"{filename}:{cmd_id} - Variable {var_name} missing default")
    elif placeholders:
        errors.append(f"{filename}:{cmd_id} - Command has placeholders but no variables defined")
    
    return errors

def main():
    """Validate all generated commands."""
    base_dir = Path(__file__).parent.parent.parent / "reference" / "data" / "commands" / "generated"
    
    if not base_dir.exists():
        print(f"Error: Directory not found: {base_dir}")
        return 1
    
    all_errors = []
    all_ids: Set[str] = set()
    duplicate_ids: List[str] = []
    total_commands = 0
    
    # Process all JSON files
    for json_file in sorted(base_dir.glob("*.json")):
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            if 'commands' not in data:
                all_errors.append(f"{json_file.name} - Missing 'commands' array")
                continue
            
            for cmd in data['commands']:
                total_commands += 1
                
                # Check for duplicate IDs
                cmd_id = cmd.get('id', 'UNKNOWN')
                if cmd_id in all_ids:
                    duplicate_ids.append(cmd_id)
                all_ids.add(cmd_id)
                
                # Validate command
                errors = validate_command(cmd, json_file.name)
                all_errors.extend(errors)
        
        except json.JSONDecodeError as e:
            all_errors.append(f"{json_file.name} - Invalid JSON: {e}")
        except Exception as e:
            all_errors.append(f"{json_file.name} - Unexpected error: {e}")
    
    # Print results
    print("="*60)
    print("OSCP Command Validation Report")
    print("="*60)
    print(f"\nTotal commands validated: {total_commands}")
    print(f"Unique command IDs: {len(all_ids)}")
    
    if duplicate_ids:
        print(f"\n❌ Duplicate command IDs found: {len(duplicate_ids)}")
        for dup in duplicate_ids:
            print(f"   - {dup}")
    
    if all_errors:
        print(f"\n❌ Validation errors found: {len(all_errors)}")
        for error in all_errors[:20]:  # Show first 20 errors
            print(f"   - {error}")
        if len(all_errors) > 20:
            print(f"   ... and {len(all_errors) - 20} more errors")
        return 1
    else:
        print("\n✓ All validations passed!")
        print("\nCommand breakdown:")
        for json_file in sorted(base_dir.glob("*.json")):
            with open(json_file, 'r') as f:
                data = json.load(f)
            count = len(data.get('commands', []))
            print(f"   {json_file.name:40s} {count:3d} commands")
        return 0

if __name__ == "__main__":
    exit(main())
