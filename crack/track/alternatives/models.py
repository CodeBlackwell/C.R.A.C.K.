"""
Data models for alternative commands system
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class Variable:
    """Variable placeholder definition"""

    name: str                        # Variable name (e.g., 'TARGET', 'PORT')
    description: str = ''            # Human-readable description
    example: str = ''                # Example value
    auto_resolve: bool = True        # Try to auto-fill from context
    required: bool = True            # Must have value to execute

    def __post_init__(self):
        """Ensure name doesn't include angle brackets"""
        # Remove <> if present (normalize to just the name)
        self.name = self.name.strip('<>')


@dataclass
class AlternativeCommand:
    """Alternative command definition"""

    # Identity
    id: str                          # Unique identifier (e.g., 'alt-manual-curl-dir')
    name: str                        # Human-readable name
    command_template: str            # Command with <PLACEHOLDER> variables

    # Categorization
    category: str                    # Primary category (web-enumeration, privesc, etc.)
    subcategory: Optional[str] = None  # Secondary category

    # Description
    description: str = ''            # What this command achieves

    # Variables
    variables: List[Variable] = field(default_factory=list)

    # Educational metadata (OSCP-focused)
    tags: List[str] = field(default_factory=list)
    os_type: str = 'both'           # 'linux', 'windows', 'both'
    flag_explanations: Dict[str, str] = field(default_factory=dict)
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    notes: str = ''

    # Linkage to task tree
    parent_task_pattern: Optional[str] = None  # Glob pattern (e.g., 'gobuster-*')

    def get_variable(self, name: str) -> Optional[Variable]:
        """Get variable by name"""
        # Normalize name (remove <> if present)
        name = name.strip('<>')
        for var in self.variables:
            if var.name == name:
                return var
        return None

    def get_required_variables(self) -> List[Variable]:
        """Get all required variables"""
        return [v for v in self.variables if v.required]

    def get_auto_resolve_variables(self) -> List[Variable]:
        """Get variables that should auto-resolve"""
        return [v for v in self.variables if v.auto_resolve]


@dataclass
class ExecutionResult:
    """Result of alternative command execution"""

    success: bool                    # Execution succeeded
    command: str                     # Final command that was executed
    output: str = ''                 # Standard output
    error: str = ''                  # Standard error
    return_code: int = 0             # Process return code
    cancelled: bool = False          # User cancelled execution
    variables_used: Dict[str, str] = field(default_factory=dict)
    output_file: Optional[str] = None  # Path to saved output file (if any)

    def __str__(self):
        if self.cancelled:
            return "Execution cancelled by user"
        if self.success:
            result = f"Success: {self.command}"
            if self.output_file:
                result += f"\nOutput saved to: {self.output_file}"
            return result
        return f"Failed (code {self.return_code}): {self.error[:100]}"
