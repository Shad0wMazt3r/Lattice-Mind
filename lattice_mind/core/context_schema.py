"""Context schema validation and normalization for execution context.

This module standardizes the structure of the execution context dictionary
to prevent key naming inconsistencies and ensure type safety across tree nodes.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
import logging

logger = logging.getLogger(__name__)


@dataclass
class ObservationSchema:
    """Standard schema for context['observations'] dictionary.
    
    Defines expected keys and provides normalization for naming conflicts
    identified across Python and YAML trees.
    """
    
    # Web reconnaissance
    http_response: Optional[Dict[str, Any]] = None
    technologies: List[str] = field(default_factory=list)  # Canonical
    crawled_endpoints: List[str] = field(default_factory=list)
    params: List[Dict[str, Any]] = field(default_factory=list)  # Canonical
    forms: List[Dict[str, Any]] = field(default_factory=list)
    request_candidates: List[Dict[str, Any]] = field(default_factory=list)
    form_reviews: List[Dict[str, Any]] = field(default_factory=list)
    crawl_graph: Optional[Dict[str, Any]] = None
    crawl_stats: Optional[Dict[str, Any]] = None
    flags: List[str] = field(default_factory=list)
    session_cookies: Dict[str, str] = field(default_factory=dict)
    detected_flag: Optional[str] = None
    found_paths: List[str] = field(default_factory=list)  # Canonical (directories)
    
    # Vulnerability detection
    vuln_candidates: List[Dict[str, Any]] = field(default_factory=list)
    auth_bypass_results: List[Dict[str, Any]] = field(default_factory=list)
    
    # Binary analysis
    asset_type: Optional[str] = None
    binary_protections: Optional[Dict[str, bool]] = None
    symbols: List[str] = field(default_factory=list)
    
    # Crypto analysis
    crypto_content: Optional[str] = None
    decoded_text: Optional[str] = None
    decode_steps: List[str] = field(default_factory=list)
    
    # Tool outputs (generic storage for adapter results)
    tool_outputs: Dict[str, Any] = field(default_factory=dict)
    
    # DEPRECATED fields (for backward compatibility)
    tech_stack: Optional[List[str]] = None  # Use 'technologies' instead
    potential_params: Optional[List[Dict[str, Any]]] = None  # Use 'params' instead
    directories: Optional[List[str]] = None  # Use 'found_paths' instead
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert schema to dictionary, excluding None values and deprecated fields."""
        result = {}
        for key, value in self.__dict__.items():
            # Skip deprecated fields
            if key in ('tech_stack', 'potential_params', 'directories'):
                continue
            # Skip None values to keep context clean
            if value is not None and value != [] and value != {}:
                result[key] = value
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ObservationSchema':
        """Create schema from dictionary, normalizing deprecated keys.
        
        Args:
            data: Raw observations dictionary from context
            
        Returns:
            ObservationSchema with normalized field names
        """
        schema = cls()
        
        # Copy known fields
        for key in schema.__dataclass_fields__:
            if key in data:
                setattr(schema, key, data[key])
        
        # Normalize deprecated field names
        if 'tech_stack' in data and not schema.technologies:
            schema.technologies = data['tech_stack']
            logger.debug("Normalized 'tech_stack' to 'technologies'")
        
        if 'potential_params' in data and not schema.params:
            schema.params = data['potential_params']
            logger.debug("Normalized 'potential_params' to 'params'")
        
        if 'directories' in data and not schema.found_paths:
            schema.found_paths = data['directories']
            logger.debug("Normalized 'directories' to 'found_paths'")
        
        # Store unknown keys in tool_outputs
        known_keys = set(schema.__dataclass_fields__.keys())
        for key, value in data.items():
            if key not in known_keys:
                schema.tool_outputs[key] = value
                logger.debug(f"Unknown observation key '{key}' stored in tool_outputs")
        
        return schema
    
    def validate(self) -> List[str]:
        """Validate schema and return list of issues.
        
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Check for use of deprecated keys
        if self.tech_stack is not None:
            errors.append("Using deprecated 'tech_stack'; use 'technologies' instead")
        
        if self.potential_params is not None:
            errors.append("Using deprecated 'potential_params'; use 'params' instead")
        
        if self.directories is not None:
            errors.append("Using deprecated 'directories'; use 'found_paths' instead")
        
        # Type validation
        if self.technologies is not None and not isinstance(self.technologies, list):
            errors.append(f"'technologies' must be list, got {type(self.technologies)}")
        
        if self.params is not None and not isinstance(self.params, list):
            errors.append(f"'params' must be list, got {type(self.params)}")
        
        if self.found_paths is not None and not isinstance(self.found_paths, list):
            errors.append(f"'found_paths' must be list, got {type(self.found_paths)}")
        
        return errors


@dataclass
class ContextSchema:
    """Full execution context schema.
    
    Validates and normalizes the entire context dictionary passed to nodes.
    """
    
    challenge: Optional[Any] = None  # ChallengeDescriptor (avoid circular import)
    observations: ObservationSchema = field(default_factory=ObservationSchema)
    flag_found: Optional[str] = None
    target_param: Optional[Dict[str, Any]] = None  # For manual parameter injection
    confirmed_vulns: List[Any] = field(default_factory=list)  # List[VulnDescriptor]
    
    # Additional execution metadata
    tree_id: Optional[str] = None
    node_path: List[str] = field(default_factory=list)  # Execution path trace
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert schema to dictionary for use as execution context."""
        result = {
            "challenge": self.challenge,
            "observations": self.observations.to_dict(),
            "flag_found": self.flag_found,
        }
        
        if self.target_param is not None:
            result["target_param"] = self.target_param
        
        if self.confirmed_vulns:
            result["confirmed_vulns"] = self.confirmed_vulns
        
        if self.tree_id:
            result["tree_id"] = self.tree_id
        
        if self.node_path:
            result["node_path"] = self.node_path
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContextSchema':
        """Create schema from raw context dictionary.
        
        Args:
            data: Raw execution context
            
        Returns:
            ContextSchema with validated and normalized structure
        """
        observations_data = data.get("observations", {})
        observations = ObservationSchema.from_dict(observations_data)
        
        return cls(
            challenge=data.get("challenge"),
            observations=observations,
            flag_found=data.get("flag_found"),
            target_param=data.get("target_param"),
            confirmed_vulns=data.get("confirmed_vulns", []),
            tree_id=data.get("tree_id"),
            node_path=data.get("node_path", []),
        )
    
    def validate(self) -> List[str]:
        """Validate entire context schema.
        
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Validate observations
        obs_errors = self.observations.validate()
        errors.extend(obs_errors)
        
        # Check for required fields
        if self.challenge is None:
            errors.append("Context missing required 'challenge' field")
        
        return errors
    
    def normalize(self) -> 'ContextSchema':
        """Normalize context by applying all field mappings.
        
        This method ensures deprecated field names are migrated to canonical names.
        
        Returns:
            Self (for method chaining)
        """
        # ObservationSchema.from_dict already handles normalization
        # Just clear deprecated fields
        self.observations.tech_stack = None
        self.observations.potential_params = None
        self.observations.directories = None
        
        return self


def validate_context(context: Dict[str, Any], strict: bool = False) -> List[str]:
    """Validate execution context dictionary.
    
    Args:
        context: Raw execution context to validate
        strict: If True, raise exception on validation errors
        
    Returns:
        List of validation error messages (empty if valid)
        
    Raises:
        ValueError: If strict=True and validation fails
    """
    schema = ContextSchema.from_dict(context)
    errors = schema.validate()
    
    if errors:
        error_msg = f"Context validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
        logger.warning(error_msg)
        
        if strict:
            raise ValueError(error_msg)
    
    return errors


def normalize_context(context: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize context dictionary by fixing deprecated field names.
    
    Args:
        context: Raw execution context
        
    Returns:
        Normalized context dictionary with canonical field names
    """
    schema = ContextSchema.from_dict(context)
    schema.normalize()
    return schema.to_dict()


def get_observation(context: Dict[str, Any], key: str, default: Any = None) -> Any:
    """Safely retrieve observation from context with fallback to deprecated names.
    
    Args:
        context: Execution context
        key: Observation key to retrieve
        default: Default value if key not found
        
    Returns:
        Observation value or default
    """
    observations = context.get("observations", {})
    
    # Try canonical name first
    if key in observations:
        return observations[key]
    
    # Fallback to deprecated names
    deprecated_map = {
        "technologies": "tech_stack",
        "params": "potential_params",
        "found_paths": "directories",
    }
    
    if key in deprecated_map:
        deprecated_key = deprecated_map[key]
        if deprecated_key in observations:
            logger.debug(f"Using deprecated key '{deprecated_key}' for '{key}'")
            return observations[deprecated_key]
    
    return default


def set_observation(context: Dict[str, Any], key: str, value: Any) -> None:
    """Set observation in context using canonical field name.
    
    Args:
        context: Execution context
        key: Canonical observation key
        value: Value to store
    """
    if "observations" not in context:
        context["observations"] = {}
    
    context["observations"][key] = value
    
    # Warn if trying to use deprecated key
    deprecated_keys = {"tech_stack", "potential_params", "directories"}
    if key in deprecated_keys:
        logger.warning(f"Setting deprecated observation key '{key}'; use canonical name instead")
