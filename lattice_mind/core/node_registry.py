"""Node registry for dynamic node routing and instantiation.

Enables routing decision nodes by string IDs instead of hard-coded instantiation.
Supports auto-registration from modules and polymorphic node replacement.
"""
import inspect
import logging
from typing import Callable, Dict, Optional, Type
from lattice_mind.core.nodes import DecisionNode

logger = logging.getLogger(__name__)


class NodeRegistry:
    """Registry for decision tree nodes with dynamic routing capabilities."""
    
    def __init__(self):
        self._factories: Dict[str, Callable[[], DecisionNode]] = {}
        self._metadata: Dict[str, Dict] = {}
    
    def register(
        self, 
        node_id: str, 
        factory: Callable[[], DecisionNode],
        metadata: Optional[Dict] = None
    ):
        """Register a node factory by ID.
        
        Args:
            node_id: Unique identifier for the node
            factory: Callable that returns a DecisionNode instance
            metadata: Optional metadata about the node (category, description, etc.)
        """
        if node_id in self._factories:
            logger.warning(f"Overwriting existing node registration: {node_id}")
        
        self._factories[node_id] = factory
        self._metadata[node_id] = metadata or {}
        logger.debug(f"Registered node: {node_id}")
    
    def create(self, node_id: str) -> Optional[DecisionNode]:
        """Instantiate a node by its ID.
        
        Args:
            node_id: Node identifier to instantiate
            
        Returns:
            DecisionNode instance or None if not found
        """
        factory = self._factories.get(node_id)
        if not factory:
            logger.error(f"Node not found in registry: {node_id}")
            return None
        
        try:
            node = factory()
            logger.debug(f"Created node instance: {node_id}")
            return node
        except Exception as e:
            logger.error(f"Failed to create node {node_id}: {e}")
            return None
    
    def is_registered(self, node_id: str) -> bool:
        """Check if a node ID is registered.
        
        Args:
            node_id: Node identifier to check
            
        Returns:
            True if registered, False otherwise
        """
        return node_id in self._factories
    
    def list_nodes(self) -> Dict[str, Dict]:
        """List all registered nodes with metadata.
        
        Returns:
            Dict mapping node IDs to metadata
        """
        return {
            node_id: {
                **self._metadata[node_id],
                "factory": self._factories[node_id].__name__
            }
            for node_id in self._factories
        }
    
    def auto_register_module(self, module, category: Optional[str] = None):
        """Auto-discover and register all DecisionNode classes in a module.
        
        Args:
            module: Python module to scan for DecisionNode classes
            category: Optional category to tag all discovered nodes with
        """
        registered_count = 0
        
        for name, obj in inspect.getmembers(module, inspect.isclass):
            # Skip imports and abstract base classes
            if obj.__module__ != module.__name__:
                continue
            
            # Check if it's a DecisionNode subclass
            if issubclass(obj, DecisionNode) and obj is not DecisionNode:
                try:
                    # Try to instantiate to get node_id
                    instance = obj()
                    node_id = instance.node_id
                    
                    metadata = {
                        "class_name": name,
                        "module": module.__name__,
                        "category": category or self._infer_category(module.__name__),
                        "name": instance.name
                    }
                    
                    self.register(node_id, obj, metadata)
                    registered_count += 1
                    
                except Exception as e:
                    logger.warning(f"Failed to auto-register {name}: {e}")
        
        logger.info(f"Auto-registered {registered_count} nodes from {module.__name__}")
        return registered_count
    
    def auto_register_package(self, package_path: str):
        """Auto-discover and register all nodes in a package.
        
        Args:
            package_path: Dot-separated package path (e.g., 'lattice_mind.trees.web')
        """
        import importlib
        import pkgutil
        
        try:
            package = importlib.import_module(package_path)
            
            # Walk package and submodules
            for importer, modname, ispkg in pkgutil.walk_packages(
                path=package.__path__,
                prefix=package.__name__ + '.',
                onerror=lambda x: None
            ):
                try:
                    module = importlib.import_module(modname)
                    self.auto_register_module(module)
                except Exception as e:
                    logger.debug(f"Skipping {modname}: {e}")
        
        except Exception as e:
            logger.error(f"Failed to auto-register package {package_path}: {e}")
    
    def _infer_category(self, module_name: str) -> str:
        """Infer category from module name.
        
        Args:
            module_name: Full module name
            
        Returns:
            Inferred category string
        """
        parts = module_name.split('.')
        
        # Extract category from path like 'lattice_mind.trees.web.sqli'
        if 'trees' in parts:
            idx = parts.index('trees')
            if idx + 1 < len(parts):
                return parts[idx + 1]  # 'web', 'pwn', 'crypto', etc.
        
        return 'unknown'
    
    def clear(self):
        """Clear all registered nodes."""
        self._factories.clear()
        self._metadata.clear()
        logger.info("Cleared node registry")


# Global singleton instance
_registry: Optional[NodeRegistry] = None


def get_node_registry() -> NodeRegistry:
    """Get the global node registry singleton.
    
    Returns:
        Global NodeRegistry instance
    """
    global _registry
    if _registry is None:
        _registry = NodeRegistry()
    return _registry


def reset_node_registry():
    """Reset the global registry (mainly for testing)."""
    global _registry
    _registry = None
