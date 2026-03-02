"""Network scanning adapter using nmap."""
from typing import Dict, Any, List, Optional
import xml.etree.ElementTree as ET
import logging

from ctf_autopwn.adapters.base import CommandToolAdapter

logger = logging.getLogger(__name__)


class NmapAdapter(CommandToolAdapter):
    """Network scanner wrapper using nmap.
    
    Normalizes nmap output to:
    {
        "target": "192.168.1.1",
        "status": "up|down|unknown",
        "open_ports": [80, 443, 8080],
        "services": {
            80: {"name": "http", "version": "..."},
            443: {"name": "https", "version": "..."},
            ...
        },
        "os_detection": {...},
        "error": None
    }
    """
    
    def __init__(self, timeout: float = 60.0):
        super().__init__("nmap", timeout=timeout)
    
    def build_command(self, target: str, args: Dict[str, Any]) -> List[str]:
        """Build nmap command.
        
        Args:
            target: IP, hostname, or CIDR range
            args: Optional args
                - ports: "80,443" or "1-65535" (default: common ports)
                - service_detection: bool (default: True, enables -sV)
                - os_detection: bool (default: False, enables -O)
                - aggressive: bool (default: False, enables -A)
                - scripts: bool (default: False, enables -sC)
                - output_format: "xml" or "text" (default: xml)
        
        Returns:
            nmap command as list
        """
        cmd = ["nmap"]
        
        # Port specification
        ports = args.get("ports", "1-1000")  # Default: common ports
        cmd.extend(["-p", ports])
        
        # Service detection
        if args.get("service_detection", True):
            cmd.append("-sV")
        
        # OS detection
        if args.get("os_detection", False):
            cmd.append("-O")
        
        # Aggressive scan
        if args.get("aggressive", False):
            cmd.append("-A")
        
        # Script scanning
        if args.get("scripts", False):
            cmd.append("-sC")
        
        # Output format
        output_format = args.get("output_format", "xml")
        if output_format == "xml":
            cmd.append("-oX")
            cmd.append("-")  # Output to stdout
        
        cmd.append(target)
        return cmd
    
    def normalize_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse nmap XML output.
        
        Args:
            raw_output: Nmap XML output
        
        Returns:
            Normalized output dict
        """
        result = {
            "target": "",
            "status": "unknown",
            "open_ports": [],
            "services": {},
            "os_detection": {},
            "error": None,
        }
        
        try:
            # Parse XML
            root = ET.fromstring(raw_output)
            
            # Extract host information
            host_elem = root.find(".//host")
            if host_elem is None:
                result["error"] = "No host found in nmap output"
                return result
            
            # Get host status
            status_elem = host_elem.find("status")
            if status_elem is not None:
                result["status"] = status_elem.get("state", "unknown")
            
            # Get target address
            addr_elem = host_elem.find("address")
            if addr_elem is not None:
                result["target"] = addr_elem.get("addr", "")
            
            # Extract open ports and services
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port_num = int(port_elem.get("portid", 0))
                    
                    # Check if port is open
                    state_elem = port_elem.find("state")
                    if state_elem is not None and state_elem.get("state") == "open":
                        result["open_ports"].append(port_num)
                    
                    # Extract service information
                    service_elem = port_elem.find("service")
                    if service_elem is not None:
                        service_info = {
                            "name": service_elem.get("name", "unknown"),
                            "product": service_elem.get("product", ""),
                            "version": service_elem.get("version", ""),
                            "method": service_elem.get("method", ""),
                        }
                        result["services"][port_num] = service_info
            
            # Extract OS detection if available
            os_elem = host_elem.find("os")
            if os_elem is not None:
                for osmatch in os_elem.findall("osmatch"):
                    os_name = osmatch.get("name", "")
                    accuracy = osmatch.get("accuracy", "0")
                    if os_name:
                        result["os_detection"][os_name] = {
                            "accuracy": accuracy,
                        }
            
            logger.debug(
                f"[nmap] Parsed scan: target={result['target']}, "
                f"status={result['status']}, "
                f"open_ports={result['open_ports']}"
            )
            
            return result
        
        except ET.ParseError as e:
            logger.error(f"[nmap] XML parse error: {str(e)}")
            result["error"] = f"XML parse error: {str(e)}"
            return result
        except Exception as e:
            logger.error(f"[nmap] Error parsing output: {str(e)}")
            result["error"] = str(e)
            return result


class SimplePortScanAdapter(CommandToolAdapter):
    """Simplified port scanner using nc (netcat) for when nmap is unavailable.
    
    Much slower than nmap, but works with basic tools.
    """
    
    def __init__(self, timeout: float = 30.0):
        super().__init__("nc", timeout=timeout)
    
    def build_command(self, target: str, args: Dict[str, Any]) -> List[str]:
        """Not used - we scan ports manually."""
        raise NotImplementedError("SimplePortScanAdapter uses custom logic")
    
    def run(self, target: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Scan ports using nc."""
        result = {
            "target": target,
            "status": "unknown",
            "open_ports": [],
            "services": {},
            "error": None,
        }
        
        # Parse port range
        ports_str = args.get("ports", "1-1000")
        try:
            if "-" in ports_str:
                start, end = ports_str.split("-")
                ports = range(int(start), int(end) + 1)
            else:
                ports = [int(p) for p in ports_str.split(",")]
        except (ValueError, AttributeError):
            result["error"] = f"Invalid port specification: {ports_str}"
            return result
        
        # Try to scan each port
        logger.info(f"[nc] Scanning {len(list(ports))} ports on {target}")
        for port in ports:
            try:
                cmd = ["nc", "-zv", "-w", "2", target, str(port)]
                output = self.execute_command(cmd)
                
                if "succeeded" in output or "open" in output:
                    result["open_ports"].append(port)
                    result["services"][port] = {
                        "name": "unknown",
                        "version": "",
                    }
            except RuntimeError:
                # Port closed or timeout - expected
                pass
        
        result["status"] = "up" if result["open_ports"] else "down"
        return result
