"""File analysis adapter using binwalk."""
from typing import Dict, Any, List, Optional
import json
import logging

from ctf_autopwn.adapters.base import CommandToolAdapter

logger = logging.getLogger(__name__)


class BinwalkAdapter(CommandToolAdapter):
    """File analysis wrapper using binwalk.
    
    Detects hidden files, compression, entropy, and file types.
    
    Normalizes output to:
    {
        "file": "archive.zip",
        "entropy": 7.8,
        "results": [
            {
                "offset": 0,
                "type": "Zip archive",
                "description": "...",
            },
            ...
        ],
        "error": None
    }
    """
    
    def __init__(self, timeout: float = 60.0):
        super().__init__("binwalk", timeout=timeout)
    
    def build_command(self, target: str, args: Dict[str, Any]) -> List[str]:
        """Build binwalk command.
        
        Args:
            target: File path
            args: Optional args
                - scan: bool (default: True, performs scan)
                - entropy: bool (default: True, shows entropy)
                - extract: bool (default: False, extracts files)
                - signature: bool (default: True, shows signatures)
                - quiet: bool (default: False)
        
        Returns:
            binwalk command as list
        """
        cmd = ["binwalk"]
        
        # Entropy analysis
        if args.get("entropy", True):
            cmd.append("-E")
        
        # Signature scan
        if args.get("signature", True):
            # Already on by default
            pass
        
        # Extraction (dangerous, be careful)
        if args.get("extract", False):
            cmd.append("-e")
        
        # Quiet mode
        if args.get("quiet", False):
            cmd.append("-q")
        
        # File to analyze
        cmd.append(target)
        
        return cmd
    
    def normalize_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse binwalk output.
        
        Args:
            raw_output: binwalk output
        
        Returns:
            Normalized output dict
        """
        result = {
            "file": "",
            "entropy": 0.0,
            "results": [],
            "error": None,
        }
        
        try:
            lines = raw_output.strip().split("\n")
            
            in_entropy = False
            in_results = False
            
            for line in lines:
                # Extract filename
                if "Scan Time:" in line or "Scan started:" in line:
                    continue
                
                # Entropy section
                if "ENTROPY" in line:
                    in_entropy = True
                    in_results = False
                    continue
                
                if in_entropy:
                    # Parse entropy values (e.g., "0.0   0%  0x0")
                    parts = line.split()
                    if len(parts) >= 1:
                        try:
                            entropy_val = float(parts[0])
                            result["entropy"] = entropy_val
                        except ValueError:
                            pass
                    in_entropy = False
                
                # Results section (file signatures)
                if line.startswith("0x"):
                    # Format: "0x0   ZIP    Zip archive data"
                    parts = line.split(None, 2)
                    if len(parts) >= 2:
                        result_item = {
                            "offset": parts[0],
                            "type": parts[1],
                            "description": parts[2] if len(parts) > 2 else "",
                        }
                        result["results"].append(result_item)
            
            logger.debug(
                f"[binwalk] Analyzed file: entropy={result['entropy']}, "
                f"found {len(result['results'])} signatures"
            )
            
            return result
        
        except Exception as e:
            logger.error(f"[binwalk] Error parsing output: {str(e)}")
            result["error"] = str(e)
            return result


class ExiftoolAdapter(CommandToolAdapter):
    """Metadata extraction using exiftool.
    
    Extracts metadata from files (images, PDFs, etc.).
    
    Normalizes to:
    {
        "file": "image.jpg",
        "metadata": {
            "MIME Type": "image/jpeg",
            "Image Width": "1920",
            ...
        },
        "error": None
    }
    """
    
    def __init__(self, timeout: float = 30.0):
        super().__init__("exiftool", timeout=timeout)
    
    def build_command(self, target: str, args: Dict[str, Any]) -> List[str]:
        """Build exiftool command.
        
        Args:
            target: File path
            args: Optional args
                - json: bool (default: True, output as JSON)
        
        Returns:
            exiftool command as list
        """
        cmd = ["exiftool"]
        
        # JSON output
        if args.get("json", True):
            cmd.append("-json")
        
        cmd.append(target)
        
        return cmd
    
    def normalize_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse exiftool JSON output.
        
        Args:
            raw_output: exiftool JSON output
        
        Returns:
            Normalized output dict
        """
        result = {
            "file": "",
            "metadata": {},
            "error": None,
        }
        
        try:
            # exiftool outputs JSON array
            data = json.loads(raw_output)
            
            if isinstance(data, list) and len(data) > 0:
                result["metadata"] = data[0]
                result["file"] = data[0].get("SourceFile", "")
            
            logger.debug(f"[exiftool] Extracted {len(result['metadata'])} metadata fields")
            return result
        
        except json.JSONDecodeError as e:
            logger.error(f"[exiftool] JSON parse error: {str(e)}")
            result["error"] = f"JSON parse error: {str(e)}"
            return result
        except Exception as e:
            logger.error(f"[exiftool] Error parsing output: {str(e)}")
            result["error"] = str(e)
            return result


class FileTypeAdapter(CommandToolAdapter):
    """Simple file type detection using 'file' command.
    
    Fast way to identify file types.
    """
    
    def __init__(self, timeout: float = 10.0):
        super().__init__("file", timeout=timeout)
    
    def build_command(self, target: str, args: Dict[str, Any]) -> List[str]:
        """Build file command."""
        return ["file", "-b", target]  # -b: brief mode
    
    def normalize_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse file command output."""
        result = {
            "file": "",
            "type": raw_output.strip(),
            "error": None,
        }
        return result
