"""Directory and file fuzzing adapter using ffuf."""
from typing import Dict, Any, List, Optional
import json
import logging

from ctf_autopwn.adapters.base import CommandToolAdapter

logger = logging.getLogger(__name__)


class FFUFAdapter(CommandToolAdapter):
    """Directory/file fuzzer wrapper using ffuf.
    
    Normalizes ffuf output to:
    {
        "target": "http://example.com",
        "wordlist": "common.txt",
        "results": [
            {
                "path": "/admin",
                "status": 200,
                "length": 1234,
                "lines": 45,
                "words": 120,
            },
            ...
        ],
        "error": None
    }
    """
    
    DEFAULT_WORDLIST = "/usr/share/dirb/wordlists/common.txt"

    def __init__(self, timeout: float = 300.0):
        super().__init__("ffuf", timeout=timeout)
    
    def build_command(self, target: str, args: Dict[str, Any]) -> List[str]:
        """Build ffuf command.
        
        Args:
            target: Base URL (e.g., http://example.com/FUZZ)
            args: Optional args
                - wordlist: Path to wordlist file (default: common.txt)
                - extensions: ".php,.html,.js" (default: empty)
                - match_status: "200,204,301,302" (default: auto)
                - filter_status: "403,404" (default: auto)
                - match_size: "1234" (default: off)
                - filter_size: "1234" (default: off)
                - threads: int (default: 40)
                - timeout: float (default: 10)
                - headers: Dict of custom headers
        
        Returns:
            ffuf command as list
        """
        cmd = ["ffuf",
               "-o", "/tmp/ffuf_output.json", "-of", "json",
               "-noninteractive",   # never prompt — critical for subprocess
               "-ac",               # auto-calibrate: filter uniform responses
               "-ic",               # ignore wordlist comments
               ]
        
        # Wordlist
        wordlist = args.get("wordlist", self.DEFAULT_WORDLIST)
        cmd.extend(["-w", wordlist])
        
        # Extensions
        if "extensions" in args:
            cmd.extend(["-e", args["extensions"]])
        
        # Match/Filter status codes
        if "match_status" in args:
            cmd.extend(["-mc", args["match_status"]])
        if "filter_status" in args:
            cmd.extend(["-fc", args["filter_status"]])
        
        # Match/Filter response size
        if "match_size" in args:
            cmd.extend(["-ms", str(args["match_size"])])
        if "filter_size" in args:
            cmd.extend(["-fs", str(args["filter_size"])])
        
        # Threads — default 100 for fast local/CTF targets
        threads = args.get("threads", 100)
        cmd.extend(["-t", str(threads)])
        
        # Per-request timeout — 5s is plenty for CTF targets
        timeout = args.get("timeout", 5)
        cmd.extend(["-timeout", str(timeout)])
        
        # Custom headers
        headers = args.get("headers", {})
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])
        
        # URL with FUZZ placeholder
        cmd.extend(["-u", target])
        
        return cmd
    
    def normalize_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse ffuf JSON output.
        
        Args:
            raw_output: ffuf output (usually reads from file)
        
        Returns:
            Normalized output dict
        """
        result = {
            "target": "",
            "wordlist": "",
            "results": [],
            "error": None,
        }
        
        try:
            # Try to parse JSON from the output
            # ffuf outputs JSON to file and a summary to stdout
            data = json.loads(raw_output)
            
            # Extract results
            if "results" in data:
                for item in data["results"]:
                    result_item = {
                        "path": item.get("input", {}).get("FUZZ", ""),
                        "status": item.get("status", 0),
                        "length": item.get("length", 0),
                        "lines": item.get("lines", 0),
                        "words": item.get("words", 0),
                        "redirects": item.get("redirects", ""),
                    }
                    result["results"].append(result_item)
            
            logger.debug(f"[ffuf] Found {len(result['results'])} results")
            return result
        
        except json.JSONDecodeError:
            # If JSON parsing fails, try to parse from text output
            logger.warning("[ffuf] JSON parse failed, attempting text parsing")
            return self._parse_text_output(raw_output, result)
        except Exception as e:
            logger.error(f"[ffuf] Error parsing output: {str(e)}")
            result["error"] = str(e)
            return result
    
    def _parse_text_output(self, output: str, result: Dict) -> Dict[str, Any]:
        """Fallback: parse ffuf text output (summary only).
        
        Args:
            output: Text output from ffuf
            result: Result dict to populate
        
        Returns:
            Result dict with parsed results
        """
        # This is a best-effort parse of ffuf text output
        # Results will be incomplete compared to JSON output
        for line in output.split("\n"):
            if "200" in line or "301" in line or "302" in line:
                # Try to extract path and status
                parts = line.split()
                if len(parts) >= 2:
                    # Rough parsing - may not work perfectly
                    result["results"].append({
                        "path": parts[0],
                        "status": 0,
                        "length": 0,
                        "lines": 0,
                        "words": 0,
                    })
        
        return result


class DirSearchAdapter(CommandToolAdapter):
    """Directory scanner using dirsearch (Python-based alternative to ffuf).
    
    Good fallback if ffuf is not available.
    """
    
    def __init__(self, timeout: float = 120.0):
        super().__init__("dirsearch", timeout=timeout)
    
    def build_command(self, target: str, args: Dict[str, Any]) -> List[str]:
        """Build dirsearch command.
        
        Args:
            target: Base URL (e.g., http://example.com)
            args: Optional args (similar to FFUFAdapter)
        
        Returns:
            dirsearch command as list
        """
        cmd = ["dirsearch", "-u", target, "-f", "--format=json"]
        
        # Wordlist
        if "wordlist" in args:
            cmd.extend(["-w", args["wordlist"]])
        
        # Extensions
        if "extensions" in args:
            cmd.extend(["-e", args["extensions"]])
        
        # Threads
        threads = args.get("threads", 50)
        cmd.extend(["--threads", str(threads)])
        
        return cmd
    
    def normalize_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse dirsearch JSON output."""
        result = {
            "target": "",
            "wordlist": "",
            "results": [],
            "error": None,
        }
        
        try:
            # dirsearch outputs JSON
            data = json.loads(raw_output)
            
            # Extract results from the structure
            if isinstance(data, list):
                for item in data:
                    result["results"].append({
                        "path": item.get("path", ""),
                        "status": item.get("status", 0),
                        "length": item.get("length", 0),
                        "lines": item.get("lines", 0),
                        "words": item.get("words", 0),
                    })
            
            logger.debug(f"[dirsearch] Found {len(result['results'])} results")
            return result
        
        except Exception as e:
            logger.error(f"[dirsearch] Error parsing output: {str(e)}")
            result["error"] = str(e)
            return result
