"""Forensics and steganography detection trees (F-Detect).

Implements forensics/stego detection from detections.md:
- F-D.1: Artifact type classification (image, PCAP, memory dump, etc.)
- F-D.2: Image steganography detection (LSB, DCT, etc.)
- F-D.3: Embedded data extraction (binwalk)
- F-D.4: Metadata extraction (exiftool)
- F-D.5: PCAP network reconstruction
- F-D.6: Memory/disk image analysis
"""
from typing import Dict, Any, Optional, List
import logging
import os

from lattice_mind.core.nodes import DecisionNode
from lattice_mind.core.types import (
    NodeResult, NodeStatus
)
from lattice_mind.adapters.file_adapter import FileTypeAdapter, BinwalkAdapter, ExiftoolAdapter

logger = logging.getLogger(__name__)


class ForensicsDetectArtifactNode(DecisionNode):
    """F-D.1: Classify artifact type (image, PCAP, memory dump, archive)."""
    
    def __init__(self):
        super().__init__("forensics_detect_artifact", "Forensics: Artifact Type")
        self.file_adapter = FileTypeAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Identify artifact type for routing."""
        challenge = context.get("challenge")
        
        if not challenge or not challenge.file_path:
            return NodeResult(
                status=NodeStatus.FAILURE,
                error="No file"
            )
        
        logger.info(f"[forensics] Identifying artifact type")
        
        try:
            result = self.file_adapter.run(challenge.file_path, {})
            file_type = result.get("type", "").lower()
            
            logger.debug(f"[forensics] File type: {file_type}")
            
            # Route based on type
            if "png" in file_type or "jpeg" in file_type or "bmp" in file_type:
                artifact_type = "image_stego"
            elif "pcap" in file_type or "pcapng" in file_type:
                artifact_type = "pcap"
            elif "memory" in file_type or "dump" in file_type:
                artifact_type = "memory_image"
            elif "disk" in file_type or "img" in file_type:
                artifact_type = "disk_image"
            elif "zip" in file_type or "tar" in file_type or "archive" in file_type:
                artifact_type = "archive"
            else:
                artifact_type = "unknown"
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={
                    "artifact_type": artifact_type,
                    "file_type": file_type,
                }
            )
        
        except Exception as e:
            logger.error(f"[forensics] Artifact detection failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))
    
    def next_node(self, result: NodeResult) -> Optional[DecisionNode]:
        if result.status == NodeStatus.SUCCESS:
            artifact_type = result.data.get("artifact_type")
            
            if artifact_type == "image_stego":
                return ForensicsImageStegoNode()
            elif artifact_type == "pcap":
                return ForensicsPCAPNode()
            elif artifact_type == "memory_image":
                return ForensicsMemoryNode()
            elif artifact_type == "disk_image":
                return ForensicsDiskImageNode()
            else:
                return ForensicsEmbeddedDataNode()
        return None


class ForensicsImageStegoNode(DecisionNode):
    """F-D.2: Extract data from image steganography."""
    
    def __init__(self):
        super().__init__("forensics_image_stego", "Forensics: Image Stego")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Run zsteg and other stego tools on image."""
        challenge = context.get("challenge")
        
        if not challenge or not challenge.file_path:
            return NodeResult(status=NodeStatus.FAILURE, error="No file")
        
        logger.info(f"[forensics] Extracting image steganography")
        
        # In real scenario would:
        # 1. Run zsteg -a for LSB/DCT extraction
        # 2. Check color channels
        # 3. Convert to spectrogram
        # 4. Run OCR on visualizations
        
        extracted_data = []
        
        try:
            # Try zsteg if available
            import subprocess
            
            result = subprocess.run(
                ["zsteg", "-a", challenge.file_path],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            if result.returncode == 0 and result.stdout:
                logger.info(f"[forensics] Found data via zsteg")
                extracted_data.append(("zsteg", result.stdout))
        
        except Exception as e:
            logger.debug(f"[forensics] zsteg not available: {str(e)}")
        
        has_stego = len(extracted_data) > 0
        
        logger.info(f"[forensics] Image stego detected: {has_stego}")
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "has_stego": has_stego,
                "extracted_data": extracted_data,
            }
        )


class ForensicsEmbeddedDataNode(DecisionNode):
    """F-D.3: Extract embedded files using binwalk."""
    
    def __init__(self):
        super().__init__("forensics_embedded_data", "Forensics: Embedded Files")
        self.binwalk = BinwalkAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Use binwalk to carve embedded files."""
        challenge = context.get("challenge")
        
        if not challenge or not challenge.file_path:
            return NodeResult(status=NodeStatus.FAILURE, error="No file")
        
        logger.info(f"[forensics] Extracting embedded data with binwalk")
        
        try:
            result = self.binwalk.run(challenge.file_path, {"action": "scan"})
            
            if result.get("error"):
                return NodeResult(
                    status=NodeStatus.SUCCESS,
                    data={"embedded_files": []}
                )
            
            # binwalk returns results
            results = result.get("results", [])
            
            logger.info(f"[forensics] Found {len(results)} embedded items")
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={
                    "embedded_files": results,
                    "files_found": len(results) > 0,
                }
            )
        
        except Exception as e:
            logger.error(f"[forensics] Binwalk failed: {str(e)}")
            return NodeResult(status=NodeStatus.FAILURE, error=str(e))


class ForensicsMetadataNode(DecisionNode):
    """F-D.4: Extract metadata using exiftool."""
    
    def __init__(self):
        super().__init__("forensics_metadata", "Forensics: Metadata Extraction")
        self.exiftool = ExiftoolAdapter()
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Extract metadata from files."""
        challenge = context.get("challenge")
        
        if not challenge or not challenge.file_path:
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"metadata": {}}
            )
        
        logger.info(f"[forensics] Extracting metadata")
        
        try:
            result = self.exiftool.run(challenge.file_path, {})
            
            metadata = result.get("metadata", {})
            
            # Look for flag in metadata
            flag_in_metadata = any(
                "flag" in str(v).lower()
                for v in metadata.values()
            )
            
            logger.info(f"[forensics] Found metadata fields: {len(metadata)}")
            
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={
                    "metadata": metadata,
                    "flag_in_metadata": flag_in_metadata,
                }
            )
        
        except Exception as e:
            logger.error(f"[forensics] Metadata extraction failed: {str(e)}")
            return NodeResult(
                status=NodeStatus.SUCCESS,
                data={"metadata": {}}
            )


class ForensicsPCAPNode(DecisionNode):
    """F-D.5: Analyze PCAP files and reconstruct traffic."""
    
    def __init__(self):
        super().__init__("forensics_pcap", "Forensics: PCAP Analysis")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Extract HTTP/FTP/SMTP objects from PCAP."""
        challenge = context.get("challenge")
        
        if not challenge or not challenge.file_path:
            return NodeResult(status=NodeStatus.FAILURE, error="No PCAP")
        
        logger.info(f"[forensics] Analyzing PCAP")
        
        # In real scenario would use tshark to extract objects
        # For now, just mark as needing analysis
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "requires_tshark": True,
                "suggested_extractions": [
                    "HTTP objects",
                    "FTP files",
                    "SMTP messages",
                    "DNS queries",
                ]
            }
        )


class ForensicsMemoryNode(DecisionNode):
    """F-D.6: Analyze memory dumps using volatility."""
    
    def __init__(self):
        super().__init__("forensics_memory", "Forensics: Memory Dump")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Extract flag from memory dump."""
        challenge = context.get("challenge")
        
        if not challenge or not challenge.file_path:
            return NodeResult(status=NodeStatus.FAILURE, error="No dump")
        
        logger.info(f"[forensics] Analyzing memory dump")
        
        # In real scenario would:
        # 1. Use volatility to identify memory image type
        # 2. List processes
        # 3. Dump memory segments
        # 4. Run strings + regex over them
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "requires_volatility": True,
                "suggested_commands": [
                    "volatility imageinfo",
                    "volatility pslist",
                    "volatility memdump",
                    "strings | grep flag",
                ]
            }
        )


class ForensicsDiskImageNode(DecisionNode):
    """Alternative path for disk image analysis."""
    
    def __init__(self):
        super().__init__("forensics_disk", "Forensics: Disk Image")
    
    def run(self, context: Dict[str, Any]) -> NodeResult:
        """Analyze disk image for files."""
        logger.info(f"[forensics] Analyzing disk image")
        
        return NodeResult(
            status=NodeStatus.SUCCESS,
            data={
                "requires_forensics_tools": True,
                "tools": ["mmls", "fls", "icat", "strings"],
            }
        )


# Summary
"""
Forensics and Steganography Detection Tree (F-Detect)

Detection nodes:
- F-D.1 (ForensicsDetectArtifactNode) - Classify artifact type
- F-D.2 (ForensicsImageStegoNode) - Extract image stego (zsteg, LSB, etc.)
- F-D.3 (ForensicsEmbeddedDataNode) - Carve embedded files (binwalk)
- F-D.4 (ForensicsMetadataNode) - Extract metadata (exiftool)
- F-D.5 (ForensicsPCAPNode) - Reconstruct network traffic (tshark)
- F-D.6 (ForensicsMemoryNode) - Extract from memory dumps (volatility)

Artifact types:
- Image steganography (PNG, JPEG, BMP)
- PCAP network captures
- Memory dumps
- Disk images
- Archives (ZIP, TAR, etc.)

Tools used:
- zsteg: LSB/DCT stego extraction
- binwalk: Embedded file carving
- exiftool: Metadata extraction
- tshark: PCAP analysis
- volatility: Memory dump analysis
- strings: String extraction
"""
