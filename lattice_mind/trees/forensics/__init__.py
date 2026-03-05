"""Forensics and steganography detection trees.

Implements forensics/stego vulnerability detection:
- Image steganography (LSB, DCT, etc.)
- Metadata extraction
- File carving and recovery
- Memory dump analysis
- PCAP analysis
"""

from .detect import (
    ForensicsDetectArtifactNode,
    ForensicsImageStegoNode,
    ForensicsEmbeddedDataNode,
    ForensicsMetadataNode,
    ForensicsPCAPNode,
    ForensicsMemoryNode,
    ForensicsDiskImageNode,
)

__all__ = [
    "ForensicsDetectArtifactNode",
    "ForensicsImageStegoNode",
    "ForensicsEmbeddedDataNode",
    "ForensicsMetadataNode",
    "ForensicsPCAPNode",
    "ForensicsMemoryNode",
    "ForensicsDiskImageNode",
]
