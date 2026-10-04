"""Forensic tool adapters.

Every adapter reports its availability HONESTLY.  If a tool is not installed,
the adapter returns ``NOT_INSTALLED`` - it never fabricates output.
"""

from app.adapters.autopsy_adapter import AutopsyAdapter
from app.adapters.base import AnalysisResult, BaseToolAdapter
from app.adapters.generic_adapter import GenericAdapter
from app.adapters.registry import AdapterRegistry, registry
from app.adapters.siem_adapter import SiemAdapter
from app.adapters.tshark_adapter import TsharkAdapter
from app.adapters.velociraptor_adapter import VelociraptorAdapter
from app.adapters.yara_adapter import YaraAdapter
from app.adapters.zeek_adapter import ZeekAdapter

__all__ = [
    "BaseToolAdapter",
    "AnalysisResult",
    "TsharkAdapter",
    "ZeekAdapter",
    "YaraAdapter",
    "VelociraptorAdapter",
    "SiemAdapter",
    "AutopsyAdapter",
    "GenericAdapter",
    "AdapterRegistry",
    "registry",
]