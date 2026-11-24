"""
Mitigation package for OpenFlow 1.3 Controller.

Provides automated flow mitigation engine to drop malicious traffic
at priority 1000 while preserving legitimate communications.
"""

from mitigation.mitigation_engine import MitigationEngine

__all__ = ["MitigationEngine"]
