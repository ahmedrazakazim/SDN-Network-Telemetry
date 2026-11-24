"""SDN Tree Topology Module.

Provides Mininet Tree Topology (depth=2, fanout=2) connecting to an
OpenFlow 1.3 remote controller.
"""

from topo.sdn_tree_topo import SDNTreeTopo, create_network

__all__ = ["SDNTreeTopo", "create_network"]
