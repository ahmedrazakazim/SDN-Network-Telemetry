"""Flow Manager for OpenFlow 1.3.

Provides high-level helpers to program OpenFlow 1.3 flow tables:
- Installing table-miss rule (priority=0 to controller)
- Installing L2/L3 forwarding rules
- Installing high-priority drop rules for attack mitigation
- Deleting flow entries
- Enforcing OpenFlow 1.3 match prerequisites (eth_type=0x0800 for IPv4 matches)
"""

import logging

logger = logging.getLogger(__name__)

# Try importing os_ken or ryu; provide fallback OpenFlow 1.3 mocks for unit testing
try:
    import os_ken
    from os_ken.ofproto import ofproto_v1_3
    from os_ken.ofproto import ofproto_v1_3_parser as ofproto_parser
    OF_BACKEND = "os_ken"
except ImportError:
    try:
        import ryu
        from ryu.ofproto import ofproto_v1_3
        from ryu.ofproto import ofproto_v1_3_parser as ofproto_parser
        OF_BACKEND = "ryu"
    except ImportError:
        OF_BACKEND = "mock"

        class MockOFProto:
            OFP_VERSION = 4
            OFPFC_ADD = 0
            OFPFC_MODIFY = 1
            OFPFC_MODIFY_STRICT = 2
            OFPFC_DELETE = 3
            OFPFC_DELETE_STRICT = 4
            OFPP_CONTROLLER = 0xfffffffd
            OFPP_FLOOD = 0xfffffffb
            OFPP_ANY = 0xffffffff
            OFPG_ANY = 0xffffffff
            OFPCML_NO_BUFFER = 0xffff
            OFPIT_APPLY_ACTIONS = 4
            OFP_NO_BUFFER = 0xffffffff

        class MockOFPMatch:
            def __init__(self, **kwargs):
                self._fields = dict(kwargs)

            def get(self, key, default=None):
                return self._fields.get(key, default)

            def __getitem__(self, item):
                return self._fields[item]

            def __contains__(self, item):
                return item in self._fields

            def to_dict(self):
                return dict(self._fields)

            def __repr__(self):
                return f"OFPMatch({self._fields})"

            def __eq__(self, other):
                if isinstance(other, MockOFPMatch):
                    return self._fields == other._fields
                return False

        class MockOFPActionOutput:
            def __init__(self, port, max_len=None):
                self.port = port
                self.max_len = max_len

            def __repr__(self):
                return f"OFPActionOutput(port={self.port})"

        class MockOFPInstructionActions:
            def __init__(self, type_, actions):
                self.type = type_
                self.actions = actions

            def __repr__(self):
                return f"OFPInstructionActions(type={self.type}, actions={self.actions})"

        class MockOFPFlowMod:
            def __init__(self, datapath=None, cookie=0, cookie_mask=0, table_id=0,
                         command=0, idle_timeout=0, hard_timeout=0, priority=0,
                         buffer_id=0xffffffff, out_port=0, out_group=0, flags=0,
                         match=None, instructions=None):
                self.datapath = datapath
                self.cookie = cookie
                self.cookie_mask = cookie_mask
                self.table_id = table_id
                self.command = command
                self.idle_timeout = idle_timeout
                self.hard_timeout = hard_timeout
                self.priority = priority
                self.buffer_id = buffer_id
                self.out_port = out_port
                self.out_group = out_group
                self.flags = flags
                self.match = match
                self.instructions = instructions or []

            def __repr__(self):
                return (f"OFPFlowMod(priority={self.priority}, match={self.match}, "
                        f"instructions={self.instructions}, command={self.command})")

        class MockOFPPacketOut:
            def __init__(self, datapath=None, buffer_id=0xffffffff, in_port=0, actions=None, data=None):
                self.datapath = datapath
                self.buffer_id = buffer_id
                self.in_port = in_port
                self.actions = actions or []
                self.data = data

            def __repr__(self):
                return f"OFPPacketOut(in_port={self.in_port}, actions={self.actions})"

        class MockParser:
            OFPMatch = MockOFPMatch
            OFPActionOutput = MockOFPActionOutput
            OFPInstructionActions = MockOFPInstructionActions
            OFPFlowMod = MockOFPFlowMod
            OFPPacketOut = MockOFPPacketOut

        ofproto_v1_3 = MockOFProto()
        ofproto_parser = MockParser()


class FlowManager:
    """Helper class for managing OpenFlow 1.3 flow table operations."""

    ETH_TYPE_IPV4 = 0x0800
    ETH_TYPE_ARP = 0x0806

    def __init__(self):
        self.ofproto = ofproto_v1_3
        self.parser = ofproto_parser

    def enforce_ipv4_prerequisite(self, match_kwargs: dict) -> dict:
        """Enforce OpenFlow 1.3 prerequisite: eth_type=0x0800 for IPv4 field matches.

        In OpenFlow 1.3, matching ipv4_src, ipv4_dst, or ip_proto without
        eth_type=0x0800 causes an OFPBAC_BAD_PREREQ error on the switch.
        """
        ipv4_fields = ("ipv4_src", "ipv4_dst", "ip_proto", "tcp_src", "tcp_dst", "udp_src", "udp_dst")
        if any(f in match_kwargs for f in ipv4_fields):
            if "eth_type" not in match_kwargs:
                match_kwargs["eth_type"] = self.ETH_TYPE_IPV4
        return match_kwargs

    def create_match(self, datapath, **kwargs):
        """Construct an OFPMatch ensuring OpenFlow 1.3 prerequisites are satisfied."""
        kwargs = self.enforce_ipv4_prerequisite(dict(kwargs))
        parser = getattr(datapath, "ofproto_parser", self.parser)
        return parser.OFPMatch(**kwargs)

    def add_flow(self, datapath, priority: int, match, actions: list,
                 buffer_id=None, idle_timeout: int = 0, hard_timeout: int = 0,
                 cookie: int = 0, table_id: int = 0):
        """Add a flow entry to the datapath switch.

        Args:
            datapath: OpenFlow switch datapath object.
            priority (int): Rule priority.
            match: OFPMatch object.
            actions (list): List of OpenFlow action objects.
            buffer_id (int, optional): Packet buffer ID from PacketIn.
            idle_timeout (int): Idle expiration timeout in seconds.
            hard_timeout (int): Hard expiration timeout in seconds.
            cookie (int): Flow identifier cookie.
            table_id (int): Target flow table ID (default: 0).
        """
        ofproto = getattr(datapath, "ofproto", self.ofproto)
        parser = getattr(datapath, "ofproto_parser", self.parser)

        # In OpenFlow 1.3, actions must be wrapped in instructions
        if actions:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        else:
            # Empty instructions specify a DROP action in OpenFlow 1.3
            inst = []

        kwargs = {
            "datapath": datapath,
            "priority": priority,
            "match": match,
            "instructions": inst,
            "idle_timeout": idle_timeout,
            "hard_timeout": hard_timeout,
            "cookie": cookie,
            "table_id": table_id,
            "command": ofproto.OFPFC_ADD
        }

        if buffer_id is not None:
            kwargs["buffer_id"] = buffer_id

        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)
        return mod

    def install_table_miss(self, datapath, table_id: int = 0):
        """Install table-miss entry (priority=0) to send unmatched packets to controller.

        Args:
            datapath: OpenFlow switch datapath object.
            table_id (int): Flow table ID (default: 0).
        """
        ofproto = getattr(datapath, "ofproto", self.ofproto)
        parser = getattr(datapath, "ofproto_parser", self.parser)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        logger.info(f"Installing table-miss entry on datapath {getattr(datapath, 'id', 'unknown')}")
        return self.add_flow(datapath, priority=0, match=match, actions=actions, table_id=table_id)

    def install_forwarding_rule(self, datapath, priority: int, match, actions: list,
                                buffer_id=None, idle_timeout: int = 60, hard_timeout: int = 0):
        """Install an L2/L3 forwarding rule."""
        return self.add_flow(
            datapath=datapath,
            priority=priority,
            match=match,
            actions=actions,
            buffer_id=buffer_id,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )

    def install_drop_rule(self, datapath, priority: int = 1000, match=None,
                          ipv4_src: str = None, idle_timeout: int = 0,
                          hard_timeout: int = 300, table_id: int = 0):
        """Install high-priority drop rule matching offending source IPv4 address.

        CRITICAL OpenFlow 1.3 requirement:
        Must include eth_type=0x0800 when matching ipv4_src to avoid OFPBAC_BAD_PREREQ.

        Args:
            datapath: Switch datapath.
            priority (int): Drop rule priority (default: 1000).
            match (OFPMatch, optional): Preconstructed match object.
            ipv4_src (str, optional): Source IPv4 to drop.
            idle_timeout (int): Idle timeout.
            hard_timeout (int): Hard timeout in seconds (default: 300).
            table_id (int): Flow table ID.
        """
        parser = getattr(datapath, "ofproto_parser", self.parser)

        if match is None:
            if ipv4_src is None:
                raise ValueError("Either match or ipv4_src must be provided to install_drop_rule.")
            match = parser.OFPMatch(eth_type=self.ETH_TYPE_IPV4, ipv4_src=ipv4_src)

        logger.warning(
            f"Installing DROP rule on switch {getattr(datapath, 'id', 'unknown')} "
            f"for match {match} (priority={priority}, timeout={hard_timeout}s)"
        )
        return self.add_flow(
            datapath=datapath,
            priority=priority,
            match=match,
            actions=[],  # Empty actions = DROP in OpenFlow 1.3
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            table_id=table_id
        )

    def delete_flow(self, datapath, match=None, priority: int = None,
                    out_port: int = None, out_group: int = None,
                    table_id: int = None, strict: bool = False):
        """Delete matching flow entries from the datapath switch."""
        ofproto = getattr(datapath, "ofproto", self.ofproto)
        parser = getattr(datapath, "ofproto_parser", self.parser)

        cmd = ofproto.OFPFC_DELETE_STRICT if strict else ofproto.OFPFC_DELETE

        kwargs = {
            "datapath": datapath,
            "command": cmd,
            "out_port": out_port if out_port is not None else ofproto.OFPP_ANY,
            "out_group": out_group if out_group is not None else ofproto.OFPG_ANY,
        }

        if table_id is not None:
            kwargs["table_id"] = table_id
        else:
            kwargs["table_id"] = ofproto.OFPP_ANY

        if priority is not None:
            kwargs["priority"] = priority

        if match is not None:
            kwargs["match"] = match
        else:
            kwargs["match"] = parser.OFPMatch()

        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)
        return mod

    def remove_drop_rule(self, datapath, ipv4_src: str, priority: int = 1000):
        """Remove previously installed drop rule for an offending source IP."""
        parser = getattr(datapath, "ofproto_parser", self.parser)
        match = parser.OFPMatch(eth_type=self.ETH_TYPE_IPV4, ipv4_src=ipv4_src)
        logger.info(
            f"Removing DROP rule on switch {getattr(datapath, 'id', 'unknown')} "
            f"for ipv4_src={ipv4_src} (priority={priority})"
        )
        return self.delete_flow(datapath, match=match, priority=priority, strict=True)
