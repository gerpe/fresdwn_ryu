from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0, ofproto_v1_3 as ofp
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.ofproto import ofproto_v1_3_parser as ofp_parser
from ryu.ofproto import ofproto_common as of_common
from ryu.ofproto.ofproto_v1_0 import NXM_OF_ETH_TYPE
from ryu.topology import event, switches
from ryu.ofproto import oxm_fields as oxm
import time

class SimpleSwitch12(app_manager.RyuApp):
    OFP_VERSIONS = [ofp.OFP_VERSION, ofproto_v1_0.OFP_VERSION]

    _CONTEXTS = {
        'switches': switches.Switches
                 }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch12, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.__sent_packets = []

    def add_flow(self, datapath, port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(in_port=port,
                                                 eth_dst=dst)
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(event.EventLinkRequest, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _request_handler(self, ev):
        pass

    @set_ev_cls(event.EventSwitchEnter, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _connectionUp_handler(self, ev):
        pass

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_cange(self, ev):
        dp = ev.datapath
        print("OFPStateChange {ip}:{port}".format(ip=ev.datapath.address[0],
                                                  port=ev.datapath.address[1]))
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        # out = ofp_parser.OFPPacketOut(datapath=dp, in_port=1, actions=actions)

        #for i in range(0, 65535):
        #    out = ofp_parser.OFPExperimenter(datapath=dp,
        out = ofp_parser.OFPExperimenter(datapath=dp,
                                                     #flags=0,
                                                     # experimenter=of_common.NX_EXPERIMENTER_ID,
                                                     #experimenter=0x4f4e4600,
                                                     experimenter=0x00000005,
                                                   #  experimenter=0x002320,
                                                     #experimenter=0xff000005,
                                                     #experimenter=999,
                                                     #exp_type=0xffff,
                                                     exp_type=1,
                                                     #exp_type=65535,
                                                     #exp_type=i,
                                                     data=bytearray())
        dp.send_msg(out)
        time.sleep(.3)
        self.__sent_packets.append(out)
       #     dp.send_msg(out)
       #     time.sleep(.3)
       #     self.__sent_packets.append(out)

    @set_ev_cls(ofp_event.EventOFPHello, [MAIN_DISPATCHER, CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER])
    def _hello_handler(self, ev):
        pass
        # print("OFPHello {ip}:{port}".format(ip=ev.datapath.address[0],
        #                                           port=ev.datapath.address[1]))

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [MAIN_DISPATCHER, CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER])
    def _error_message_handler(self, ev):
        pass
    #
    # @set_ev_cls(ofp_event.EventOFPEchoRequest, [MAIN_DISPATCHER, CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER])
    # def _echo_request_handler(self, ev):
    #     pass

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, in_port, dst, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

