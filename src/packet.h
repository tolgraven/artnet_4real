/* Artnet and RDM packet definitions
 */
#pragma once

#include "protocol.h"
#include "components.h"


namespace an4r::artnet {

namespace packet {

using namespace protocol;


#pragma pack(push, 1)

namespace rdm {

union RdmData {
  static const uint16_t rdmStartCode = 0xCC01;
  struct {
    // uint16_t startCode = rdmStartCode;    // Start Code 0xCC01 for RDM - we skip? but still need around to pass onto physical or w/e...
    uint8_t  length;        // defines slot containing Chksum hi byte, range 23-255, "slotcount"
    RdmUid dest, src;
    uint8_t sequenceID;   // transaction number, not checked
    enum Response: uint8_t {
      Ack = 0x00, AckTimer = 0x01, NackReason = 0x02, AckOverflow = 0x03, AckBulkDraft	= 0x03
    } responseType; // ack code / port ID
    uint8_t  msgCount;     // Message count queued at device
    uint16_t subDev;       // sub device number (root = 0)
    enum CmdClass: uint8_t {
      DiscoveryCommand = 0x10, DiscoveryCommandResponse = 0x11,
      GetCommand = 0x20, GetCommandResponse = 0x21,
      SetCommand = 0x30, SetCommandResponse = 0x31
    } cmdClass;

    uint16_t pid;          // parameter ID. there are hundreds to eh just use RDM.h
    uint8_t  dataLength;   // parameter data length "parameterslotcount" in bytes, "also SlotCount+23=ParameterSlotCount" <- guess that means it rolls over? or they wrote wrong
    uint8_t  data[231];    // data field
  } packet{};

  struct {
    uint8_t headerFE, headerAA;
    uint8_t maskedDevID[12];
    uint8_t maskedChecksum[4];
  } discovery;

  uint8_t buffer[255];
  // void endianFlip(void) { // remember to actually fix this for constructor / reading
    // packet.startCode = (packet.startCode << 8) | (packet.startCode >> 8); // 16 bit flips
    // packet.destMan = (packet.destMan << 8) | (packet.destMan >> 8);
    // packet.sourceMan = (packet.sourceMan << 8) | (packet.sourceMan >> 8);
    // packet.subDev = (packet.subDev << 8) | (packet.subDev >> 8);
    // packet.pid = (packet.pid << 8) | (packet.pid >> 8);
    // packet.destDev = __builtin_bswap32 (packet.destDev); 32 bit flips
    // packet.sourceDev = __builtin_bswap32 (packet.sourceDev);
  // }
};
// __builtin_bswap32 < good to have
}

namespace art {

struct Header { // Core Artnet header. Inherited by all other packets.
  Header(OpCode opCode): opCode(opCode) {}
	// const char ID[8] = {protocol::idStr}; // protocol ID = "Art-Net"
	// const char ID[8] = protocol::idStr; // protocol ID = "Art-Net"
	const char ID[8] = {ARTNET_ID_STR}; // protocol ID = "Art-Net"
	// const char ID[8] = {protocol::id}; // protocol ID = "Art-Net"
	OpCode opCode;
};
struct HeaderExt: Header { // Most packets also add the protocol version. maybe call HeaderExt or w/e
  HeaderExt(OpCode opCode): Header(opCode) {}
	const uint16_t protocolVer = protocol::protocolVersion << 8; // hi byte first so just switch the damn def.
};

struct Poll: HeaderExt {
  Poll(): HeaderExt(OpPoll) {}
  struct { // no =, aarf c++20 has defaults ;()
     bool : 1,                       // bit 0 unused
          pollReplyOnlyOnPoll:   1,  // Node sends ArtPollReply when polled / 0 "when it needs to"
          sendMeDiagnostics:     1,  // Send me diagnostics messages
          broadcastDiagnostics:  1,  // (if sendMeDiagnostics) broadcast / unicast messages
          enableVlcTransmission: 1,  // can handle whatever this is
                                :3; // and rest
  } talkToMe{}; // alt is setting all on creation. but find consistancy etc...
	DiagPriority priority = DiagPriority::All; // Set the lowest priority of diagnostics message that node should send. See DpXxx defines above.
};

enum PortProtocol: uint8_t {
  // DMX512 = 0b000000, MIDI = 0b000001, Avab, CMX, ADB, ArtNet // note 0b not 0x
  DMX512 = 0, MIDI, Avab, CMX, ADB, ArtNet // note 0b not 0x
};

struct PollReply: Header { // we can extend packed like dis?
  PollReply(DeviceNetwork& network, NodeName& names,
      DeviceInfo& deviceInfo, Group& group): // TODO pass nodeReport as well...
    Header(OpPollReply),
    ip(uint32_t(network.ip)), netSwitch(group.addr.netSwitch), subSwitch(group.addr.subSwitch),
    names(names), portCount(group.numPorts << 8), //hmm ze shift
    mac(network.mac), bindIp(ip), bindIndex(group.index),
    webConfig(false), dhcpUsed(network.dhcp), dhcpSupported(true), // not necessarily i guess...
    portAddress15Bit(true), // we are v4
    sAcnCapable(false) // not yet
  {}

  std::vector<Universe> activeInputs() {
    std::vector<Universe> ins;
    for(auto p=0; p < protocol::numPorts; p++) {
      // Serial.printf("Port: %u, uni: %u / %u\n", p, swIn[p], swOut[p]);
      // if(goodInput[p].receivingData) // well maybe first check mode or w/e but yeah enough?
      //   ins.emplace_back(swIn[p], subSwitch, netSwitch);
      if(goodOutput[p].sendingData) // keep rereading spec until fucking grasp in/out/whatiswhat
        ins.emplace_back(swOut[p], subSwitch, netSwitch);
    }
    return ins;
  }

  uint32_t  ip          = 0;         // 0 is valid, means not configured
	uint16_t  port				= protocol::defaultUdpPort;   // 6454. lo, hi...
	uint16_t  fwVersion	  = 0;         // uint8_t fwHi = 0, fwLo = 0; //
	uint8_t   netSwitch		= 0;         // Bits 14-8 of the 15 bit universe number are encoded into the bottom 7 bits of this field.
	uint8_t   subSwitch		= 0;         // Bits 7-4 of the 15 bit universe number are encoded into the bottom 4 bits of this field.
	uint16_t  oem				  = protocol::defaultOem; // uint8_t oemHi = 0x00, oemLo = 0xff;
	uint8_t   ubeaVersion	= 0;

  struct Status {
  // struct {
      bool ubea: 1,             // 0 UBEA... something?
           rdmCapable: 1,       // 1 RDM capable (not = unidirectional DMX, RDM = bi-directional. Meaning same port must send and receive same uni?)
           bootFromRom: 1,      // 2  0 Boot flash (normal), 1 Boot ROM (possible error)
                       :1;      // 3 fill
      enum PA: uint8_t {        // 4-5: 00 Universe programming authority
        Unknown = 0b00, FrontPanel = 0b01, Network = 0b10
      } programmingAuthority: 2;
      enum Indicators: uint8_t { // 7-6: Front panel indicators.
        Locate = 0b01, Mute = 0b10, Normal = 0b11
      } indicators: 2;
  } status{false, true, false, Status::PA::Network, Status::Indicators::Normal}; // XXX no defaults, create from passed config!

	uint16_t  estaMan     = protocol::defaultEstaMan; // lo, hi...
  NodeName names;
	char nodeReport[protocol::nodeReportLength] = {0}; // Text feedback of Node status, errors, debug..

  uint16_t portCount     = 0;         // 0-4, whichever biggest of in/out port count
  struct {
    struct {
      // bool : 5, // seems every bit below is protocol
      //       protocolIsMidi: 1;  //  0-5 protocol number (0= DMX, 1=MIDI)
      // enum PortProtocol: uint8_t {
      // enum: uint8_t {
      //   DMX512 = 0x000000, MIDI, Avab, CMX, ADB, ArtNet
      // }
      PortProtocol prot: 6;
      // union {
        // struct {
        //   bool input: 1, output: 1; // or prob gotta wrap struct
        // };
        PortMode mode: 2; // warning isnt true afaict, how silence
      // };
    // } type[protocol::numPorts] = {}; // niet good init
    // } type[protocol::numPorts] = {PortProtocol::DMX512, false, false}; // niet good init
    } type[protocol::numPorts] = {PortProtocol::DMX512, PortMode::PortDMX}; // niet good init

    struct { // NOPE. have to stick to anon struct GoodInput { // might as well keep named since multiple instances = no passthrough anyways
        bool : 2,                   // 0-1 unused
             receiveErrors: 1,      // 2 receive errors
             isDisabled: 1,         // 3 input is disabled,
             textInData: 1,         // 4 data includes text,
             sipsInData: 1,         // 5 data includes SIPs,
             testPacketsInData: 1,  // 6 data includes test packets
             receivingData: 1;      // 7 data active,
    } goodInput[protocol::numPorts] = {};
    struct {
        bool sacn: 1,                 // supposed fill might actually be sACN slot... in some extension?
             mergeLPT: 1,             // 1 DMX output merge mode LTP
             outputShortDetected: 1,  // 2 DMX output short detected on power up,
             isMerging: 1,            // 3 output merging data.,
             textInData: 1,           // 4 data includes text,
             sipsInData: 1,           // 5 data includes SIPs,
             testPacketsInData: 1,    // 6 data includes test packets
             sendingData: 1;          // 7 data active,
    } goodOutput[protocol::numPorts] = {}; // but couldnt have multiple copies of anon struct...
    // fix type for below? used elsewhere.
    uint8_t swIn[protocol::numPorts]       = {0},   // Bits 3-0 of the 15 bit universe number are encoded into the low nibble
            swOut[protocol::numPorts]      = {0};   // This is used in combination with SubSwitch and NetSwitch to produce the full universe address.  THIS IS FOR INPUT/OUTPUT - ART-NET or DMX, NB ON ART-NET II THESE 4 UNIVERSES WILL BE UNICAST TO.
  };

	uint8_t swVideo     = 0;    // Low nibble is the value of the video output channel
	uint8_t swMacro     = 0;    // Bit 0-7 Macro input 1-8
	uint8_t swRemote    = 0;    // Bit 0-7 Macro input 1-8

	uint8_t spare[3]    = {0};	// Spare 1-3, currently zero
  enum Style: uint8_t { // break out make class
    Node = 0, Controller, Media, Route, Backup, Config, Visual
  } style             = Style::Node;	  // Set to Style code to describe type of equipment

  mac_t   mac; 	// Mac Address, zero if info not available
  uint32_t bindIp     = 0;    // Must be same as ip
	uint8_t bindIndex   = 0;	  // order of Artnet v4 4-port "device" in this device / on this IP. 0 and 1 is root device - mirrors our Groups.

  union {
    struct { // 'unnamed struct' aint so nice for errors.  // bit 0 supports web config, 1 DHCP configured, 2 DHCP capable, 3-7 n/a, 0
      bool webConfig: 1,
          dhcpUsed: 1,
          dhcpSupported: 1,
          portAddress15Bit: 1, // 0 = 8 bit port address (Artnet 2), 1 = 15 bit (v3 / v4)
          sAcnCapable: 1,      // Node can switch Artnet/sACN
          squawking: 1,       // ???
                      :2;      //  Not used
    }; // set in initialiser
    uint8_t status2 = 0; // back to before haha. prob good keep name of field after all?
  };
	uint8_t filler[26]  = {0};	        // Filler bytes, currently zero.
};


struct DMX: public HeaderExt {
  DMX(uint8_t seqId, Port* port, uint8_t* payload, uint16_t length):
    HeaderExt(OpDmx), // or OpOutput
    sequenceID(seqId), portId(port->index), subUni(port->addr.subUni),
    net(port->addr.netSwitch), length(htons(length)),
    data(*((dmx_buf_t*)payload)) {}
	uint8_t sequenceID		= 1;
	uint8_t portId	      = 0;  // physical Port ID 0-3 (not really necessary debug/info)
	uint8_t subUni				= 0;  // sub + uni: low 8 bits of 15bit universe
	uint8_t net           = 0;  // high 7 bits of 15bit universe
	uint16_t length       = 0;
  dmx_buf_t data;

  Universe getUniverse() { return Universe(subUni, net); }
  uint16_t dmxDataLen()  { return htons(length); }
};


const uint8_t maxRdmAddressCount = 32;
const int maxRdmDataLength = 278;
// according to the rdm spec, this should be 278 bytes we'll set to 512 here, the firmware datagram is still bigger
// enum { ARTNET_MAX_RDM_DATA = 512 };

// enum rdm_tod_state { RDM_TOD_NOT_READY, RDM_TOD_READY, RDM_TOD_ERROR };
enum class TODState: uint8_t { NOT_READY = 0, READY, ERROR };

struct TODData: HeaderExt  {
  static const uint16_t maxUidCount = 200;
  static const uint8_t rdmUidWidth = 6;  //typ, 48 bits

  TODData(Port* port, uint8_t state, uint16_t uidTotal):
    HeaderExt(OpTodData),
    port(port->index + 1), bindIndex(port->group->index + 1), netSwitch(port->addr.netSwitch),
    cmdRes((state == (uint8_t)TODState::READY)? TodFull: TodNak), //,  // 0x00 TOD full, 0xFF  TOD not avail or incomplete)
    address(port->addr.subUni), uidTotal(htons(uidTotal)) {}
  uint8_t  rdmVer     = protocol::rdmVersion;    // RDM version - RDM STANDARD V1.0
  uint8_t  port; //physical?
  uint8_t  spare[6]   = {0};
  uint8_t  bindIndex;
  uint8_t  netSwitch;
  enum CommandResponse: uint8_t {
    TodFull = 0x00, TodNak = 0xFF // Full Discovery / ToD not available.
  } cmdRes;
  uint8_t  address;
  uint16_t uidTotal;
  uint8_t  blockCount;
  uint8_t  uidCount;
  std::array<RdmUid, maxUidCount> device; // uint8_t  tod[maxUidCount][rdmUidWidth] = {};
  size_t getLength() { return protocol::todDataSize + (rdmUidWidth * uidTotal); } // bc might be shorter than sizeof
};

struct TODRequest: HeaderExt  {
  TODRequest(): HeaderExt(OpTodRequest) {}
  uint8_t  filler[2] = {0};
  uint8_t  spare[7]  = {0};
  uint8_t  net;     // hi 7 bits port address
  uint8_t  command; // always 0
  uint8_t  adCount; // max maxRdmAddressCount = 32
  std::array<uint8_t, maxRdmAddressCount> address; // low byte of port address
};
struct TODControl: HeaderExt  {
  TODControl(): HeaderExt(OpTodControl) {} // only minor diff request and control
  uint8_t  filler[2] = {0};
  uint8_t  spare[7]  = {0};
  uint8_t  net;
  enum: uint8_t {
    None = 0, Flush
  } command;
  uint8_t  address;
};


struct RDM: HeaderExt {
  RDM(rdm::RdmData* c, Port* port):
    HeaderExt(OpRdm),
    netSwitch(port->addr.netSwitch), address(port->addr.subUni),
    rdmData(*c) {
      // memcpy(data, c->buffer + 1, c->packet.length + 1); // Copy everything except the 0xCC start code
    }
  uint8_t   rdmVer     = protocol::rdmVersion;    // RDM version - RDM STANDARD V1.0
  uint8_t   filler2    = 0;
  uint8_t   spare[7]   = {0};
  uint8_t   netSwitch;
  uint8_t   cmd        = 0x00;    // Command - 0x00 = Process RDM
  uint8_t   address;
  rdm::RdmData   rdmData; //"excluding the DMX startcode" - so both CC rdm and 01 dmx niet?
};

struct RDMSub: HeaderExt { // u16 big-endian

};

struct DiagData: HeaderExt {
  DiagData(DiagPriority priority, uint16_t length, uint8_t* diagData):
    HeaderExt(OpDiagData),
    // priority(priority), buffer(diagData, length) {
    priority(priority), length(htons(length)) {
      memcpy(data, diagData, length);
  }
	uint8_t filler1;
  DiagPriority priority;
	uint8_t filler2, filler3;
	uint16_t length;             // BYTE-SWAPPED MANUALLY. Length of array below
	uint8_t data[protocol::dmxBufferSize]; // Variable size array which is defined as maximum here.
};

////////////////////////////////////////////////
//  Transfer diagnostic data from node to server
struct Command: HeaderExt {
  Command(uint16_t estaMan = protocol::defaultEstaMan):
    HeaderExt(OpCommand), estaMan(estaMan) {}
	uint16_t estaMan;           // ESTA manufacturer id, hi byte
	uint16_t length;             // BYTE-SWAPPED MANUALLY. Length of array below. Range 0 - 512
	char data[protocol::dmxBufferSize]; // Variable size array which is defined as maximum here. Contains null terminated command text.
};

//////////////////////////////////////////
// Transfer settings from server to node.  So we'll mostly parse this.
struct Address: HeaderExt {
  Address(): HeaderExt(OpAddress) {}
  // template<int N>
  // struct UniverseEncodeBits {
  //   union {
  //     struct { uint8_t dataBits: N; } data;
  //     struct { uint8_t :7; bool program: 1;  } cmd;
  //   } uniEnc; // tricky cause they're different layout. template trick can't work cause need specific at bit 7...
  // };
  // UniverseEncodeBits<7> netSwitch;

  // union {
  //   struct {
  //     uint8_t netSwitch: 7;
  //     bool program: 1;
  //   };
  //   SwitchCmd cmd;
  // };

  // template<uint8_t param, int bits, int _N = (8 - bits - 1)> // max 8 together
  // union Cfg {
  //   Cfg(uint8_t newVal): param(newVal), program(true) {}
  //   Cfg(bool reset = true): cmd(Switch::Reset) {}
  //   struct {
  //     uint8_t :_N, param: bits; // or tbh if only pre then will just fill til bool?  prob not
  //     bool program: 1;
  //   };
  //   enum Switch: uint8_t {
  //     Reset = 0x00, NoChange = 0x7f //weird thing
  //   } cmd = Switch::NoChange;
  // };
  // Cfg<netSwitch, 7>;
  // Cfg<swIn, 4>;
  // Cfg<swOut, 4>;
  // Cfg<subSwitch, 4>;
  // template<int bits, int _N = (8 - bits - 1)> // max 8 together
  // union Cfg {
  //   Cfg(uint8_t newVal): param(newVal), program(true) {}
  //   Cfg(bool reset = true): cmd(Switch::Reset) {}
  //   struct {
  //     uint8_t :_N, param: bits; // or tbh if only pre then will just fill til bool?  prob not
  //     bool program: 1;
  //   };
  //   enum: uint8_t {
  //     Reset = 0x00, NoChange = 0x7F //weird thing
  //   } cmd = ::NoChange;
  // };
  // Cfg<7> netSwitch;
  // Cfg<4> swIn;
  // Cfg<4> swOut;
  // Cfg<4> subSwitch;

	uint8_t netSwitch; // Bits 14-8 of the 15 bit universe number are encoded into the bottom 7 bits of this field.
	// This is used in combination with SubSwitch and SwIn[] or SwOut[] to produce the full universe address.
	// This value is ignored unless bit 7 is high. i.e. to program a  value 0x07, send the value as 0x87.
	// Send 0x00 to reset this value to the physical switch setting.  Use value 0x7f for no change. How wouldnt that be an actual val?
	uint8_t bindIndex; // This number represents the order of bound devices. A lower number means closer to root device.  BindIndex == 1 = Root Device Receivers should treat 0 and 1 as identical = Root device

  NodeName names{};

	uint8_t swIn[protocol::numPorts]; // Bits 3-0 of the 15 bit universe number for a given input port are encoded into the bottom 4 bits of this field.
	// This is used in combination with NetSwitch and SubSwitch to produce the full universe address.
	// This value is ignored unless bit 7 is high. i.e. to program a  value 0x07, send the value as 0x87.
	// Send 0x00 to reset this value to the physical switch setting.
	// Use value 0x7f for no change.  Array size is fixed
	uint8_t swOut[protocol::numPorts]; // Bits 3-0 of the 15 bit universe number for a given output port are encoded into the bottom 4 bits of this field.
	// This is used in combination with NetSwitch and SubSwitch to produce the full universe address.
	// This value is ignored unless bit 7 is high. i.e. to program a  value 0x07, send the value as 0x87.
	// Send 0x00 to reset this value to the physical switch setting.
	// Use value 0x7f for no change.  Array size is fixed
	uint8_t subSwitch; // Bits 7-4 of the 15 bit universe number are encoded into the bottom 4 bits of this field.
	// This is used in combination with NetSwitch and SwIn[] or SwOut[] to produce the full universe address.
	// This value is ignored unless bit 7 is high. i.e. to program a  value 0x07, send the value as 0x87.
	// Send 0x00 to reset this value to the physical switch setting.  Use value 0x7f for no change.
	uint8_t swVideo; // Low nibble is the value of the video output channel Bit 7 hi = use data
  // AcCommand command;
  Ac command;
};

/////////////////////////////////////////////////
// Transmitted by Server to set or test the Node's custom IP settings.
// NB. This function is provided for specialist applications. Do not implement this functionality unless really needed!!!
struct IpProg: HeaderExt {
  IpProg(): HeaderExt(OpIpProg) {}
	uint8_t filler1;   // TalkToMe position in Poll
	uint8_t filler2;   // The physical i/p 0-3. so why filler For Debug only

  // struct Command {
  union {
  struct { // aarf c++20 has defaults ;()
    bool setCustomPortNr: 1,      	// Bit 0 Use custom Port number in this packet.
         setCustomSubnetMask: 1,   	// Bit 1 Use custom Subnet Mask in this packet.
         setCustomIP: 1,           	// Bit 2 Use custom IP in this packet.
         restoreToDefault: 1,      	// Bit 3 Return all three parameters to default. (This bit takes priority).
                              :2,   // Bit 5-4 not used
         enableDHCP: 1,	            // Bit 6 enable DHCP (overrides all lower bits)
         programming: 1;	          // Bit 7 must be 1 for any programming.
  };   // Bit fields as follows: (Set to zero to poll for IP info)
  bool falseMeansPollIP;
  };
	uint8_t filler4;  // Fill to word boundary.

  uint32_t ip,        // uint8_t ProgIpHi; // Use this IP if Command.Bit2 uint8_t ProgIp2; uint8_t ProgIp1; uint8_t ProgIpLo;
           subMask;   // Use this Subnet Mask if Command.Bit1. hi->lo
	uint16_t port;      // Use this Port Number if Command.Bit0

	uint8_t spare[8]{0}; // Set to zero, do not test in receiver.
};
/////////////////////////////////////////////////
// Transmitted by Node in response to IpProg.
struct IpProgReply: HeaderExt {
  IpProgReply(DeviceNetwork& network):
    HeaderExt(OpIpProgReply),
    ip(network.ip), subMask(network.subnet), dhcpEnabled(network.dhcp) // garbage around?
     {}
  // IpProgReply(IPAddress ip, IPAddress subnet, uint16_t port = protocol::defaultUdpPort):
  //   ip(ip), subMask(subnet), port(htons(port)), dhcpEnabled(true) {} // really swap??
	uint8_t filler[4]{0}; // Fill to word boundary.

  uint32_t ip; // The node's current IP Address
  uint32_t subMask; // current subnet
	uint16_t port = protocol::defaultUdpPort; // hi lo, current port. I'm guessing to use non-6454?

  struct {
    bool :6,
         dhcpEnabled: 1,
         :1;
  };
	uint8_t spare[7]{0}; // Set to zero, do not test in receiver.
};

struct Sync: HeaderExt {
  Sync(): HeaderExt(OpSync) {}
	uint8_t   aux[2]{0}; // not used, transmit as zero
};

#pragma pack(pop)
} // END NAMESPACE ART
} // END NAMESPACE PACKET

} // END NAMESPACE
