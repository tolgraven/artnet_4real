/* Artnet and RDM packet definitions
 */
#pragma once

#include "platform.h"
#include "protocol.h"
#include "components.h"


namespace anfr {

namespace packet {

using namespace def;

// WANT:
// - clean ctors alt for all packets
// - apart from ctor prefer ext helpers for packets?
//     ...certainly for stuff that can be templatized.


#pragma pack(push, 1)

namespace rdm {

#define COUNT_DEVICE_MODEL_DESCRIPTION 		32
#define COUNT_MANUFACTURER_LABEL 			32
#define COUNT_DEVICE_LABEL 					32
#define COUNT_SOFTWARE_LABEL 				32
#define COUNT_PERSONALITY_DESCRIPTION 		32
#define COUNT_PERSONALITY_LONG_DESCRIPTION 	64
#define COUNT_SELF_TEST_DESCRIPTION 		32
#define COUNT_SLOT_DESCRIPTION 				8
#define COUNT_SENSOR_DESCRIPTION 			32
#define COUNT_RDM_MAX_FILE_BLOCK			216
#define COUNT_PRESET_TRANSFER				64

enum class Cmd: uint8_t {
  ResponseOffset = 0x01,
  Discovery = 0x10, DiscoveryResponse = 0x11,
  Get = 0x20, GetResponse = 0x21,
  Set = 0x30, SetResponse = 0x31
};
enum CmdClass: uint8_t {
  ResponseOffset = 0x01,
  DiscoveryCommand = 0x10, DiscoveryCommandResponse = 0x11,
  GetCommand = 0x20, GetCommandResponse = 0x21,
  SetCommand = 0x30, SetCommandResponse = 0x31
};

enum class PID: uint16_t {
DISCOVERY_UNIQUE_BRANCH = 0x0001, DISCOVERY_MUTE, DISCOVERY_UN_MUTE,
PROXIED_DEVICES = 0x0010, PROXIED_DEVICE_COUNT, COMMS_STATUS	= 0x0015,
GET_POLL = 0x0020,  // Queued messages
STATUS_MESSAGES = 0x0030, STATUS_ID_DESCRIPTION, CLEAR_STATUS_ID, SUB_DEVICE_STATUS_REPORT_THRESHOLD,

SupportedParameters = 0x0050, PARAMETER_DESCRIPTION,

DeviceInfo = 0x0060, PRODUCT_DETAIL_ID_LIST = 0x0070,
DeviceModelDesc = 0x0080, ManufacturerLabel, DeviceLabel,

FACTORY_DEFAULTS = 0x0090,

LANGUAGE_CAPABILITIES = 0x00a0, LANGUAGE = 0x00b0,
SOFTWARE_VERSION_LABEL = 0x00c0, BOOT_SOFTWARE_VERSION_ID, BOOT_SOFTWARE_VERSION_LABEL,

DMX_PERSONALITY = 0x00e0, DMX_PERSONALITY_DESCRIPTION,
DMX_START_ADDRESS = 0x00f0,

SLOT_ID = 0x0120, SLOT_DESCRIPTION, SLOT_DEFAULT_VALUE,

SENSOR_DEFINITION = 0x0200, SENSOR, SENSOR_RECORD_ALL,
DIMMER_TYPE = 0x0301, DIMMER_CURVE_CLASS,  //These are draft pids awaiting resolution of RDM standard V1.1
DEVICE_HOURS = 0x0400, LAMP_HOURS, LAMP_STRIKES, LAMP_STATE, LAMP_ON_MODE,

DISPLAY_INVERT = 0x0500, DISPLAY_LEVEL,
PAN_INVERT = 0x0600, TILT_INVERT, PAN_TILT_SWAP,

IDENTIFY_DEVICE = 0x1000, RESET_DEVICE,
PERFORM_SELFTEST = 0x1020, SELF_TEST_DESCRIPTION,
CAPTURE_PRESET = 0x1030, PRESET_PLAYBACK,

BULK_DATA_REQUEST = 0x2060, BULK_DATA_OFFER = 0x2070, BULK_DATA_QUERY = 0x2080,

UNSUPPORTED_ID = 0x7fff
};

// Licence published PID's
// ART_PROGRAM_UID				0x8000
// ART_LS_SPECIAL				0x8001	//used by Light-Switch for product sync
// ART_SC_SPECIAL				0x8002	//used by Sign-Control & Light-Switch for product sync (V3.08 firmware onwards)
// ART_DATA_LOSS_MODE			0x8003	//used by Artistic products to define action on loss of data.
// ART_FORCE_ROM_BOOT			0x8004	//used by Artistic products to force rom boot / factory restart
// ART_PRESET_TRANSFER			0x8005	//used by Artistic products to transfer preset data
// // Get and Set Response packets have a 2 byte payload (Preset number (1-x), page (0-7) )
// // Set and Get Response packets have a 66 byte payload (Preset number (1-x), page (0-7), array of values[64])
// // Data is moved in 64 byte chunks so multiple calls needed if footprint>64.
//
union RdmData {
  static const uint16_t rdmStartCode = 0xCC01;
  struct {
    // uint16_t startCode = rdmStartCode;    // Start Code 0xCC01 for RDM - we skip? but still need around to pass onto physical or w/e...
    uint8_t  length;        // defines slot containing Chksum hi byte, range 23-255, "slotcount"
    RdmUid dest, src;
    uint8_t transactionNumber;   // transaction number, not checked
    enum Response: uint8_t { // dunno bout this. Wireshark has Port ID here?
      Ack = 0x00, AckTimer = 0x01, NackReason = 0x02, AckOverflow = 0x03, AckBulkDraft	= 0x03
    } responseType; // ack code / port ID
    uint8_t  msgCount;     // Message count queued at device
    uint16_t subDev;       // sub device number (root = 0)

    CmdClass cmdClass;
    // uint16_t pid;          // parameter ID. there are hundreds to eh just use RDM.h
    PID  pid;          // parameter ID - type of request. there are loads.
    uint8_t  dataLength;   // parameter data length "parameterslotcount" in bytes, "also SlotCount+23=ParameterSlotCount" <- guess that means it rolls over? or they wrote wrong
    uint8_t  data[231];    // data field
    // then checksum at end??
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
	// const char ID[8] = {def::idStr}; // protocol ID = "Art-Net"
	// const char ID[8] = def::idStr; // protocol ID = "Art-Net"
	const char ID[8] = {ARTNET_ID_STR}; // protocol ID = "Art-Net"
	// const char ID[8] = {def::id}; // protocol ID = "Art-Net"
	OpCode opCode;
};
struct HeaderExt: Header { // Most packets also add the protocol version. maybe call HeaderExt or w/e
  HeaderExt(OpCode opCode): Header(opCode) {}
	const uint16_t protocolVer = def::protocolVersion << 8; // hi byte first so just switch the damn def.
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
  DMX512 = 0, MIDI, Avab, CMX, ADB, ArtNet
};

struct PollReply: Header { // we can extend packed like dis?
  PollReply(DeviceNetwork& network, NodeName& names,
      DeviceInfo& deviceInfo, Group& group): // TODO pass nodeReport as well...
    Header(OpPollReply),
    ip(uint32_t(network.ip)), netSwitch(group.addr.netSwitch), subSwitch(group.addr.subSwitch),
    // names(names), portCount(group.numPorts << 8), //hmm ze shift
    names(names), portCount(group.ports.size() << 8), //hmm ze shift
    mac(network.mac), bindIp(ip), bindIndex(group.index),
    webConfig(false), dhcpUsed(network.dhcp), dhcpSupported(true), // not necessarily i guess...
    portAddress15Bit(true), // we are v4
    sAcnCapable(false) // not yet
  {}

  std::vector<Universe> activeInputs() {
    std::vector<Universe> ins;
    for(auto p=0; p < def::numPorts; p++) {
      // if(goodInput[p].receivingData) // well maybe first check mode or w/e but yeah enough?
      //   ins.emplace_back(swIn[p], subSwitch, netSwitch);
      if(goodOutput[p].sendingData) // keep rereading spec until fucking grasp in/out/whatiswhat
        ins.emplace_back(swOut[p], subSwitch, netSwitch);
    }
    return ins;
  }

  uint32_t  ip          = 0;         // 0 is valid, means not configured
	uint16_t  port				= def::defaultUdpPort;   // 6454. lo, hi...
	uint16_t  fwVersion	  = 0;         // uint8_t fwHi = 0, fwLo = 0; //
	uint8_t   netSwitch		= 0;         // Bits 14-8 of the 15 bit universe number are encoded into the bottom 7 bits of this field.
	uint8_t   subSwitch		= 0;         // Bits 7-4 of the 15 bit universe number are encoded into the bottom 4 bits of this field.
	uint16_t  oem				  = def::defaultOem; // uint8_t oemHi = 0x00, oemLo = 0xff;
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

	uint16_t  estaMan     = def::defaultEstaMan; // lo, hi...
  NodeName names;
	char nodeReport[def::nodeReportLength] = {0}; // Text feedback of Node status, errors, debug..

  uint16_t portCount     = 0;         // 0-4, whichever biggest of in/out port count
  struct {
    struct {
      // enum PortProtocol: uint8_t {
      // enum: uint8_t { DMX512 = 0x000000, MIDI, Avab, CMX, ADB, ArtNet }
      PortProtocol prot: 6;
      // union {
        // struct { bool input: 1, output: 1; }; // or prob gotta wrap struct
      PortMode mode: 2; // warning isnt true afaict, how silence
      // };
    // } type[def::numPorts] = {}; // niet good init
    // } type[def::numPorts] = {PortProtocol::DMX512, false, false}; // niet good init
    } type[def::numPorts] = {PortProtocol::DMX512, PortMode::PortDMX}; // niet good init

    struct { // NOPE. have to stick to anon struct GoodInput { // might as well keep named since multiple instances = no passthrough anyways
        bool : 2,                   // 0-1 unused
             receiveErrors: 1,      // 2 receive errors
             isDisabled: 1,         // 3 input is disabled,
             textInData: 1,         // 4 data includes text,
             sipsInData: 1,         // 5 data includes SIPs,
             testPacketsInData: 1,  // 6 data includes test packets
             receivingData: 1;      // 7 data active,
    } goodInput[def::numPorts] = {};
    struct {
        bool sacn: 1,                 // supposed fill might actually be sACN slot... in some extension?
             mergeLPT: 1,             // 1 DMX output merge mode LTP
             outputShortDetected: 1,  // 2 DMX output short detected on power up,
             isMerging: 1,            // 3 output merging data.,
             textInData: 1,           // 4 data includes text,
             sipsInData: 1,           // 5 data includes SIPs,
             testPacketsInData: 1,    // 6 data includes test packets
             sendingData: 1;          // 7 data active,
    } goodOutput[def::numPorts] = {}; // but couldnt have multiple copies of anon struct...
    // fix type for below? used elsewhere.
    uint8_t swIn[def::numPorts]       = {0},   // Bits 3-0 of the 15 bit universe number are encoded into the low nibble
            swOut[def::numPorts]      = {0};   // This is used in combination with SubSwitch and NetSwitch to produce the full universe address.  THIS IS FOR INPUT/OUTPUT - ART-NET or DMX, NB ON ART-NET II THESE 4 UNIVERSES WILL BE UNICAST TO.
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
    sequenceID(seqId), portId(port->index + 1), subUni(port->addr.subUni),
    net(port->addr.netSwitch), length(htons(length)),
    data(*((dmx_buf_t*)payload)) {}
	uint8_t sequenceID		= 1;
	uint8_t portId	      = 0;  // physical Port ID 1-4 (not really necessary debug/info)
	uint8_t subUni				= 0;  // sub + uni: low 8 bits of 15bit universe
	uint8_t net           = 0;  // high 7 bits of 15bit universe
	uint16_t length       = 0;
  dmx_buf_t data;

  static const uint8_t headerLength = 18;
  Universe getUniverse() { return Universe(subUni, net); }
  uint16_t dmxDataLen()  { return htons(length); }
};


const int maxRdmDataLength = 278;

enum class TODState: uint8_t { NOT_READY = 0, READY, ERROR };

struct TODData: HeaderExt  {
  inline static const uint16_t maxUidCount = 200;

  TODData(Port* port, uint16_t uidTotal, uint8_t blockCount = 0):
    HeaderExt(OpTodData),
    port(port->index + 1), bindIndex(port->group->index + 1), netSwitch(port->addr.netSwitch),
    cmdRes((uidTotal == 0) || (blockCount > 0)?  TodNak:  // Nak both means n/a and "incomplete subsection, so makes sense"
                                                 TodFull), // packet contains a full flush, or is starting one
    // address(port->addr.subUni), uidTotal(htons(uidTotal)) //,
    address(port->addr.subUni), uidTotal(htons(uidTotal)), //,
    uidCount(std::min(uidTotal, maxUidCount))
    {}
  uint8_t  rdmVer     = def::rdmVersion;    // RDM version - RDM STANDARD V1.0
  uint8_t  port;       //physical
  uint8_t  spare[6]   = {0};
  uint8_t  bindIndex;
  uint8_t  netSwitch;
  enum CommandResponse: uint8_t {
    TodFull = 0x00, TodNak = 0xFF // Full Discovery / ToD not available.
  } cmdRes;
  uint8_t  address;
  uint16_t uidTotal;            // total count of devices we're aware of
  uint8_t  blockCount = 0;      // incr when multiple  packets in sequence.
  uint8_t  uidCount;            // count of devices in this packet (since max 200)
  std::array<RdmUid, maxUidCount> device; // uint8_t  tod[maxUidCount][rdmUidWidth] = {};

  size_t getLength() { return def::todDataSize + (sizeof(RdmUid) * uidCount); } // bc might be shorter than sizeof
};


struct TODRequest: HeaderExt  {
  static const uint8_t maxRdmAddressCount = 32;

  // "node receiving this must not interpret as forcing a full discovery" - only poweron + TODControl Flush
  // looks like these are only supposed to be sent by directed bcast (by Controller and Input Gateway)
  // - but ola is unicasting to us...
  TODRequest(): HeaderExt(OpTodRequest) {}
  uint8_t  filler[2] = {0};
  uint8_t  spare[7]  = {0};
  uint8_t  net;     // hi 7 bits port address
  TODCommand command = TODCommand::None; // always 0
  uint8_t  adCount; // up to max maxRdmAddressCount = 32
  std::array<uint8_t, maxRdmAddressCount> address; // low byte of port address asked to respond - subSwitch + "Universe"
};

struct TODControl: HeaderExt  {
  TODControl(): HeaderExt(OpTodControl) {} // TODControl is like TODRequest with only one address and no count...
  uint8_t  filler[2] = {0};
  uint8_t  spare[7]  = {0};
  uint8_t  net;
  TODCommand command = TODCommand::Flush;
  uint8_t  address;
};


struct RDM: HeaderExt {
  RDM(rdm::RdmData* c, Port* port):
    HeaderExt(OpRdm),
    netSwitch(port->addr.netSwitch), address(port->addr.subUni),
    rdmData(*c) {
      // memcpy(data, c->buffer + 1, c->packet.length + 1); // Copy everything except the 0xCC start code
    }
  uint8_t   rdmVer     = def::rdmVersion;    // RDM version - RDM STANDARD V1.0
  uint8_t   filler2    = 0;
  uint8_t   spare[7]   = {0};
  uint8_t   netSwitch;
  uint8_t   cmd        = 0x00;    // Command - 0x00 ArProcess = Process RDM. only one available.
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
	uint8_t data[def::dmxBufferSize]; // Variable size array which is defined as maximum here.
};

struct Command: HeaderExt {
  Command(char* commandStr, uint16_t estaMan = def::defaultEstaMan):
    HeaderExt(OpCommand), estaMan(estaMan) {
      strncpy(data, commandStr, def::dmxBufferSize - 1); //or?
    }
	uint16_t estaMan;           // ESTA manufacturer id, hi byte
	uint16_t length;             // BYTE-SWAPPED MANUALLY. Length of array below. Range 0 - 512
	char data[def::dmxBufferSize] = {0}; // Variable size array which is defined as maximum here. Contains null terminated command text.
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

	uint8_t swIn[def::numPorts]; // Bits 3-0 of the 15 bit universe number for a given input port are encoded into the bottom 4 bits of this field.
	// This is used in combination with NetSwitch and SubSwitch to produce the full universe address.
	// This value is ignored unless bit 7 is high. i.e. to program a  value 0x07, send the value as 0x87.
	// Send 0x00 to reset this value to the physical switch setting.
	// Use value 0x7f for no change.  Array size is fixed
	uint8_t swOut[def::numPorts]; // Bits 3-0 of the 15 bit universe number for a given output port are encoded into the bottom 4 bits of this field.
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
  bool falseMeansJustPollIP;
  };
	uint8_t filler4;  // Fill to word boundary.

  uint32_t ip,        // uint8_t ProgIpHi; // Use this IP if Command.Bit2 uint8_t ProgIp2; uint8_t ProgIp1; uint8_t ProgIpLo;
           subMask;   // Use this Subnet Mask if Command.Bit1. hi->lo
	uint16_t port;      // Use this (UDP!!) Port Number if Command.Bit0

	uint8_t spare[8]{0}; // Set to zero, do not test in receiver.
};
/////////////////////////////////////////////////
// Transmitted by Node in response to IpProg.
struct IpProgReply: HeaderExt {
  IpProgReply(DeviceNetwork& network):
    HeaderExt(OpIpProgReply),
    ip(network.ip), subMask(network.subnet), dhcpEnabled(network.dhcp) // garbage around?
     {}
  // IpProgReply(IPv4 ip, IPv4 subnet, uint16_t port = def::defaultUdpPort):
  //   ip(ip), subMask(subnet), port(htons(port)), dhcpEnabled(true) {} // really swap??
	uint8_t filler[4]{0}; // Fill to word boundary.

  uint32_t ip; // The node's current IP Address
  uint32_t subMask; // current subnet
	uint16_t port = def::defaultUdpPort; // hi lo, current port. I'm guessing to use non-6454?

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
