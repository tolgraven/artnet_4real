
/*
espArtNetRDM v1 (pre-release) library
Copyright (c) 2016, Matthew Tong
https://github.com/mtongnz/
Modified from https://github.com/forkineye/E131/blob/master/E131.h
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any
later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with this program.
If not, see http://www.gnu.org/licenses/
*/

#pragma once

#include <Arduino.h>
#if defined(ARDUINO_ARCH_ESP32) || defined(ESP32)
#include <WiFi.h>
#elif defined(ARDUINO_ARCH_ESP8266)
#include <ESP8266WiFi.h>
#elif defined(ARDUINO_ARCH_SAMD)
#if defined(ARDUINO_SAMD_MKR1000)
#include <WiFi101.h>
#else
#include <WiFiNINA.h>
#endif
#else
#error "Architecture not supported!"
#endif
#include <WiFiUdp.h>

#include <functional>

#include "rdmDataTypes.h"
#include "artnet.h"

// artnetnodewifi has less of protocol impl but all of it better documented so keep mining that for good docu
// arttimecode can do both smpte and midi clock(?not? timecode). so fix that
using ArtDMXCallback		= std::function<void(uint8_t, uint8_t, uint16_t, bool)>;
using ArtSyncCallback		= std::function<void()>;
using ArtRDMCallback		= std::function<void(uint8_t, uint8_t, rdm_data*)>;
using ArtIPCallback			= std::function<void()>;
using ArtAddressCallback	= std::function<void()>;
using ArtTodRequestCallback	= std::function<void(uint8_t, uint8_t)>;
using ArtTodFlushCallback	= std::function<void(uint8_t, uint8_t)>;

enum port_type : uint8_t {
	RECEIVE_DMX = 0,   // = receive DMX from ArtNet
	RECEIVE_RDM = 1,   // = receive RDM from ArtNet
	SEND_DMX = 2     // = send DMX to ArtNet
};

enum protocol_type : uint8_t {
	ARTNET = 0,
	SACN_UNICAST = 1, SACN_MULTICAST = 2
};

struct IPEvent {
  IPAddress src = INADDR_NONE;
  uint32_t receivedAt;
};

struct _port_def {
	_port_def(uint8_t universe, port_type t = RECEIVE_DMX,
				uint8_t* buf = nullptr, bool htp = true):
		portType(t), portUni(universe),
		dmxBuffer(buf? buf: new uint8_t[DMX_BUFFER_SIZE]{0}),
		ownBuffer(buf? false: true), //right?
		mergeHTP(htp) {
	}
	~_port_def() {
		if(ownBuffer) delete dmxBuffer;
		if(ipBuffer)  delete ipBuffer;
	}
	uint8_t portType = RECEIVE_DMX; // DMX out/in or RDM out
	uint8_t protocol = ARTNET; // ArtNet or sACN

	// sACN settings
	/* uint16_t e131Uni; */
	/* uint16_t e131Sequence; */
	/* uint8_t e131Priority; */

	uint8_t portUni; // Port universe

	uint8_t* dmxBuffer = nullptr; // DMX final values buffer
	uint16_t dmxChans = 0;
	bool ownBuffer = true;
	bool mergeHTP = true;
	bool merging = false;

	uint8_t* ipBuffer = nullptr; // ArtDMX input merge buffers for 2 IPs. If abstract can have only those, no main buf, and perform when data grabbed?
	uint16_t ipChans[2]{0};

  // IPEvent sender[2];
	IPAddress senderIP[2]{INADDR_NONE}; // IPs for current data + time of last packet
	unsigned long lastPacketTime[2];

  // IPEvent rdmSender[5];
	IPAddress rdmSenderIP[5]{INADDR_NONE}; // IPs for the last 5 RDM commands
	unsigned long rdmSenderTime[5];

	// RDM Variables
	bool todAvailable = false;
	uint16_t uidTotal = 0;
	uint16_t uidMan[50]{0};
	uint32_t uidSerial[50]{0};
	unsigned long lastTodCommand = 0;
};
typedef struct _port_def port_def;


struct _group_def {
	_group_def(uint8_t net, uint8_t subnet):
    netSwitch(net & 0b01111111), subnet(subnet) {}
	~_group_def() { for(auto port: ports) delete port; }
	// Port Address
	uint8_t netSwitch = 0x00;
	uint8_t subnet = 0x00;

	port_def* ports[ARTNET_NUM_PORTS]{nullptr};
	uint8_t numPorts = 0;

	IPAddress cancelMergeIP = INADDR_NONE;
	bool cancelMerge = false;
	unsigned long cancelMergeTime = 0;
};
typedef struct _group_def group_def;


struct _artnet_def {
	_artnet_def() {}
	~_artnet_def() { for(auto gr: group) delete gr; }

	IPAddress deviceIP;
	IPAddress subnet;
	IPAddress broadcastIP;
	IPAddress rdmIP[5]; //appears unused...
	uint8_t rdmIPcount;

	IPAddress syncIP = INADDR_NONE;
	unsigned long lastSync = 0;

	uint8_t deviceMAC[6];
	bool dhcp = true;

	char shortName[ARTNET_SHORT_NAME_LENGTH]{0};
	char longName[ARTNET_LONG_NAME_LENGTH]{0};

	uint16_t oem;
	uint8_t oemHi;
	uint8_t oemLo;
	uint16_t estaMan;
	uint8_t estaHi;
	uint8_t estaLo;

	group_def* group[ARTNET_MAX_GROUPS]{nullptr};
	uint8_t numGroups = 0;
	uint32_t lastIPProg;
	uint32_t nextPollReply = 0;

	uint16_t fwVersion  = 0;
	uint32_t nodeReportCounter = 0;
	uint16_t nodeReportCode = ARTNET_RC_POWER_OK;
	char nodeReport[ARTNET_NODE_REPORT_LENGTH - ARTNET_NODE_REPORT_HEADER_LENGTH] = {0}; //make string n that.
};
typedef struct _artnet_def artnet_device;
// afa these structs I mean they have nothing to do with artnet layout or whatever so just use proper shit yeah?


#pragma pack(push, 1)

// SO. These mainly for construction but guess also parsing by casting.
// Figure whether makes sense working around putting packet data always in same spot
// or, since do have multiple group possibility etc and so much is reused,
// keeping more allocated.
// Or best is streamline so relevant stuff is lifted straight away and
// end user never actually (have to) touch these datatypes at all.

struct PacketArtPoll {
	char     ID[8]      = {ARTNET_ID_STR}; // protocol ID = "Art-Net"
	uint16_t opCode			= ARTNET_ARTPOLL;
	uint8_t  ip[4]			= {0};    // 0 means not configured
	uint16_t port				= ARTNET_PORT;   // 6454. lo, hi...
};


struct PacketPollReply {
  PacketPollReply(IPAddress ipReply, uint8_t macAddress[6], char* nodeShortName, char* nodeLongName) {
      strncpy(shortName, nodeShortName, ARTNET_SHORT_NAME_LENGTH - 1);
      strncpy(longName, nodeLongName, ARTNET_LONG_NAME_LENGTH - 1);
      memcpy(ip, &ipReply, 4);
      memcpy(mac, macAddress, 6);
      memcpy(bindIp, &ipReply, 4); // root device ip but seems needed always
    } // feels more like giv it a full def obj yeah and let it grab what it needs ffs.
	char      ID[8]       = {ARTNET_ID_STR}; // protocol ID = "Art-Net"
	uint16_t  opCode			= ARTNET_ARTPOLL_REPLY; // == OpPollReply
	uint8_t   ip[4]				= {0};      // 0 means not configured
	uint16_t  port				= ARTNET_PORT;   // 6454. lo, hi...
	uint16_t  fwVersion	  = 0;         // uint8_t fwHi = 0, fwLo = 0; //
	uint8_t   netSwitch		= 0;         // Bits 14-8 of the 15 bit universe number are encoded into the bottom 7 bits of this field.
	uint8_t   subSwitch		= 0;         // Bits 7-4 of the 15 bit universe number are encoded into the bottom 4 bits of this field.
	uint16_t  oem				  = ARTNET_DEFAULT_OEM; // uint8_t oemHi = 0x00, oemLo = 0xff;
	uint8_t   ubeaVersion	= 0;

	uint8_t   status      = 0b11110010; // bit 0 UBEA, 1 RDM capable (not = uni, RDM = bi-directional), bit 2 = 0 Boot flash (normal), 1 Boot ROM (possible error),  bit 3 = Not used bit 5-4 = 00 Universe programming authority unknown, 01 by front panel controls, 10 by network,  bit 7-6 = 00 Indicators Normal, 01 Indicators Locate, 10 Indicators Mute
  // so make setters...  setUbea(bool present) { ... } setBoot(bool present) { ... } setUniverseAuthority(UniverseAuthority state) { ... } setIndicators(IndicatorState state) { ... }

	uint16_t  estaMan     = ARTNET_DEFAULT_ESTA_MAN; // lo, hi...
	// INDEX: 26
	char shortName[ARTNET_SHORT_NAME_LENGTH]   = {0},
       longName[ARTNET_LONG_NAME_LENGTH]     = {0};
	char nodeReport[ARTNET_NODE_REPORT_LENGTH] = {0}; // Text feedback of Node status, errors, debug..

	// uint8_t numPortsPadHi = 0, numPorts = 0;	// hi always 0, lo 0-4
	// but why not just u16 and set normal then...?
	uint16_t numPorts     = 0;

	// INDEX 174: 4 * 20 byte port information for group

	uint8_t portType[ARTNET_NUM_PORTS]   = {0};   // setPortType(uint8_t port, PortData data, bool state) {  } bit 7 is output, 6 input, 0-5 protocol number (0= DMX, 1=MIDI).  for DMX-Hub ={0xc0,0xc0,0xc0,0xc0};
	uint8_t goodInput[ARTNET_NUM_PORTS]  = {0};   // bit 7 data active, 6 data includes test packets, 5 data includes SIPs, 4 data includes text, 3 input is disabled, 2 receive errors, 1-0 not used, transmitted as zero.  Don't test for zero! (means what?)
	uint8_t goodOutput[ARTNET_NUM_PORTS] = {0};   // bit 7-4 same as goodInput 3 output merging data., 2 DMX output short detected on power up, 1 DMX output merge mode LTP, 0 not used, transmitted as zero.
	uint8_t swIn[ARTNET_NUM_PORTS]       = {0},   // Bits 3-0 of the 15 bit universe number are encoded into the low nibble
          swOut[ARTNET_NUM_PORTS]      = {0};   // This is used in combination with SubSwitch and NetSwitch to produce the full universe address.  THIS IS FOR INPUT/OUTPUT - ART-NET or DMX, NB ON ART-NET II THESE 4 UNIVERSES WILL BE UNICAST TO.

	uint8_t swVideo     = 0;    // Low nibble is the value of the video output channel
	uint8_t swMacro     = 0;    // Bit 0-7 Macro input 1-8
	uint8_t swRemote    = 0;    // Bit 0-7 Macro input 1-8

	uint8_t spare[3]    = {0};	// Spare 1-3, currently zero
	uint8_t style       = 0;	  // Set to Style code to describe type of equipment

	uint8_t mac[6]      = {0};	// Mac Address, zero if info not available
	uint8_t bindIp[4]   = {0};	// If this unit is part of a larger or modular product, this is the IP of the root device.
	uint8_t bindIndex   = 0;	  // Set to zero if no binding, otherwise this number represents the order of bound devices. A lower number means closer to root device.

	uint8_t status2     = 0b00000110;   // bit 0 supports web config, 1 DHCP configured, 2 DHCP capable, 3-7 n/a, 0
	uint8_t filler[26]  = {0};	        // Filler bytes, currently zero.
};


// struct SubPacketHeader {
// 	char     ID[8]	      = {ARTNET_ID_STR};
// 	uint16_t opCode;
// 	uint16_t protocolVer	= ARTNET_PROTOCOL_VERSION << 8; // hi byte first. wha how is right
//   // uint8_t  rdmVer     = 0x01;    // on all RDM packets version - RDM STANDARD V1.0
// };

struct PacketArtDMX {
  // PacketArtDMX(group_def& group, port_def& port, uint8_t seqId, uint8_t portId,
    // subUni((group.subnet << 4) | port.portUni), // maybe bit messy doing like this but eh
    // net(group.netSwitch & 0x7F), lenHi(length >> 8), lenLo(length & 0xFF) {
  PacketArtDMX(uint8_t seqId, uint8_t p, uint8_t subUni, uint8_t netSwitch,
               uint8_t* payload, uint16_t length):
    sequenceID(seqId), portId(p), subUni(subUni), //{
    net(netSwitch & 0x7F), length(htons(length)) {
      memcpy(data, payload, length);
    }
	char     ID[8]        = {ARTNET_ID_STR}; // protocol ID = "Art-Net"
	uint16_t opCode				= ARTNET_ARTDMX;
	uint16_t protocolVer	= ARTNET_PROTOCOL_VERSION << 8; // hi byte first. wha how is right
	uint8_t sequenceID		= 0;
	uint8_t portId	      = 0;  // Port ID (not really necessary)
	uint8_t subUni				= 0;
	uint8_t net           = 0;
	uint16_t length       = 0;
	uint8_t data[512]     = {0};

  uint8_t getNetSwitch() { return net & 0x7F; }
  uint8_t getSubNet()    { return subUni >> 4; }
  uint8_t getUni()       { return subUni & 0x0F; }
  uint16_t getLength()   { return htons(length); }

};

#define ARTNET_MAX_UID_COUNT 200
#define ARTNET_RDM_UID_WIDTH 6  //typ, 48 bits
struct PacketArtTODData {
  PacketArtTODData(uint8_t g, uint8_t p, uint8_t net, uint8_t address, uint8_t state, uint16_t uidTotal):
    port(p + 1), bindIndex(g + 1), netSwitch(net), //,
    cmdRes((state == RDM_TOD_READY)? 0x00: 0xFF), //,  // 0x00 TOD full, 0xFF  TOD not avail or incomplete)
    // address(address), uidTotalHi(uidTotal >> 8), uidTotalLo(uidTotal) {
    address(address), uidTotal(htons(uidTotal)) {
      // then the rest seems a bit complicated so maybe not from constructor...
    }
	char     ID[8]      = {ARTNET_ID_STR}; // protocol ID = "Art-Net"
  uint16_t opCode     = ARTNET_TOD_DATA;
  uint16_t protocolVer= ARTNET_PROTOCOL_VERSION << 8;
  uint8_t  rdmVer     = ARTNET_RDM_VERSION;    // RDM version - RDM STANDARD V1.0
  uint8_t  port;
  uint8_t  spare[6]   = {0};
  uint8_t  bindIndex;
  uint8_t  netSwitch;
  uint8_t  cmdRes;
  uint8_t  address;
  uint16_t uidTotal;
  // uint8_t  uidTotalHi, uidTotalLo;
  uint8_t  blockCount;
  uint8_t  uidCount;
  uint8_t  tod[ARTNET_MAX_UID_COUNT][ARTNET_RDM_UID_WIDTH] = {};
}; //PACKED;

// enum { ARTNET_MAX_RDM_ADCOUNT = 32 };
// according to the rdm spec, this should be 278 bytes
// we'll set to 512 here, the firmware datagram is still bigger
// enum { ARTNET_MAX_RDM_DATA = 512 };

struct PacketArtRDMResponse {
  PacketArtRDMResponse(rdm_data* c, uint8_t netSwitch, uint8_t subUni):
    netSwitch(netSwitch), // no & 0x7F here?
    address(subUni) {
    // address((group.subnet << 4) | port.portUni) {
      memcpy(data, c->buffer + 1, c->packet.Length + 1); // Copy everything except the 0xCC start code
    }
	char      ID[8]      = {ARTNET_ID_STR}; // protocol ID = "Art-Net"
  uint16_t  opCode     = ARTNET_RDM;
  uint16_t  protocolVer= ARTNET_PROTOCOL_VERSION << 8;
  uint8_t   rdmVer     = ARTNET_RDM_VERSION;    // RDM version - RDM STANDARD V1.0
  uint8_t   filler2    = 0;
  uint8_t   spare[7]   = {0};
  uint8_t   netSwitch;
  uint8_t   cmd        = 0x00;    // Command - 0x00 = Process RDM Packet
  uint8_t   address;
  uint8_t   data[ARTNET_MAX_RDM_DATA] = {0};
}; // PACKED;

// struct PacketArtTimeSync { // this is important for me. also grab the RDM stuff for setting strobe curbes etc from ArtNode.
// 	// set the (clock) time
// };

#pragma pack(pop)

enum ArtPacketType {
  ART_POLL              = 0x2000,
  ART_REPLY             = 0x2100,
  ART_DMX               = 0x5000,
  ART_ADDRESS           = 0x6000,
  ART_INPUT             = 0x7000,
  ART_TODREQUEST        = 0x8000,
  ART_TODDATA           = 0x8100,
  ART_TODCONTROL        = 0x8200,
  ART_RDM               = 0x8300,
  // ART_VIDEOSTEUP        = 0xa010,
  // ART_VIDEOPALETTE      = 0xa020,
  // ART_VIDEODATA         = 0xa040,
  ART_MACMASTER         = 0xf000,
  ART_MACSLAVE          = 0xf100,
  // ART_FIRMWAREMASTER    = 0xf200,
  // ART_FIRMWAREREPLY     = 0xf300,
  ART_IPPROG            = 0xf800,
  ART_IPREPLY           = 0xf900,
  ART_MEDIA             = 0x9000,
  // ART_MEDIAPATCH        = 0x9200,
  // ART_MEDIACONTROLREPLY = 0x9300
  // ART_TIMESYNC          =
}; //PACKED;


class espArtNetRDM {
public:
	espArtNetRDM(): _art(new artnet_device) {} //still makes sense having a sep init so can eg create then wait until online and got IP, and is needed before actual allocs etc
	~espArtNetRDM() {
    delete _art;
    // eUDP.stopAll();
    eUDP.stop();
  }

	void init(IPAddress ip, IPAddress sub, uint8_t* mac, bool dhcp,
				const char* shortName, const char* longName, uint16_t oem, uint16_t esta);
	void init(const char* name, uint16_t oem = ARTNET_DEFAULT_OEM, uint16_t esta = ARTNET_DEFAULT_ESTA_MAN);

	void setFirmwareVersion(uint16_t);
	void setDefaultIP();

	uint8_t addGroup(uint8_t, uint8_t);
	uint8_t addPort(uint8_t group, uint8_t port, uint8_t universe,
					uint8_t type = RECEIVE_DMX, bool htp = true, uint8_t* buf = nullptr);
	bool closePort(uint8_t, uint8_t);

	void begin();
	void pause();
	uint8_t* getDMX(uint8_t, uint8_t);
	uint16_t numChans(uint8_t, uint8_t);

	// protocol functions
	// type: 0 = ARTNET, 1 = SACN_UNICAST, 2 = SACN_MULTICAST
	void setProtocolType(uint8_t, uint8_t, uint8_t);
	uint8_t getProtocolType(uint8_t, uint8_t);

	/* // sACN functions */
	/* void setE131Uni(uint8_t, uint8_t, uint16_t); */

	// handler function for including in loop()
	int handler();

	// set callback functions
	void setArtDMXCallback(ArtDMXCallback callback);
	void setArtRDMCallback(ArtRDMCallback callback);
	void setArtSyncCallback(ArtSyncCallback callback);
	void setArtIPCallback(ArtIPCallback callback);
	void setArtAddressCallback(ArtAddressCallback callback);
	void setTODRequestCallback(ArtTodRequestCallback callback);
	void setTODFlushCallback(ArtTodFlushCallback callback);

	// set ArtNet uni settings
	void setNet(uint8_t, uint8_t);
	void setSubNet(uint8_t, uint8_t);
	void setUni(uint8_t, uint8_t, uint8_t);
	void setPortType(uint8_t, uint8_t, uint8_t);

	// get ArtNet uni settings
	uint8_t getNet(uint8_t);
	uint8_t getSubNet(uint8_t);
	uint8_t getUni(uint8_t, uint8_t);
  uint8_t getSubUni(uint8_t g, uint8_t p);

	// set network settings
	void setIP(IPAddress ip, IPAddress subnet);
	void setIP(IPAddress ip) { setIP(ip, INADDR_NONE); } //wait why
	void setDHCP(bool);

	void setMerge(uint8_t, uint8_t, bool); // XXX merge is a matter for network to device. "We" can't set it.
	bool getMerge(uint8_t, uint8_t);

	void setShortName(char*);
	void setShortName(const String& shortName);
	char* getShortName();
	void setLongName(char*);
	void setLongName(const String& longName);
	char* getLongName();

	void setArtDiagData(char* diagString, uint8_t priority = ARTNET_DP_LOW); //fix this yo. tho also per port i guess
	// RDM functions
	void rdmResponse(rdm_data*, uint8_t, uint8_t);
	void artTODData(uint8_t, uint8_t, uint16_t*, uint32_t*, uint16_t, uint8_t);

	// get network settings
	IPAddress getIP(); // no reason for this to be external or? - controlling device responsible...
	IPAddress getSubnetMask();
	bool getDHCP();

	void setNodeReport(char*, uint16_t);
	void setNodeReport(const String& text);

	void sendDMX(uint8_t group, uint8_t port, uint8_t* data, uint16_t length);

private:
	artnet_device* _art = nullptr;
	void end();

	int _artOpCode(uint8_t*);
	void _artIPProgReply();

	port_def* getPort(uint8_t g, uint8_t p) {
    return (_art->group[g] != nullptr)?
            _art->group[g]->ports[p]:
            nullptr;
	}
  void _clearMergeBuffer(port_def* port) {
      delete port->ipBuffer; // Delete merge buffer if it exists
      port->ipBuffer = nullptr;
  }
  void _cancelMergeOrFinish(group_def* group, bool cancel, IPAddress cancelMergeIP = INADDR_NONE) {
      if(cancel)  group->cancelMergeTime = millis();
      group->cancelMerge = cancel;
      group->cancelMergeIP = cancelMergeIP;
  }
  void _sendPacket(IPAddress dest, uint8_t* data, uint16_t length, uint16_t port = ARTNET_PORT) {
    // right way is maybe like other lib and make a union out of all the structs, for common packet? :)
    // or like the existing proper teensy lib, completely outside...
    eUDP.beginPacket(dest, port);
    int response = eUDP.write(data, length);
    eUDP.endPacket();
  }
  // void _sendPacket(IPAddress dest, uint8_t* data, uint16_t length, uint16_t port = ARTNET_PORT) {
  //   _sendPacketCallback(dest, data, length);
  // }

	// handlers for received packets
	void _artPollReply(bool force = false);
	void _artPollReplyFancy(bool force = false);
	void _artDMX(uint8_t*);
	void _saveDMX(uint8_t*, uint16_t, uint8_t, uint8_t, IPAddress, uint16_t);
	void _artIPProg(uint8_t*);
	void _artAddress(uint8_t*);
	void _artSync(uint8_t*);
	void _artFirmwareMaster(uint8_t*);
	void _artTODRequest(uint8_t*);
	void _artTODControl(uint8_t*);
	void _artRDM(uint8_t*, uint16_t);
	void _artRDMSub(uint8_t*);


	uint8_t _dmxSeqID = 0; // isnt this per group/port if anything or?

	WiFiUDP eUDP; //fix more flexibility so ethernet etc tho! maybe template like applemidi lib but so much boilerp
  // else that this only deals with packet construction/parsing -> generic lib woohoo. more smarter.

	ArtDMXCallback dmxCallback;
	ArtSyncCallback syncCallback;
	ArtRDMCallback rdmCallback;
	ArtIPCallback ipCallback;
	ArtAddressCallback addressCallback;
	ArtTodRequestCallback todRequestCallback;
	ArtTodFlushCallback todFlushCallback;
};
