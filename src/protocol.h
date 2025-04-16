#pragma once

#include <cstdint>
#include <stddef.h>

#include "platform.h"

namespace anfr::def {


const uint32_t defaultUdpPort       = 6454;
constexpr const char* idStr         = "Art-Net";
// #define idStr                    'A', 'r', 't', '-', 'N', 'e', 't', '\0'
#define ARTNET_ID_STR               'A', 'r', 't', '-', 'N', 'e', 't', '\0'
const uint32_t protocolVersion      = 14;
const uint32_t rdmVersion           = 0x01 ;       // RDM STANDARD V1.0

const size_t bufferMax              = 600;
const size_t dmxBufferSize          = 512;
const size_t senderSlots            = 2;
// const size_t pollReplySize          = 239;
// const size_t ipProgReplySize        = 34;
const size_t rdmReplySize           = 24;
const size_t todDataSize            = 28;
const uint32_t addressOffset        = 18;

const size_t shortNameLength        = 18;
const size_t longNameLength         = 64;
const size_t nodeReportLength       = 64;
constexpr const char* nodeReportHeaderFmt = "#%04x[%d] %s";  //. at least the 4char hex in beginning is per spec cant remember look up
const size_t nodeReportHeaderLength = 15;   //"#%04x[%d] %s". 14+\0. hack for now, make dynamic/adjustable...

// time defines
const uint32_t cancelMergeTimeout   = 2500;
const int SENDER_TIMEOUT            = 10000; // was set to but thought everything is 4s p much?
const int KEEPALIVE_INTERVAL        = 4000; //ms

// const uint32_t maxGroups         = 16
const uint32_t numPorts             = 4;
const uint32_t defaultOem           = 0x00ff;      // Artnet OEM code - "unknown"
const uint32_t defaultEstaMan       = 0x7fff;      // ESTA Manufacturer code - "prototyping reserved"
const uint32_t defaultEstaDev       = 0xEE000000;  // RDM Device ID (used with Man Code to make 48bit UID)

// from other lib: according to the rdm spec,
// this should be 278 bytes we'll set to 512 here, the firmware datagram is still bigger
// this lib has it at 24 lol
const uint32_t maxRdmData           = 278;

const IPv4 primaryBroadcast{2, 255, 255, 255};
const IPv4 secondaryBroadcast{10, 255, 255, 255};

// enum class Op: uint16_t {
//   Poll             = 0x2000, // This is an ArtPoll packet		= no other data is contained in this UDP packet
// }; // seems kooler

enum OpCode: uint16_t {
  OpPoll             = 0x2000, // This is an ArtPoll packet		= no other data is contained in this UDP packet
  OpPollReply        = 0x2100, // This is an ArtPollReply Packet. It contains device status information.
  OpDiagData         = 0x2300, // Diagnostics and data logging packet.
  OpCommand          = 0x2400, // Used to send text based parameter commands.
  // OpOutput           = 0x5000, // This is an ArtDmx data packet. It contains zero start code DMX512 information for a single Universe.
  OpDmx              = 0x5000, // This is an ArtDmx data packet. It contains zero start code DMX512 information for a single Universe.
  // OpNzs              = 0x5100, // This is an ArtNzs data packet. It contains non-zero start code (except RDM) DMX512 information for a single Universe.
  OpSync             = 0x5200, // Used to synchronise frame output
  OpAddress          = 0x6000, // This is an ArtAddress packet. It contains remote programming information for a Node.
  OpInput            = 0x7000, // This is an ArtInput packet. It contains enable – disable data for DMX inputs.
  OpTodRequest       = 0x8000, // This is an ArtTodRequest packet. It is used to request a Table of Devices (ToD) for RDM discovery.
  OpTodData          = 0x8100, // This is an ArtTodData packet. It is used to send a Table of Devices (ToD) for RDM discovery.
  OpTodControl       = 0x8200, // This is an ArtTodControl packet. It is used to send RDM discovery control messages.
  OpRdm              = 0x8300, // This is an ArtRdm packet. It is used to send all non discovery RDM messages.
  OpRdmSub           = 0x8400, // This is an ArtRdmSub packet. It is used to send compressed		= RDM Sub-Device data.
  // OpVideoSetup       = 0xa010, // This is an ArtVideoSetup packet. It contains video screen setup information for nodes that implement the extended video features.
  // OpVideoPalette     = 0xa020, // This is an ArtVideoPalette packet. It contains colour palette setup information for nodes that implement the extended video features.
  // OpVideoData        = 0xa040, // This is an ArtVideoData packet. It contains display data for nodes that implement the extended video features.
  // OpMacMaster        = 0xf000, // This is an ArtMacMaster packet. It is used to program the Node’s MAC address		= Oem device type and ESTA manufacturer code. This is for factory initialisation of a Node. It is not to be used by applications.
  // OpMacSlave         = 0xf100, // This is an ArtMacSlave packet. It is returned by the node to acknowledge receipt of an ArtMacMaster packet.
  OpFirmwareMaster   = 0xf200, // This is an ArtFirmwareMaster packet. It is used to upload new firmware or firmware extensions to the Node.
  // OpFirmwareReply    = 0xf300, // This is an ArtFirmwareReply packet. It is returned by the node to acknowledge receipt of an ArtFirmwareMaster packet or ArtFileTnMaster packet.
  // OpFileTnMaster     = 0xf400, // Uploads user file to node.
  // OpFileFnMaster     = 0xf500, // Downloads user file from node.
  // OpFileFnReply      = 0xf600, // Node acknowledge for downloads.
  OpIpProg           = 0xf800, // This is an ArtIpProg packet. It is used to reprogramme the IP		= Mask and Port address of the Node.
  OpIpProgReply      = 0xf900, // This is an ArtIpProgReply packet. It is returned by the node to acknowledge receipt of an ArtIpProg packet.
  // OpMedia            = 0x9000, // This is an ArtMedia packet. It is Unicast by a Media Server and acted upon by a Controller.
  // OpMediaPatch       = 0x9100, // This is an ArtMediaPatch packet. It is Unicast by a Controller and acted upon by a Media Server.
  // OpMediaControl     = 0x9200, // This is an ArtMediaControl packet. It is Unicast by a Controller and acted upon by a Media Server.
  // OpMediaContrlReply = 0x9300, // This is an ArtMediaControlReply packet. It is Unicast by a Media Server and acted upon by a Controller.
  // OpTimeCode         = 0x9700, // This is an ArtTimeCode packet. It is used to transport time code over the network.
  OpTimeSync         = 0x9800, // Used to synchronise real time date and clock
  // OpTrigger          = 0x9900, // Used to send trigger macros
  // OpDirectory        = 0x9a00, // Requests a node's file list
  // OpDirectoryReply   = 0x9b00  // Replies to OpDirectory with file list
};


union Ac {        // ArtAddress commands...
  enum: uint8_t {
    None        = 0x00,
    CancelMerge = 0x01,      // The next ArtDmx packet cancels Node's merge mode
    LedNormal   = 0x02, LedMute = 0x03, LedLocate = 0x04,  // Node front panel indicators operate normally, are muted, Fast flash all indicators for locate
    ResetRxFlags= 0x05,      // Reset the receive DMX flags for errors, SI's, Text & Test packets
    AnalysisOn  = 0x06, AnalysisOff = 0x07, // Product signal analysis enabled/disabled

    MergeLtp	  = 0x10, MergeHtp	  = 0x50, // Set Port to merge in LTP / HTP (Default Mode)
    ArtNetSel   = 0x60, AcnSel = 0x70, // Set Port to output DMX + RDM from Art-Net (Default Mode) / DMX from sACN.
    ClearOp 	  = 0x90, // Clear all data buffers associated with output port 0
  } cmd;
  uint8_t :6, port: 2; // for port-indexed cmds we extract + cleave off index, so dont handle as enum.

  int getAndClearPortIndex() { // terrblu
    int p = -1;
    if(cmd >= Ac::MergeLtp)  // is port-indexed cmd
      p = port, port = 0; // cleave off index so can use base
    return p;
  }
};


enum PortDmxType: uint8_t { // should use actual codepoints tho..
	RECEIVE_DMX = 0b01, // = receive DMX from ArtNet
	SEND_DMX = 0b10,     // = send DMX to ArtNet
  SEND_RECEIVE_DMX = 0b11,
	RECEIVE_RDM = 0xFF // = receive RDM from ArtNet
};
enum PortMode: uint8_t { // actual values in Port Info packet field. Dunno what about receive rdm...
  PortDMX = 0b00,
  PortArtnetIn = 0b01,    // what im thinking Artnet->DMX
  PortArtnetOut = 0b10,   // DMX->Artnet
  PortArtnetHub = 0b11
};
// enum class PORT: uint8_t { // actual values in Port Info packet field. Dunno what about receive rdm...
//   DMX = 0b00, ArtnetToDMX = 0b01, DMXToArtnet = 0b10, ArtnetHub = 0b11
// };
enum protocol_type : uint8_t {
	// ARTNET = 0, SACN_UNICAST = 1, SACN_MULTICAST = 2
	ARTNET = 0x60, SACN = 0x70 // why not, bc maps onto Ac sel
};

// Artnet Node Report Codes
// #define RcSocketWr1    0x0003  // Last UDP from Node failed due to truncated length, Most likely caused by a collision.
// #define RcParseFail    0x0004  // Unable to identify last UDP transmission. Check OpCode and \packet length.
// #define RcUdpFail      0x0005  // Unable to open Udp Socket in last transmission attempt
// #define RcDmxError     0x0008  // DMX512 receive errors detected.
// #define RcDmxUdpFull   0x0009  // Ran out of internal DMX transmit buffers.
// #define RcDmxRxFull    0x000a  // Ran out of internal DMX Rx buffers.
// #define RcSwitchErr    0x000b  // Rx Universe switches conflict.
// #define RcConfigErr    0x000c  // Product configuration does not match firmware.
// #define RcDmxShort     0x000d  // DMX output short detected. See GoodOutput field.
// #define RcUserFail     0x000f  // User changed switch settings when address locked by remote programming. User changes ignored.
enum RC: uint16_t { // Report Codes
  Debug	= 0x0000,
  PowerOk, PowerFail, SocketWr1, ParseFail, UdpFail, ShNameOk, LoNameOk,
  DmxError, DmxUdpFull, DmxRxFull, SwitchErr, ConfigErr, DmxShort, FirmareFail, UserFail
};


enum class DiagPriority: uint8_t {
  All = 0x00, // not an actual priority - used as setting for what to accept
  Low	= 0x10, Med = 0x40, High = 0x80, Critical = 0xe0, Vol = 0xf0, None = 0xff
}; // The message priority, see DpXxxx defines above.

enum class TODCommand: uint8_t {
  None = 0, Flush
};

}
