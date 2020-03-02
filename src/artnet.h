
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

#define ARTNET_PORT                 6454
#define ARTNET_BUFFER_MAX           600
#define ARTNET_REPLY_SIZE           239
#define ARTNET_IP_PROG_REPLY_SIZE   34
#define ARTNET_RDM_REPLY_SIZE       24
#define ARTNET_TOD_DATA_SIZE        28
#define ARTNET_ADDRESS_OFFSET       18
#define ARTNET_SHORT_NAME_LENGTH    18
#define ARTNET_LONG_NAME_LENGTH     64
#define ARTNET_NODE_REPORT_LENGTH   64
#define ARTNET_NODE_REPORT_HEADER_LENGTH   15   //"#%04x[%d] %s". 14+\0. hack for now, make dynamic/adjustable...
#define ARTNET_CANCEL_MERGE_TIMEOUT 2500
#define DMX_BUFFER_SIZE             512
#define DMX_MAX_CHANS               512

#define ARTNET_MAX_GROUPS           16
#define ARTNET_GROUP_MAX_PORTS      4
#define ARTNET_NUM_PORTS            4
#define ARTNET_DEFAULT_OEM          0x00ff      // Artnet OEM code - "unknown"
#define ARTNET_DEFAULT_ESTA_MAN     0x7fff      // ESTA Manufacturer code - "prototyping reserved"
#define ARTNET_DEFAULT_ESTA_DEV     0xEE000000  // RDM Device ID (used with Man Code to make 48bit UID)
#define ARTNET_ID                   "Art-Net"
#define ARTNET_ID_STR              'A', 'r', 't', '-', 'N', 'e', 't', '\0'
#define ARTNET_PROTOCOL_VERSION     14
#define ARTNET_RDM_VERSION          0x01        // RDM STANDARD V1.0

// from other lib: according to the rdm spec,
// this should be 278 bytes we'll set to 512 here, the firmware datagram is still bigger
// this lib has it at 24 lol
#define ARTNET_MAX_RDM_DATA       278

// Artnet Op Codes
#define ARTNET_ARTPOLL         0x2000
#define ARTNET_ARTPOLL_REPLY   0x2100
#define ARTNET_DIAG_DATA       0x2300
#define ARTNET_COMMAND         0x2400
#define ARTNET_ARTDMX          0x5000
#define ARTNET_NZS             0x5100
#define ARTNET_SYNC            0x5200
#define ARTNET_ADDRESS         0x6000
#define ARTNET_INPUT           0x7000
#define ARTNET_TOD_REQUEST     0x8000
#define ARTNET_TOD_DATA        0x8100
#define ARTNET_TOD_CONTROL     0x8200
#define ARTNET_RDM             0x8300
#define ARTNET_RDM_SUB         0x8400
#define ARTNET_FIRMWARE_MASTER 0xF200
#define ARTNET_FIRMWARE_REPLY  0xF300
#define ARTNET_IP_PROG         0xF800
#define ARTNET_IP_PROG_REPLY   0xF900

#define OpPoll             0x2000  // This is an ArtPoll packet, no other data is contained in this UDP packet
#define OpPollReply        0x2100  // This is an ArtPollReply Packet. It contains device status information.
#define OpDiagData         0x2300  // Diagnostics and data logging packet.
#define OpCommand          0x2400  // Used to send text based parameter commands.
#define OpOutput           0x5000  // This is an ArtDmx data packet. It contains zero start code DMX512 information for a single Universe.
#define OpDmx              0x5000  // This is an ArtDmx data packet. It contains zero start code DMX512 information for a single Universe.
#define OpNzs              0x5100  // This is an ArtNzs data packet. It contains non-zero start code (except RDM) DMX512 information for a single Universe.
#define OpAddress          0x6000  // This is an ArtAddress packet. It contains remote programming information for a Node.
#define OpInput            0x7000  // This is an ArtInput packet. It contains enable – disable data for DMX inputs.
#define OpTodRequest       0x8000  // This is an ArtTodRequest packet. It is used to request a Table of Devices (ToD) for RDM discovery.
#define OpTodData          0x8100  // This is an ArtTodData packet. It is used to send a Table of Devices (ToD) for RDM discovery.
#define OpTodControl       0x8200  // This is an ArtTodControl packet. It is used to send RDM discovery control messages.
#define OpRdm              0x8300  // This is an ArtRdm packet. It is used to send all non discovery RDM messages.
#define OpRdmSub           0x8400  // This is an ArtRdmSub packet. It is used to send compressed, RDM Sub-Device data.
#define OpVideoSetup       0xa010  // This is an ArtVideoSetup packet. It contains video screen setup information for nodes that implement the extended video features.
#define OpVideoPalette     0xa020  // This is an ArtVideoPalette packet. It contains colour palette setup information for nodes that implement the extended video features.
#define OpVideoData        0xa040  // This is an ArtVideoData packet. It contains display data for nodes that implement the extended video features.
#define OpMacMaster        0xf000  // This is an ArtMacMaster packet. It is used to program the Node’s MAC address, Oem device type and ESTA manufacturer code. This is for factory initialisation of a Node. It is not to be used by applications.
#define OpMacSlave         0xf100  // This is an ArtMacSlave packet. It is returned by the node to acknowledge receipt of an ArtMacMaster packet.
#define OpFirmwareMaster   0xf200  // This is an ArtFirmwareMaster packet. It is used to upload new firmware or firmware extensions to the Node.
#define OpFirmwareReply    0xf300  // This is an ArtFirmwareReply packet. It is returned by the node to acknowledge receipt of an ArtFirmwareMaster packet or ArtFileTnMaster packet.
#define OpFileTnMaster     0xf400  // Uploads user file to node.
#define OpFileFnMaster     0xf500  // Downloads user file from node.
#define OpFileFnReply      0xf600  // Node acknowledge for downloads.
#define OpIpProg           0xf800  // This is an ArtIpProg packet. It is used to reprogramme the IP, Mask and Port address of the Node.
#define OpIpProgReply      0xf900  // This is an ArtIpProgReply packet. It is returned by the node to acknowledge receipt of an ArtIpProg packet.
#define OpMedia            0x9000  // This is an ArtMedia packet. It is Unicast by a Media Server and acted upon by a Controller.
#define OpMediaPatch       0x9100  // This is an ArtMediaPatch packet. It is Unicast by a Controller and acted upon by a Media Server.
#define OpMediaControl     0x9200  // This is an ArtMediaControl packet. It is Unicast by a Controller and acted upon by a Media Server.
#define OpMediaContrlReply 0x9300  // This is an ArtMediaControlReply packet. It is Unicast by a Media Server and acted upon by a Controller.
#define OpTimeCode         0x9700  // This is an ArtTimeCode packet. It is used to transport time code over the network.
#define OpTimeSync         0x9800  // Used to synchronise real time date and clock
#define OpTrigger          0x9900  // Used to send trigger macros
#define OpDirectory        0x9a00  // Requests a node's file list
#define OpDirectoryReply   0x9b00  // Replies to OpDirectory with file list

// Artnet Node Report Codes
#define ARTNET_RC_DEBUG 0x0000
#define ARTNET_RC_POWER_OK 0x0001
#define ARTNET_RC_POWER_FAIL 0x0002
#define ARTNET_RC_SH_NAME_OK 0x0006
#define ARTNET_RC_LO_NAME_OK 0x0007
#define ARTNET_RC_FIRMWARE_FAIL 0x000E
#define RcSocketWr1    0x0003  // Last UDP from Node failed due to truncated length, Most likely caused by a collision.
#define RcParseFail    0x0004  // Unable to identify last UDP transmission. Check OpCode and \packet length.
#define RcUdpFail      0x0005  // Unable to open Udp Socket in last transmission attempt
#define RcDmxError     0x0008  // DMX512 receive errors detected.
#define RcDmxUdpFull   0x0009  // Ran out of internal DMX transmit buffers.
#define RcDmxRxFull    0x000a  // Ran out of internal DMX Rx buffers.
#define RcSwitchErr    0x000b  // Rx Universe switches conflict.
#define RcConfigErr    0x000c  // Product configuration does not match firmware.
#define RcDmxShort     0x000d  // DMX output short detected. See GoodOutput field.
#define RcUserFail     0x000f  // User changed switch settings when address locked by remote programming. User changes ignored.

// Artnet Command Codes
#define ARTNET_AC_NONE           0x00
#define ARTNET_AC_CANCEL_MERGE   0x01
#define ARTNET_AC_LED_NORMAL     0x02
#define ARTNET_AC_LED_MUTE       0x03
#define ARTNET_AC_LED_LOCATE     0x04
#define ARTNET_AC_RESET_RX_FLAGS 0x05
#define ARTNET_AC_MERGE_LTP_0    0x10
#define ARTNET_AC_MERGE_LTP_1    0x11
#define ARTNET_AC_MERGE_LTP_2    0x12
#define ARTNET_AC_MERGE_LTP_3    0x13
#define ARTNET_AC_MERGE_HTP_0    0x50
#define ARTNET_AC_MERGE_HTP_1    0x51
#define ARTNET_AC_MERGE_HTP_2    0x52
#define ARTNET_AC_MERGE_HTP_3    0x53
#define ARTNET_AC_CLEAR_OP_0     0x90
#define ARTNET_AC_CLEAR_OP_1     0x91
#define ARTNET_AC_CLEAR_OP_2     0x92
#define ARTNET_AC_CLEAR_OP_3     0x93
#define ARTNET_AC_ARTNET_SEL_0   0x60
#define ARTNET_AC_ARTNET_SEL_1   0x61
#define ARTNET_AC_ARTNET_SEL_2   0x62
#define ARTNET_AC_ARTNET_SEL_3   0x63
#define ARTNET_AC_ACN_SEL_0      0x70
#define ARTNET_AC_ACN_SEL_1      0x71
#define ARTNET_AC_ACN_SEL_2      0x72
#define ARTNET_AC_ACN_SEL_3      0x73

// Artnet ArtPoll and            ArtDiagData priority codes
#define ARTNET_DP_LOW            0x10
#define ARTNET_DP_MED            0x40
#define ARTNET_DP_HIGH           0x80
#define ARTNET_DP_CRITICAL       0xe0
#define ARTNET_DP_VOLATILE       0xf0


#define ARTNET_ST_NODE           0x00  // regular Art-Net device
#define ARTNET_ST_CONTROLLER     0x01  // console.
#define ARTNET_ST_MEDIA          0x02  // Media Server.
#define ARTNET_ST_ROUTE          0x03  // network routing device.
#define ARTNET_ST_BACKUP         0x04  // backup device.
#define ARTNET_ST_CONFIG         0x05  // configuration or diagnostic tool.
#define ARTNET_ST_VISUAL         0x06  // visualiser.

