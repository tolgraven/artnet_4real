
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

// goal is just update for modern c++, uncouple ESP8266WiFi (and ideally Arduino...)...
#pragma once

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <WiFiUdp.h>

#include <functional>

extern "C" {
#include "mem.h"
}
#include "rdmDataTypes.h"
#include "artnet.h"

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

enum protocol_type : uint8_t   // private enum
{
	ARTNET = 0,
	SACN_UNICAST = 1,
	SACN_MULTICAST = 2
};


struct _port_def {
	_port_def(uint8_t universe, port_type t = RECEIVE_DMX,
				uint8_t* buf = nullptr, bool htp = true):
		portType(t), portUni(universe),
		dmxBuffer(buf? buf: new uint8_t[DMX_BUFFER_SIZE]{0}),
		ownBuffer(buf? true: false),
		mergeHTP(htp) {
	}
	~_port_def() {
		if(ownBuffer) delete dmxBuffer;
		if(ipBuffer)  delete ipBuffer;
	}
	// DMX out/in or RDM out
	uint8_t portType = RECEIVE_DMX;

	// ArtNet or sACN
	uint8_t protocol = ARTNET;

	// sACN settings
	uint16_t e131Uni;
	uint16_t e131Sequence;
	uint8_t e131Priority;

	// Port universe
	uint8_t portUni;

	// DMX final values buffer
	uint8_t* dmxBuffer = nullptr;
	uint16_t dmxChans = 0;
	bool ownBuffer = true;
	bool mergeHTP = true;
	bool merging = 0;

	// ArtDMX input buffers for 2 IPs
	uint8_t* ipBuffer = nullptr;
	uint16_t ipChans[2]{0};

	// IPs for current data + time of last packet
	IPAddress senderIP[2]{INADDR_NONE};
	unsigned long lastPacketTime[2];

	// IPs for the last 5 RDM commands
	IPAddress rdmSenderIP[5]{INADDR_NONE};
	unsigned long rdmSenderTime[5];

	// RDM Variables
	bool todAvailable = false;
	uint16_t uidTotal = 0;
	uint16_t uidMan[50];
	uint32_t uidSerial[50];
	unsigned long lastTodCommand = 0;
};

typedef struct _port_def port_def;

struct _group_def {
	_group_def() {}
	~_group_def() { for(auto port: ports) delete port; }
	// Port Address
	uint8_t netSwitch = 0x00;
	uint8_t subnet = 0x00;

	port_def* ports[ARTNET_GROUP_MAX_PORTS]{nullptr};
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
	IPAddress rdmIP[5];
	uint8_t rdmIPcount;

	IPAddress syncIP = INADDR_NONE;
	unsigned long lastSync = 0;

	uint8_t deviceMAC[6];
	bool dhcp = true;

	char shortName[ARTNET_SHORT_NAME_LENGTH];
	char longName[ARTNET_LONG_NAME_LENGTH];

	uint8_t oemHi;
	uint8_t oemLo;
	uint8_t estaHi;
	uint8_t estaLo;

	group_def* group[ARTNET_MAX_GROUPS];
	uint8_t numGroups = 0;
	uint32_t lastIPProg;
	uint32_t nextPollReply = 0;

	uint16_t firmWareVersion = 0;
	uint32_t nodeReportCounter = 0;
	uint16_t nodeReportCode = ARTNET_RC_POWER_OK;
	char nodeReport[ARTNET_NODE_REPORT_LENGTH];
};

typedef struct _artnet_def artnet_device;




class espArtNetRDM {
public:
	espArtNetRDM(): _art(new artnet_device) {} //still makes sense having a sep init so can eg create then wait until online and got IP, and is needed before actual allocs etc
	~espArtNetRDM();

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

	// sACN functions
	void setE131Uni(uint8_t, uint8_t, uint16_t);

	// handler function for including in loop()
	void handler();

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

	// set network settings
	void setIP(IPAddress, IPAddress);
	void setIP(IPAddress ip) {
		setIP(ip, INADDR_NONE);
	}
	void setDHCP(bool);

	// Set Merge & node name
	void setMerge(uint8_t, uint8_t, bool);
	bool getMerge(uint8_t, uint8_t);
	void setShortName(char*);
	char* getShortName();
	void setLongName(char*);
	char* getLongName();

	// RDM functions
	void rdmResponse(rdm_data*, uint8_t, uint8_t);
	void artTODData(uint8_t, uint8_t, uint16_t*, uint32_t*, uint16_t, uint8_t);

	// get network settings
	IPAddress getIP();
	IPAddress getSubnetMask();
	bool getDHCP();

	void setNodeReport(char*, uint16_t);
	void artPollReply();

	void sendDMX(uint8_t, uint8_t, IPAddress, uint8_t*, uint16_t);

private:
	artnet_device* _art = nullptr;
	void end();

	int _artOpCode(unsigned char*);
	void _artIPProgReply();

	// handlers for received packets
	void _artPoll(void);
	void _artDMX(unsigned char*);
	void _saveDMX(unsigned char*, uint16_t, uint8_t, uint8_t, IPAddress, uint16_t);
	void _artIPProg(unsigned char*);
	void _artAddress(unsigned char*);
	void _artSync(unsigned char*);
	void _artFirmwareMaster(unsigned char*);
	void _artTODRequest(unsigned char*);
	void _artTODControl(unsigned char*);
	void _artRDM(unsigned char*, uint16_t);
	void _artRDMSub(unsigned char*);


	uint8_t _dmxSeqID = 0;

	WiFiUDP eUDP;

	ArtDMXCallback dmxCallback;
	ArtSyncCallback syncCallback;
	ArtRDMCallback rdmCallback;
	ArtIPCallback ipCallback;
	ArtAddressCallback addressCallback;
	ArtTodRequestCallback todRequestCallback;
	ArtTodFlushCallback todFlushCallback;
};
