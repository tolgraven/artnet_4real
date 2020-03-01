
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


#include "ArtNetE131Lib.h"



void _artClearDMXBuffer(uint8_t* buf) {
	memset(buf, 0, DMX_BUFFER_SIZE);
}

void _artSetPacketIP(uint8_t* packet, uint16_t offset, const IPAddress& ip) {
  for(uint8_t i = 0; i < 4; i++)
    packet[offset + i] = ip[i];    // ip address
}

void _artSetPacketHeader(uint8_t* packet, uint32_t opcode) { // common bit of header only
  strcpy((char*)packet, ARTNET_ID);
	packet[8] = opcode;      	// op code lo-hi
	packet[9] = opcode >> 8;
}


// espArtNetRDM::~espArtNetRDM() {
// 	eUDP.stopAll();
// }

void espArtNetRDM::init(IPAddress ip, IPAddress subnet, uint8_t* mac, bool dhcp, const char* shortname, const char* longname, uint16_t oem, uint16_t esta) {
	_art->deviceIP = ip;
	/* _art->subnet = ip; //why is subnet set to ip? */
	/* _art->subnet = subnet; */
	_art->subnet = IPAddress(255, 255, 255, 0); //ip; //why is subnet set to ip?
	/* _art->broadcastIP = IPAddress((uint32_t)ip | ~((uint32_t)subnet)); */
	_art->broadcastIP = IPAddress(192, 168, 1, 255); // well, dont hardcode heh
	_art->dhcp = dhcp;
	_art->oem = oem;
	_art->estaMan = esta;
  strncpy(_art->shortName, shortname, ARTNET_SHORT_NAME_LENGTH - 1); //nullchar?
  strncpy(_art->longName,  longname,  ARTNET_LONG_NAME_LENGTH - 1);
	memcpy(_art->deviceMAC, mac, 6);
}


void espArtNetRDM::init(const char* name, uint16_t oem, uint16_t esta) {
  IPAddress ip = WiFi.localIP();
  IPAddress sub = WiFi.subnetMask();
  uint8_t mac[6];
  WiFi.macAddress(mac);
  init(ip, sub, mac, true, name, name, oem, esta);
};

void espArtNetRDM::setFirmwareVersion(uint16_t fw) {
	_art->fwVersion = fw;
}

void espArtNetRDM::setDefaultIP() {
	_art->dhcp = false;
	_art->subnet = IPAddress(255, 0, 0, 0);
	_art->broadcastIP = IPAddress(2, 255, 255, 255);

	uint8_t b = _art->deviceMAC[3] + (uint8_t)_art->oem + (uint8_t)(_art->oem >> 8);
	uint8_t c = _art->deviceMAC[4];
	uint8_t d = _art->deviceMAC[5];

	_art->deviceIP = IPAddress(2, b, c, d);
}

uint8_t espArtNetRDM::addGroup(uint8_t net, uint8_t subnet) {
	uint8_t g = _art->numGroups;

	_art->group[g] = new group_def(net, subnet);
	return _art->numGroups++; //return index of added group, not amt of groups
}

uint8_t espArtNetRDM::addPort(uint8_t g, uint8_t p, uint8_t universe, uint8_t t, bool htp, uint8_t* buf) {
	// Check for a valid universe, group and port number
	if (universe > 15 || p >= ARTNET_GROUP_MAX_PORTS || g > _art->numGroups)
		return 255;

	group_def* group = _art->group[g];
	if (group->ports[p]) return p; // Check if port is already initialised, return its port number

	group->ports[p] = new port_def(universe, (port_type)t, buf, htp);
	group->numPorts++;

	return p;
}

bool espArtNetRDM::closePort(uint8_t g, uint8_t p) {
	if (g >= _art->numGroups) return false; //seems off? if reply means "yup port was/is now closed"
	if (!getPort(g, p)) return true; // Port already closed

  delete getPort(g, p);
	_art->group[g]->numPorts--;

	return true;
}

void espArtNetRDM::setArtDMXCallback(ArtDMXCallback callback) { dmxCallback = callback; }
void espArtNetRDM::setArtSyncCallback(ArtSyncCallback callback) { syncCallback = callback; }
void espArtNetRDM::setArtRDMCallback(ArtRDMCallback callback) { rdmCallback = callback; }
void espArtNetRDM::setArtIPCallback(ArtIPCallback callback) { ipCallback = callback; }
void espArtNetRDM::setArtAddressCallback(ArtAddressCallback callback) { addressCallback = callback; }
void espArtNetRDM::setTODRequestCallback(ArtTodRequestCallback callback) { todRequestCallback = callback; }
void espArtNetRDM::setTODFlushCallback(ArtTodFlushCallback callback) { todFlushCallback = callback; }

void espArtNetRDM::begin() {
	eUDP.begin(ARTNET_PORT); // Start listening for UDP packets
	eUDP.flush();

	_artPollReply(); // Send ArtPollReply to tell everyone we're here
}

void espArtNetRDM::pause() {
	eUDP.flush();
	// eUDP.stopAll(); //should prob set a flag?
	eUDP.stop(); //should prob set a flag?
}

int espArtNetRDM::handler() {
	uint16_t packetSize = eUDP.parsePacket(); // look for artnet packet.
  int opCode = 0;

	if (packetSize > 0 && packetSize <= ARTNET_BUFFER_MAX) {

		uint8_t data[ARTNET_BUFFER_MAX];

		eUDP.read(data, packetSize);
		opCode = _artOpCode(data);

		switch (opCode) {
      case ARTNET_ARTPOLL:  // The Controller may assume a maximum timeout of 3 seconds between sending ArtPoll and receiving all ArtPollReply packets. If the Controller does not receive a response in this time it should consider the Node to have disconnecte
        _artPollReply(true);  //XXX unlimit. maybe force arg if want to keep periodic behavior.  // was named just artpoll but thats not what we're sending...
        break;              // so spamming out every 2s as below ought work but not spec. immediate reply is the intent.    // so spamming out every 2s as below ought work but not spec. immediate reply (+one on boot) is the intent. wonder why they went this route.
                            // controllers should send every 2.5-3s tho
      case ARTNET_ARTDMX:   _artDMX(data); break;
      case ARTNET_IP_PROG:  _artIPProg(data); break;
      case ARTNET_ADDRESS:  _artAddress(data); break;
      case ARTNET_SYNC:     _artSync(data); break;
      case ARTNET_FIRMWARE_MASTER: _artFirmwareMaster(data); break;
      case ARTNET_TOD_REQUEST: _artTODRequest(data); break;
      case ARTNET_TOD_CONTROL: _artTODControl(data); break;
      case ARTNET_RDM:      _artRDM(data, packetSize); break;
      case ARTNET_RDM_SUB:  _artRDMSub(data); break;
		}
	}

	_artPollReply(); // Send artPollReply - the function will limit the number sent
  return opCode;
}

int espArtNetRDM::_artOpCode(uint8_t* data) {
	if (String((char*)data) == ARTNET_ID) {
		if (data[11] >= 14) {                 //protocol version [10] hi uint8_t [11] lo uint8_t
			return data[9] * 256 + data[8];  //opcode lo uint8_t first
		}
	}
	return 0;
}


void espArtNetRDM::_artPollReply(bool force) {
	if (!force && _art->nextPollReply > millis()) return; // limit the number of artPollReply messages
	_art->nextPollReply = millis() + 2000;

  PacketPollReply packet = PacketPollReply();
  _artSetPacketIP(packet.ip, 0, getIP());    // ip address

  packet.estaMan = _art->estaMan;

  strncpy(packet.shortName, _art->shortName, ARTNET_SHORT_NAME_LENGTH - 1);
  strncpy(packet.longName,  _art->longName,  ARTNET_LONG_NAME_LENGTH - 1);

	// Set reply code
	sprintf(packet.nodeReport, "#%04x[%d] %s", _art->nodeReportCode, _art->nodeReportCounter++, _art->nodeReport);
  // XXX gcc8.2 errors complains that "writing up to 63 bytes into region of size 45-55" like ok cause art_nodereport already 64 I guess but...
	if (_art->nodeReportCounter > 999999) _art->nodeReportCounter = 0; // Max 6 digits for counter - could be longer if wanted

  memcpy(packet.mac, _art->deviceMAC, 6);

  _artSetPacketIP(packet.bindIp, 0, getIP());    // ip address
  // ^^ in orig but it's "ip of root device in modular system" so dunno if should be set normally? check spec

	packet.status2 = (_art->dhcp)? 31: 29;  // status 2, dhcp at bit 2. but can have other functionality...

	// Set values for each group of ports and send artPollReply, reusing rest of data
  // but that seems dumb having to clear, dunno
	for (uint8_t groupNum = 0; groupNum < _art->numGroups; groupNum++) {
		group_def* group = _art->group[groupNum];
		if (group->numPorts == 0) continue;

		packet.netSwitch = group->netSwitch;
		packet.subSwitch = group->subnet;
		packet.numPorts  = (uint16_t)group->numPorts << 8; // hi lo
		packet.bindIndex = groupNum + 1;

		for (int p = 0; p < ARTNET_GROUP_MAX_PORTS; p++) { // Port details
      port_def* port = group->ports[p];

			// Send blank values for empty ports
      packet.portType[p] = 0, packet.goodInput[p] = 0, packet.goodOutput[p] = 0, packet.swIn[p] = 0, packet.swOut[p] = 0;
			if (!port) continue;

			if (port->portType != SEND_DMX) { // DMX or RDM out port
				packet.portType[p]    |= 128;			      // Port Type (128 = DMX out)
				// Get values for Good Output field
				uint8_t go = 0;
				if(port->dmxChans != 0)      go |= 128;	// data being transmitted
				if(port->merging)            go |= 8;		// artnet data being merged
				if(!port->mergeHTP)          go |= 2;		// Merge mode LTP
				if(port->protocol != ARTNET) go |= 1;		// sACN. Should stay in whether or not lib retains support - artnet itself supports flag.
				packet.goodOutput[p]  = go;				      // Good output (128 = data being transmitted)

				packet.swOut[p]       = port->portUni;  // swOut - port address

			} else if (port->portType == SEND_DMX) { // DMX In port info
				packet.portType[p] |= 64;				    // Port type (64 = DMX in)

				if (port->dmxChans != 0)
					packet.goodInput[p] = 128;       		// Good input (128 = data being received)

				packet.swIn[p] = port->portUni; //XXX was setting/getting ports[0] not [p], was that somehow correct or just more dumb shit? 	// swIn
			}
		}

		eUDP.beginPacket(_art->broadcastIP, ARTNET_PORT);
		eUDP.write(reinterpret_cast<uint8_t*>(&packet), ARTNET_REPLY_SIZE);
		eUDP.endPacket();

		delay(0); // is yield necessary? i guess if have tons and tons of ports shit could turn south
	}
}

void espArtNetRDM::_artDMX(uint8_t* data) {
	IPAddress rIP = eUDP.remoteIP();

	uint8_t net = (data[15] & 0x7F);
	uint8_t sub = (data[14] >> 4);
	uint8_t uni = (data[14] & 0x0F);

	// Number of channels hi uint8_t first
	uint16_t numberOfChannels = data[17] + (data[16] << 8);
	uint16_t startChannel = 0;

	for (int g = 0; g < _art->numGroups; g++) { // Loop through all groups
    auto group = _art->group[g];
		if (net != group->netSwitch || sub != group->subnet)
      continue;

    for (int p = 0; p < ARTNET_GROUP_MAX_PORTS; p++) { // Loop through each port
      auto port = getPort(g, p);
      if (!port || port->portType == SEND_DMX)
        continue;

      // If this port has the correct Net, Sub & Uni then save DMX to buffer
      if (uni == port->portUni)
        _saveDMX(data + ARTNET_ADDRESS_OFFSET, numberOfChannels, g, p, rIP, startChannel);
    }
	}
}

void espArtNetRDM::_saveDMX(uint8_t* dmxData, uint16_t numberOfChannels,
                            uint8_t groupNum, uint8_t portNum,
                            IPAddress rIP, uint16_t startChannel) {
	auto group = _art->group[groupNum];
	auto port = group->ports[portNum];

	uint8_t senderID = 255;  // Will be set to 0 or 1 if valid later

	unsigned long timeNow = millis();

	// We can't do the next calculations until after 10 seconds - XXX compare against our start, not boot...
	// if (timeNow > 10000) {
    // for(uint8_t i=0; i < 2; i++) { // used to be if/else if but wouldnt that lead to senderIP[1] never clearing if [0] times out?
      // if(port->lastPacketTime[i] < timeNow - 10000) // is is some inscrutable logic below based on that? lol
        // port->senderIP[i] = INADDR_NONE;
    // }
	// }
  for(uint8_t i=0; i < 2; i++) { // used to be if/else if but wouldnt that lead to senderIP[1] never clearing if [0] times out?
    if(timeNow > port->lastPacketTime[i] + 10000) // is is some inscrutable logic below based on that? lol
      port->senderIP[i] = INADDR_NONE;
  }
  for(int i=1; i>=0; i--) { // guess we start by filling 1
    if(port->senderIP[i] == rIP || port->senderIP[i] == INADDR_NONE) {
      senderID = i;
      port->senderIP[i] = rIP;
      port->lastPacketTime[i] = timeNow;
      break;
    }
  }
	// if (port->senderIP[0] == rIP) {     // packet comes from existing sender 0
	// 	senderID = 0;
	// 	port->lastPacketTime[0] = timeNow;
	// }
	// else if (port->senderIP[1] == rIP || port->senderIP[1] == INADDR_NONE) {
    // // packet matches sender 1, or not yet any sender 1
	// 	senderID = 1;
	// 	port->senderIP[1] = rIP;
	// 	port->lastPacketTime[1] = timeNow;
	// }
	// else if (port->senderIP[0] == INADDR_NONE) {
	// 	senderID = 0;
	// 	port->senderIP[0] = rIP; //dont understand why none should be classed same as rIP?
	// 	port->lastPacketTime[0] = timeNow;
	// }

	// This is a different IP, so drop the packet (Artnet v4 only allows for merging 2 DMX streams)
	if (senderID == 255) return;

	// Check if we're merging (the other IP will be non zero)
	port->merging = (port->senderIP[(senderID ^ 0x01)] == INADDR_NONE);

	if (timeNow > (group->cancelMergeTime + ARTNET_CANCEL_MERGE_TIMEOUT)) { // Cancel merge has lapsed, remove it
		group->cancelMerge = false;
		group->cancelMergeIP = INADDR_NONE;

	} else {
		if (group->cancelMergeIP == port->senderIP[senderID]) { // This is the correct IP, enable cancel merge
			group->cancelMerge = true; // this is already set when command handled in _artAddress. why repeat here?
			group->cancelMergeTime = timeNow;
			// port->mergeHTP = false; //seems wromg to revert this?
			port->merging = false;

			// If the merge is current & IP isn't correct, ignore this packet
		} else if (group->cancelMerge) return;
	}

	// update size if has grown...
  port->dmxChans = max(port->dmxChans, numberOfChannels);

  bool sync = false;
	if (port->merging && port->mergeHTP) {     // Check if we should merge (HTP) or not merge (LTP)
		if (!port->ipBuffer) {                   // Check if there is a buffer.  If not, allocate and clear it
			port->ipBuffer = new uint8_t[2 * DMX_BUFFER_SIZE]{0};
		}
    int offset = senderID * DMX_BUFFER_SIZE + startChannel;
		memcpy(&port->ipBuffer[offset], dmxData, numberOfChannels);

		for (uint16_t x = 0; x < max(port->dmxChans, numberOfChannels); x++) {         // Compare data and put in the output buffer
			port->dmxBuffer[x] = max(port->ipBuffer[x], port->ipBuffer[x + DMX_BUFFER_SIZE]);
		}

	} else { // No merge: copy data directly into output buffer
		memcpy(&port->dmxBuffer[startChannel], dmxData, numberOfChannels); // use len from incoming pack ofc

    // Delete merge buffer if it exists -- should be done when merging ends...
    /* if (port->ipBuffer) { delete port->ipBuffer; } */

		// Check if Sync is enabled and call dmx callback in the main script
    sync = (_art->lastSync > 0 && _art->lastSync < timeNow - 4000 && _art->syncIP == rIP);
		//    _art->syncIP = rIP;
	}
  if(dmxCallback)
    dmxCallback(groupNum, portNum, numberOfChannels, sync);
}

uint8_t* espArtNetRDM::getDMX(uint8_t g, uint8_t p) {
  auto port = getPort(g, p);
  return port? port->dmxBuffer: nullptr;
	// if (g < _art->numGroups && getPort(g, p)) {
    // return getPort(g, p)->dmxBuffer;
	// }
	// return nullptr;
}

uint16_t espArtNetRDM::numChans(uint8_t g, uint8_t p) {
  auto port = getPort(g, p);
  return port? port->dmxChans: 0;
	// if (g < _art->numGroups && getPort(g, p)) {
    // return getPort(g, p)->dmxChans;
	// }
	// return 0;
}

void espArtNetRDM::_artIPProg(uint8_t* data) {
	// Don't do anything if it's the same command again
	if ((_art->lastIPProg + 20) > millis())
		return;
	_art->lastIPProg = millis();

	uint8_t command = data[14];

	if ((command & 0b11000000) == 0b11000000) { // Enable DHCP
		_art->dhcp = true;

	} else if ((command & 0b11000000) == 0b10000000) { // Disable DHCP
		_art->dhcp = false;

		// Program IP
		if ((command & 0b10000100) == 0b10000100)
			_art->deviceIP = IPAddress(data[16], data[17], data[18], data[19]);

		// Program subnet
		if ((command & 0b10000010) == 0b10000010) {
			_art->subnet = IPAddress(data[20], data[21], data[22], data[23]);
			_art->broadcastIP = IPAddress((uint32_t)_art->deviceIP | ~((uint32_t)_art->subnet));
		}

		// Use default address
		if ((command & 0b10001000) == 0b10001000)
			setDefaultIP();
	}

	// Run callback - must be before reply for correct dhcp setting
	if (ipCallback) ipCallback();
	_artIPProgReply(); // Send reply
	_artPollReply(); // Send artPollReply
}

void espArtNetRDM::_artIPProgReply() {
	// Initialise our reply
	uint8_t ipProgReply[ARTNET_IP_PROG_REPLY_SIZE] = {0};
  _artSetPacketHeader(ipProgReply, ARTNET_IP_PROG_REPLY);

	ipProgReply[11] = 14;                 // artNet version (14)
  _artSetPacketIP(ipProgReply, 16, getIP());         // ip address
  _artSetPacketIP(ipProgReply, 20, getSubnetMask()); // subnet address
	ipProgReply[26] = (_art->dhcp) ? (1 << 6) : 0;  // DHCP enabled

	// Send packet
	eUDP.beginPacket(eUDP.remoteIP(), ARTNET_PORT);
	int test = eUDP.write(ipProgReply, ARTNET_IP_PROG_REPLY_SIZE);
	eUDP.endPacket();
}

void espArtNetRDM::_artAddress(uint8_t* data) {
	uint8_t g = data[13] - 1;
  group_def* group = _art->group[g];

	if ((data[12] & 0x80) == 0x80) { // Set net switch
		group->netSwitch = data[12] & 0x7F;
	}
	if (data[14] != '\0') { // Set short name
    memcpy(_art->shortName, data + 14, ARTNET_SHORT_NAME_LENGTH);
	}
	if (data[32] != '\0') { // Set long name
    memcpy(_art->longName, data + 32, ARTNET_LONG_NAME_LENGTH);
	}

	for (int x = 0; x < ARTNET_GROUP_MAX_PORTS; x++) { // Set Port Address
		if ((data[100 + x] & 0xF0) == 0x80 && group->ports[x])
			group->ports[x]->portUni = data[100 + x] & 0x0F;
	}

	if ((data[104] & 0xF0) == 0x80) { // Set subnet
		group->subnet = data[104] & 0x0F;
	}

	// Get port number
	uint8_t p = data[106] & 0x0F;
  port_def* port = group->ports[p];

  uint8_t command = data[106];
	switch (command) { // Command
	case ARTNET_AC_CANCEL_MERGE: {        // a sender has requested we stop merging in the other sender
		group->cancelMergeTime = millis();  // this will happen on next packet
		group->cancelMergeIP = eUDP.remoteIP();

		/*
		for (int x = 0; x < 4; x++) {
		  if (group->ports[x] == 0)
			continue;

		  // Delete merge buffer if it exists
		  if (group->ports[x]->ipBuffer != 0) {
			os_free(group->ports[x]->ipBuffer);
			group->ports[x]->ipBuffer = 0;
		  }

		  // Update our timer variables
		  group->ports[x]->lastPacketTime[0] = 0;
		  group->ports[x]->lastPacketTime[1] = 0;
		}
		*/
		break;
  }

	case ARTNET_AC_MERGE_LTP_0:
	case ARTNET_AC_MERGE_LTP_1:
	case ARTNET_AC_MERGE_LTP_2:
	case ARTNET_AC_MERGE_LTP_3: {
		if (port) {
      delete port->ipBuffer; // Delete merge buffer if it exists
      port->ipBuffer = nullptr;

			// Update our timer variables
			port->lastPacketTime[0] = 0; // shouldnt these be set for rest too?
			port->lastPacketTime[1] = 0;

			port->mergeHTP = false; // Set to LTP

			group->cancelMerge = false; // Cancel any pending cancel merge
			group->cancelMergeIP = INADDR_NONE;
		}
		break;
	}

	case ARTNET_AC_MERGE_HTP_0:
	case ARTNET_AC_MERGE_HTP_1:
	case ARTNET_AC_MERGE_HTP_2:
	case ARTNET_AC_MERGE_HTP_3: {
    uint16_t pid = command - ARTNET_AC_MERGE_HTP_0; //well no but fix. easy get port index by offset see command layout.
		if (port) {
			port->mergeHTP = true; // Set to HTP

			group->cancelMerge = false; // Cancel any pending cancel merge
			group->cancelMergeIP = INADDR_NONE;
		}
		break;
	}

	case ARTNET_AC_CLEAR_OP_0:
	case ARTNET_AC_CLEAR_OP_1:
	case ARTNET_AC_CLEAR_OP_2:
	case ARTNET_AC_CLEAR_OP_3: {
		/* if (port == 0) { */
		if (port) { //this was !port per above. cant be right??
			// Delete merge buffer if it exists
      delete port->ipBuffer; // i guess in this instance we do actually need to nullptr-set it tho
      port->ipBuffer = nullptr;

			_artClearDMXBuffer(port->dmxBuffer); // Clear the DMX output buffer
		}
		break;
	}


	case ARTNET_AC_ARTNET_SEL_0:
	case ARTNET_AC_ARTNET_SEL_1:
	case ARTNET_AC_ARTNET_SEL_2:
	case ARTNET_AC_ARTNET_SEL_3: {
		for (uint8_t x = 0; x < ARTNET_GROUP_MAX_PORTS; x++) {
			if (group->ports[x] == 0) //XXX again super weird check??
				setProtocolType(g, x, protocol_type::ARTNET);
		}
		break;
	}

	case ARTNET_AC_ACN_SEL_0:  //yup actually part of artnet! sacn dmx, but art rdm
	case ARTNET_AC_ACN_SEL_1:
	case ARTNET_AC_ACN_SEL_2:
	case ARTNET_AC_ACN_SEL_3: {
		for (uint8_t x = 0; x < ARTNET_GROUP_MAX_PORTS; x++) {
			if (port == 0) //XXX and here
				setProtocolType(g, x, protocol_type::SACN_UNICAST);
		}
		break;
	}
	}

	_artPollReply();
	if (addressCallback) addressCallback();
}

void espArtNetRDM::_artSync(uint8_t* data) {
	_art->lastSync = millis(); //times out after 4s. should it be micros?

  // ip must be same as last dmx packet.
  // sync is ignored when merging.
	if (syncCallback) // && _art->syncIP == eUDP.remoteIP())
		syncCallback();
}

void espArtNetRDM::_artFirmwareMaster(uint8_t* data) {
	//Serial.println("artFirmwareMaster");
}

void espArtNetRDM::_artTODRequest(uint8_t* data) {
	uint8_t net = data[21];
	uint8_t numAddress = data[23];
	uint8_t addr = 24;

	// Handle artTodControl requests
	if (_artOpCode(data) == ARTNET_TOD_CONTROL) {
		numAddress = 1;
		addr = 23;
	}

	for (int g = 0; g < _art->numGroups; g++) {
    group_def* group = _art->group[g];
		if (group->netSwitch != net)
      continue;

    for (int a = 0; a < numAddress; a++) { // Net matches so loop through the addresses

      // Subnet doesn't match, try the next address
      if (group->subnet != (data[addr + a] >> 4))
        continue;

      // Subnet matches so loop through the 4 ports and check universe
      for (int p = 0; p < ARTNET_GROUP_MAX_PORTS; p++) {
        port_def* port = group->ports[p];
        if (!port || port->portUni != (data[addr + a] & 0x0F))
          continue; // No port, or universe doesnt match.

        port->lastTodCommand = millis();

        if (data[22] == 0x01 && todFlushCallback) { // Flush TOD
          todFlushCallback(g, p);
        } else if(todRequestCallback) { // TOD Request
          todRequestCallback(g, p);
        }
      }
    }
	}
}

void espArtNetRDM::artTODData(uint8_t g, uint8_t p, uint16_t* uidMan, uint32_t* uidDev, uint16_t uidTotal, uint8_t state) {
	// Initialise our reply
	uint16_t len = ARTNET_TOD_DATA_SIZE + (ARTNET_RDM_UID_WIDTH * uidTotal);
  // PacketArtTODData packet(g, p, _art->group[g]->netSwitch,
  auto packet = PacketArtTODData(g, p, _art->group[g]->netSwitch,
                                 getSubUni(g, p), state, uidTotal);

	// uint8_t artTodData[len]; //XXX changed char to uint8_t, should work surely? was complaining about unsigned so beware
  // memset(artTodData, 0, len);
  // _artSetPacketHeader(artTodData, ARTNET_TOD_DATA);
	// artTodData[11] = 14;                 // artNet version (14)
	// artTodData[12] = 0x01;               // rdm standard Ver 1.0
	// artTodData[13] = p + 1;              // port number (1-4 not 0-3)
	// artTodData[20] = g + 1;              // bind index
	// artTodData[21] = _art->group[g]->netSwitch;

  // artTodData[22] = (state == RDM_TOD_READY)? 0x00: 0xFF;  // 0x00 TOD full, 0xFF  TOD not avail or incomplete

	// artTodData[23] = (_art->group[g]->subnet << 4) | getPort(g, p)->portUni;
	// artTodData[24] = uidTotal >> 8;      // number of RDM devices found
	// artTodData[25] = uidTotal;

	uint8_t blockCount = 0;
	uint16_t uidPos = 0;

	while (1) { //dunno about this hah. but guess uidtotal will always reach 0 evt
		// artTodData[26] = blockCount;
		// artTodData[27] = (uidTotal > 200) ? 200 : uidTotal;
		packet.blockCount = blockCount;
		packet.uidCount   = constrain(uidTotal, 0, ARTNET_MAX_UID_COUNT);

		uint8_t uidCount = 0;

		// Add RDM UIDs (48 bit each) - max 200 per packet
		// for (uint16_t xx = 28; uidCount < ARTNET_MAX_UID_COUNT && uidTotal > 0; uidCount++) {
		// for (uint16_t i = 0, uint8_t uidCount = 0;
		for (uint16_t i = 0;
         uidCount < ARTNET_MAX_UID_COUNT && uidTotal > 0;
         uidCount++, uidTotal--) {
			// uidTotal--;

			packet.tod[i][0] = uidMan[uidTotal] >> 8;
			packet.tod[i][1] = uidMan[uidTotal];
			packet.tod[i][2] = uidDev[uidTotal] >> 24;
			packet.tod[i][3] = uidDev[uidTotal] >> 16;
			packet.tod[i][4] = uidDev[uidTotal] >> 8;
			packet.tod[i][5] = uidDev[uidTotal];
			// artTodData[xx++] = uidMan[uidTotal] >> 8;
			// artTodData[xx++] = uidMan[uidTotal];
			// artTodData[xx++] = uidDev[uidTotal] >> 24;
			// artTodData[xx++] = uidDev[uidTotal] >> 16;
			// artTodData[xx++] = uidDev[uidTotal] >> 8;
			// artTodData[xx++] = uidDev[uidTotal];
		}

    _sendPacket(_art->broadcastIP,
                reinterpret_cast<uint8_t*>(&packet), len);
		// eUDP.beginPacket(_art->broadcastIP, ARTNET_PORT);
		// int test = eUDP.write(artTodData, len);
		// eUDP.endPacket();

		if(uidTotal == 0) break;
		blockCount++;
	}
}

void espArtNetRDM::_artTODControl(uint8_t* data) {
	_artTODRequest(data);
}

void espArtNetRDM::_artRDM(uint8_t* data, uint16_t packetSize) {
	if (!rdmCallback) return;

	IPAddress remoteIp = eUDP.remoteIP();

	uint8_t net = data[21] * 0x7F;
	uint8_t sub = data[23] >> 4;
	uint8_t uni = data[23] & 0x0F;

	// Get RDM data into out buffer ready to send
	rdm_data c;
	c.buffer[0] = 0xCC;
	memcpy(&c.buffer[1], &data[24], data[25] + 2);

	unsigned long timeNow = millis();

	for (int g = 0; g < _art->numGroups; g++) {
    group_def* group = _art->group[g];
		if (net != group->netSwitch || sub != group->subnet)
      continue;

    for (int p = 0; p < ARTNET_GROUP_MAX_PORTS; p++) {
      auto port = getPort(g, p);
      if (!port || port->portType != RECEIVE_RDM)
        continue; // If the port isn't in use

      // Run callback
      if (uni == port->portUni) {
        rdmCallback(g, p, &c);

        bool ipSet = false;

        for (int q = 0; q < 5; q++) {
          // Check when last packets received.  Clear if over 200ms
          if (timeNow >= (port->rdmSenderTime[q] + 200))
            port->rdmSenderIP[q] = INADDR_NONE;

          // Save our IP
          if (ipSet) continue;
          if (port->rdmSenderIP[q] == INADDR_NONE || port->rdmSenderIP[q] == remoteIp) {
            port->rdmSenderIP[q] = remoteIp;
            port->rdmSenderTime[q] = timeNow;
            ipSet = true;
          }
        }
      }
    }
	}
}

void espArtNetRDM::rdmResponse(rdm_data* c, uint8_t g, uint8_t p) {
  auto port = getPort(g, p);
  auto group = _art->group[g];
	uint16_t len = ARTNET_RDM_REPLY_SIZE + c->packet.Length + 1;
  // auto rdmReply = PacketArtRDMResponse(c, group->netSwitch, getSubUni(g, p));
  uint8_t subUni = getSubUni(g, p);
  auto rdmReply = PacketArtRDMResponse(c, group->netSwitch, subUni);

	// uint8_t rdmReply[len]; // Initialise our reply
  // memset(rdmReply, 0, len);
  // _artSetPacketHeader(rdmReply, ARTNET_RDM);
	// rdmReply[11] = 14;                 // artNet version (14)
	// rdmReply[12] = 0x01;               // RDM version - RDM STANDARD V1.0

	// rdmReply[21] = group->netSwitch;
	// rdmReply[22] = 0x00;              // Command - 0x00 = Process RDM Packet
	// rdmReply[23] = (group->subnet << 4) | port->portUni;

	// Copy everything except the 0xCC start code
	// memcpy(&rdmReply[24], &c->buffer[1], c->packet.Length + 1);

	for (int x = 0; x < 5; x++) {
		if (port->rdmSenderIP[x] != INADDR_NONE) {

      _sendPacket(port->rdmSenderIP[x], reinterpret_cast<uint8_t*>(&rdmReply), len);
			// eUDP.beginPacket(getPort(g, p)->rdmSenderIP[x], ARTNET_PORT);
			// int test = eUDP.write(rdmReply, len);
			// eUDP.endPacket();
		}
	}
}

void espArtNetRDM::_artRDMSub(uint8_t* data) {
	//Serial.println("artRDMSub");
}

IPAddress espArtNetRDM::getIP()         { return _art->deviceIP; }
IPAddress espArtNetRDM::getSubnetMask() { return _art->subnet; }
bool      espArtNetRDM::getDHCP()       { return _art->dhcp; }


void espArtNetRDM::setIP(IPAddress ip, IPAddress subnet) {
	_art->deviceIP = ip;

	if ((uint32_t)subnet != 0)
		_art->subnet = subnet;

	_art->broadcastIP = IPAddress((uint32_t)_art->deviceIP | ~((uint32_t)_art->subnet));
}

void espArtNetRDM::setDHCP(bool d) { _art->dhcp = d; }

void espArtNetRDM::setNet(uint8_t g, uint8_t net) {
	if (g >= _art->numGroups) return;
	_art->group[g]->netSwitch = net;
}

uint8_t espArtNetRDM::getNet(uint8_t g) {
	if (g >= _art->numGroups) return 0;
	return _art->group[g]->netSwitch;
}

void espArtNetRDM::setSubNet(uint8_t g, uint8_t sub) {
	if (g >= _art->numGroups) return;
	_art->group[g]->subnet = sub;
}

uint8_t espArtNetRDM::getSubNet(uint8_t g) {
	if (g >= _art->numGroups) return 0; // XXX 0 is a valid subnet right, so that's crap
	return _art->group[g]->subnet;
}

void espArtNetRDM::setUni(uint8_t g, uint8_t p, uint8_t uni) {
  auto port = getPort(g, p);
  if(port) port->portUni = uni;
}

uint8_t espArtNetRDM::getUni(uint8_t g, uint8_t p) {
  auto port = getPort(g, p);
  return port? port->portUni: 0;
}

// is "SubUni" otherwise knows as... address?
uint8_t espArtNetRDM::getSubUni(uint8_t g, uint8_t p) {
  auto port = getPort(g, p);
  if(!port) return 0;
  return (_art->group[g]->subnet << 4) | port->portUni;
}

void espArtNetRDM::setPortType(uint8_t g, uint8_t p, uint8_t t) {
	if (!getPort(g, p)) return;
	getPort(g, p)->portType = t;
}

void espArtNetRDM::setMerge(uint8_t g, uint8_t p, bool htp) {
	if (!getPort(g, p)) return;
	getPort(g, p)->mergeHTP = htp;
}

bool espArtNetRDM::getMerge(uint8_t g, uint8_t p) {
  // auto port = getPort(g, p);
  // return (port? port->mergeHTP: false);
	if (!getPort(g, p)) return false;
	return getPort(g, p)->mergeHTP;
}


void espArtNetRDM::setShortName(char* name) {
	strncpy(_art->shortName, name, ARTNET_SHORT_NAME_LENGTH - 1);
}
void espArtNetRDM::setLongName(char* name) {
	strncpy(_art->longName, name, ARTNET_LONG_NAME_LENGTH - 1);
}

char* espArtNetRDM::getShortName() { return _art->shortName; }
char* espArtNetRDM::getLongName() { return _art->longName; }



void espArtNetRDM::setNodeReport(char* c, uint16_t code) {
	strncpy(_art->nodeReport, c, ARTNET_NODE_REPORT_LENGTH - 1);
	_art->nodeReportCode = code;
}

// void espArtNetRDM::sendDMX(uint8_t g, uint8_t p, IPAddress bcAddress, uint8_t* data, uint16_t length) {
void espArtNetRDM::sendDMX(uint8_t g, uint8_t p, uint8_t* data, uint16_t length) {
  auto port = getPort(g, p);
	if (port == nullptr) return;

  auto group = _art->group[g];

	if (length % 2)   length++; // length is always even and up to 512 channels
	if (length > 512) length = 512;
	port->dmxChans = length;

  // PacketArtDMX packet = {_dmxSeqID++, p, getSubUni(g, p), group->netSwitch, data, length};
  // PacketArtDMX packet{_dmxSeqID++, p, getSubUni(g, p), group->netSwitch, data, length};
  PacketArtDMX packet = PacketArtDMX(_dmxSeqID++, p, getSubUni(g, p),
                              group->netSwitch, data, length);
  // auto packet = new PacketArtDMX(_dmxSeqID++, p, getSubUni(g, p),
  //                             group->netSwitch, data, length);

	// packet.sequenceID     = _dmxSeqID++;
	// packet.physicalPort   = p;
	// packet.subUni         = (group->subnet << 4) | port->portUni;	// Subuni
	// packet.net            = group->netSwitch & 0x7F;	  // Netswitch
	// // packet.length       = length >> 8;		                  // DMX Data length
	// packet.lenHi          = (length >> 8);		// DMX Data length
	// packet.lenLo          = (length & 0xFF);
  // memcpy(packet.data, data, length);

  const uint8_t headerLength = 18;
  auto ip = IPAddress(192,168,1,100);
  _sendPacket(ip, reinterpret_cast<uint8_t*>(&packet), (headerLength + length));
  // _sendPacket(ip, reinterpret_cast<uint8_t*>(packet), (headerLength + length));
	// eUDP.beginPacket(_art->broadcastIP, ARTNET_PORT); //illegal. to output we must become a controller and send artpoll.
	// eUDP.beginPacket(, ARTNET_PORT);
	// eUDP.write(reinterpret_cast<uint8_t*>(&packet), (headerLength + length));
	// eUDP.endPacket();
}

void espArtNetRDM::setProtocolType(uint8_t g, uint8_t p, uint8_t type) {
  auto port = getPort(g, p);
	if(!port) return;


	// Increment or decrement our e131Count variable if the universe was artnet before and is now sACN
	if (port->protocol == ARTNET && type != ARTNET) {
		_artClearDMXBuffer(port->dmxBuffer);
	}  // if it was not an sACN before and it is an ArtNet now => decrement
	else if (port->protocol != ARTNET && type == ARTNET) {
		_artClearDMXBuffer(port->dmxBuffer);
	}

	getPort(g, p)->protocol = type;
}

uint8_t espArtNetRDM::getProtocolType(uint8_t g, uint8_t p) {
	return getPort(g, p)->protocol;
}

