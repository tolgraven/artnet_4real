
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


espArtNetRDM::~espArtNetRDM() {
	eUDP.stopAll();
}

void espArtNetRDM::init(IPAddress ip, IPAddress subnet, uint8_t* mac, bool dhcp, const char* shortname, const char* longname, uint16_t oem, uint16_t esta) {
	_art->deviceIP = ip;
	_art->subnet = ip;
	_art->broadcastIP = IPAddress((uint32_t)ip | ~((uint32_t)subnet));
	_art->dhcp = dhcp;
	_art->oemLo = (uint8_t)oem;
	_art->oemHi = (uint8_t)(oem >> 8);
	_art->estaLo = (uint8_t)esta;
	_art->estaHi = (uint8_t)(esta >> 8);
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
	_art->firmWareVersion = fw;
}

void espArtNetRDM::setDefaultIP() {
	_art->dhcp = false;
	_art->subnet = IPAddress(255, 0, 0, 0);
	_art->broadcastIP = IPAddress(2, 255, 255, 255);

	uint8_t b = _art->deviceMAC[3] + _art->oemLo + _art->oemHi;
	uint8_t c = _art->deviceMAC[4];
	uint8_t d = _art->deviceMAC[5];

	_art->deviceIP = IPAddress(2, b, c, d);
}

uint8_t espArtNetRDM::addGroup(uint8_t net, uint8_t subnet) {
	uint8_t g = _art->numGroups;

	_art->group[g] = new group_def;
	_art->group[g]->netSwitch = net & 0b01111111;
	_art->group[g]->subnet = subnet;
	_art->numGroups++;

	return g;
}

uint8_t espArtNetRDM::addPort(uint8_t g, uint8_t p, uint8_t universe, uint8_t t, bool htp, uint8_t* buf) {
	// Check for a valid universe, group and port number
	if (universe > 15 || p >= 4 || g > _art->numGroups)
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

void espArtNetRDM::setArtDMXCallback(ArtDMXCallback callback) {
	dmxCallback = callback;
}

void espArtNetRDM::setArtSyncCallback(ArtSyncCallback callback) {
	syncCallback = callback;
}

void espArtNetRDM::setArtRDMCallback(ArtRDMCallback callback) {
	rdmCallback = callback;
}

void espArtNetRDM::setArtIPCallback(ArtIPCallback callback) {
	ipCallback = callback;
}

void espArtNetRDM::setArtAddressCallback(ArtAddressCallback callback) {
	addressCallback = callback;
}

void espArtNetRDM::setTODRequestCallback(ArtTodRequestCallback callback) {
	todRequestCallback = callback;
}

void espArtNetRDM::setTODFlushCallback(ArtTodFlushCallback callback) {
	todFlushCallback = callback;
}

void espArtNetRDM::begin() {
	// Start listening for UDP packets
	eUDP.begin(ARTNET_PORT);
	eUDP.flush();

	// Start E131
	// NO Start here. Was already startet in "setProtocolType".

	// Send ArtPollReply to tell everyone we're here
	artPollReply();
}

void espArtNetRDM::pause() {
	eUDP.flush();
	eUDP.stopAll();
}

void espArtNetRDM::handler() {
	if (!_art) return;

	// Artnet packet
	uint16_t packetSize = eUDP.parsePacket();

	if (packetSize > 0) {

		unsigned char _artBuffer[ARTNET_BUFFER_MAX];

		// Read data into buffer
		eUDP.read(_artBuffer, packetSize);

		// Get the Op Code
		int opCode = _artOpCode(_artBuffer);

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

	// Send artPollReply - the function will limit the number sent
	_artPollReply(); // is that really to spec...?

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
	// limit the number of artPollReply messages
	if (!force && _art->nextPollReply > millis()) return;
	_art->nextPollReply = millis() + 2000;

	uint8_t artReplyBuffer[ARTNET_REPLY_SIZE] = {0};
  _artSetPacketHeader(artReplyBuffer, ARTNET_ARTPOLL_REPLY);
  _artSetPacketIP(artReplyBuffer, 10, getIP());    // ip address

	artReplyBuffer[14] = 0x36;               		// port lo first always 0x1936
	artReplyBuffer[15] = 0x19;
	artReplyBuffer[16] = _art->firmWareVersion >> 8;     // firmware hi-lo
	artReplyBuffer[17] = _art->firmWareVersion;
	artReplyBuffer[20] = _art->oemHi;                    // oem hi-lo
	artReplyBuffer[21] = _art->oemLo;
	artReplyBuffer[22] = 0;              		// ubea

	artReplyBuffer[23] = 0b11110010;			// Device is RDM Capable
	artReplyBuffer[24] = _art->estaLo;           	// ESTA Code (2 uint8_ts)
	artReplyBuffer[25] = _art->estaHi;

  memcpy(artReplyBuffer + 26, _art->shortName, ARTNET_SHORT_NAME_LENGTH);
  memcpy(artReplyBuffer + 44, _art->longName, ARTNET_LONG_NAME_LENGTH);

	// node report - send blank - well not if we have something to report no??
	/* for (int x = 0; x < ARTNET_NODE_REPORT_LENGTH; x++) { */
	/* 	artReplyBuffer[x + 108] = 0; */
	/* } */

	// Set reply code
	char tmp[7]; //XXX beware here too whether char vs uint
	sprintf(tmp, "#%04x[", _art->nodeReportCode);
  memcpy(artReplyBuffer + 108, tmp, 7);
  /* strcpy(artReplyBuffer + 108, tmp); */
	/* sprintf(tmp, "%04x", _art->nodeReportCode); */
	/* artReplyBuffer[108] = '#'; */
  /* memcpy(artReplyBuffer + 109, tmp, 4); */
	/* artReplyBuffer[113] = '['; */

	// Max 6 digits for counter - could be longer if wanted
	sprintf(tmp, "%d", _art->nodeReportCounter++);
	if (_art->nodeReportCounter > 999999) _art->nodeReportCounter = 0;

	// Format counter and add to reply buffer
	uint8_t x = 0;
	for (x = 0; tmp[x] != '\0' && x < 6; x++)
		artReplyBuffer[x + 114] = tmp[x];

	uint8_t rLen = ARTNET_NODE_REPORT_LENGTH - x - 2;
	x += 114;

	artReplyBuffer[x++] = ']';
	artReplyBuffer[x++] = ' ';

	// Append plain text report
	for (uint8_t y = 0; y < rLen && _art->nodeReport[y] != '\0'; y++)
		artReplyBuffer[x++] = _art->nodeReport[y];

	/* artReplyBuffer[172] = 0;             //number of ports Hi (always 0) */
	/* artReplyBuffer[200] = 0;             // Style - 0x00 = DMX to/from Artnet */

  memcpy(artReplyBuffer + 201, _art->deviceMAC, 6);// MAC Address

  _artSetPacketIP(artReplyBuffer, 207, getIP());    // ip address

	artReplyBuffer[212] = (_art->dhcp) ? 31 : 29;  // status 2

	/* for (int x = 213; x < ARTNET_REPLY_SIZE; x++) */
	/* 	artReplyBuffer[x] = 0;             // Reserved for future - transmit 0 */

	  // Set values for each group of ports and send artPollReply
	for (uint8_t groupNum = 0; groupNum < _art->numGroups; groupNum++) {
		group_def* group = _art->group[groupNum];

		if (group->numPorts == 0) continue;
    // there are no group offsets here so if multiple groups it'll just get overwritten??
    // or actually worse cause it's bitshifting stuff in place??

		artReplyBuffer[18] = group->netSwitch;       // net
		artReplyBuffer[19] = group->subnet;          // subnet
		artReplyBuffer[173] = group->numPorts;       //number of ports (Lo uint8_t)

		artReplyBuffer[211] = groupNum + 1;    	  // Bind Index

		// Port details
		for (int p = 0; p < ARTNET_GROUP_MAX_PORTS; p++) {
      port_def* port = group->ports[p];

			// Send blank values for empty ports
      /* for(auto i: {174, 178, 182, 186, 190}) */
      /*   artReplyBuffer[i + p] = 0; */

			if (!port) continue; // This port isn't in use

			if (port->portType != SEND_DMX) { // DMX or RDM out port

				// Get values for Good Output field
				uint8_t go = 0;
				if (port->dmxChans != 0)      go |= 128;	// data being transmitted
				if (port->merging)            go |= 8;		// artnet data being merged
				if (!port->mergeHTP)          go |= 2;		// Merge mode LTP
				if (port->protocol != ARTNET) go |= 1;		// sACN. Should stay in whether or not lib retains support - artnet itself supports flag.

				artReplyBuffer[174 + p] |= 128;			      // Port Type (128 = DMX out)
				artReplyBuffer[182 + p] = go;				      // Good output (128 = data being transmitted)
				artReplyBuffer[190 + p] = port->portUni;  // swOut - port address

			  // DMX In port info
			} else if (port->portType == SEND_DMX) {
				artReplyBuffer[174 + p] |= 64;				    // Port type (64 = DMX in)

				if (port->dmxChans != 0)
					artReplyBuffer[178 + p] = 128;       		// Good input (128 = data being received)

				artReplyBuffer[186] = group->ports[0]->portUni; //XXX using ports[0] not p? 	// swIn
			}
		}

		// Send packet
		eUDP.beginPacket(_art->broadcastIP, ARTNET_PORT);
		eUDP.write(artReplyBuffer, ARTNET_REPLY_SIZE);
		eUDP.endPacket();

		delay(0); // is yield necessary?
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

	// We can't do the next calculations until after 10 seconds
	if (timeNow > 10000) {
		unsigned long timeExp = timeNow - 10000;

		// Clear IPs that we haven't heard from in over 10 seconds
		if (port->lastPacketTime[0] < timeExp)
			port->senderIP[0] = INADDR_NONE;
		else if (port->lastPacketTime[1] < timeExp)
			port->senderIP[1] = INADDR_NONE;
	}

	// Get a sender ID
	if (port->senderIP[0] == rIP) {
		senderID = 0;
		port->lastPacketTime[0] = timeNow;
	}
	else if (port->senderIP[1] == rIP || port->senderIP[1] == INADDR_NONE) {
		senderID = 1;
		port->senderIP[1] = rIP;
		port->lastPacketTime[1] = timeNow;
	}
	else if (port->senderIP[0] == INADDR_NONE) {
		senderID = 0;
		port->senderIP[0] = rIP;
		port->lastPacketTime[0] = timeNow;
	}

	// This is a third IP so drop the packet (Artnet v4 only allows for merging 2 DMX streams)
	if (senderID == 255)
		return;

	// Check if we're merging (the other IP will be non zero)
	if (port->senderIP[(senderID ^ 0x01)] == INADDR_NONE)
		port->merging = false;
	else
		port->merging = true;


	// Cancel merge is old so cancel the cancel merge
	if ((group->cancelMergeTime + ARTNET_CANCEL_MERGE_TIMEOUT) < millis()) {
		group->cancelMerge = false;
		group->cancelMergeIP = INADDR_NONE;

	}
	else {
		// This is the correct IP, enable cancel merge
		if (group->cancelMergeIP == port->senderIP[senderID]) {
			group->cancelMerge = 1;
			group->cancelMergeTime = millis();
			port->mergeHTP = false;
			port->merging = false;

			// If the merge is current & IP isn't correct, ignore this packet
		}
		else if (group->cancelMerge)
			return;
	}

	// Store number of channels
	if (numberOfChannels > port->dmxChans)
		port->dmxChans = numberOfChannels;

	// Check if we should merge (HTP) or not merge (LTP)
	if (port->merging && port->mergeHTP) {
		// Check if there is a buffer.  If not, allocate and clear it
		if (port->ipBuffer == 0) {

			port->ipBuffer = (uint8_t*)os_malloc(2 * DMX_BUFFER_SIZE);
			delay(0);
			_artClearDMXBuffer(port->ipBuffer);
			_artClearDMXBuffer(&port->ipBuffer[DMX_BUFFER_SIZE]);
			delay(0);
		}

		// Put data into our buffer
		memcpy(&port->ipBuffer[senderID * DMX_BUFFER_SIZE + startChannel], dmxData, numberOfChannels);

		// Get the number of channels to compare
		numberOfChannels = (port->dmxChans > numberOfChannels) ? port->dmxChans : numberOfChannels;

		// Compare data and put in the output buffer
		for (uint16_t x = 0; x < numberOfChannels; x++)
			port->dmxBuffer[x] = (port->ipBuffer[x] > port->ipBuffer[x + DMX_BUFFER_SIZE]) ? port->ipBuffer[x] : port->ipBuffer[x + DMX_BUFFER_SIZE];

		// Call our dmx callback in the main script (Sync doesn't get used when merging)
		_art->dmxCallback(groupNum, portNum, numberOfChannels, false);

	}
	else {
		// Copy data directly into output buffer
		memcpy(&port->dmxBuffer[startChannel], dmxData, numberOfChannels);

		/*
			// Delete merge buffer if it exists
			if (port->ipBuffer != 0) {
			  os_free(port->ipBuffer);
			  port->ipBuffer = 0;
			}
		*/

		// Check if Sync is enabled and call dmx callback in the main script
		if (_art->lastSync == 0 || (_art->lastSync + 4000) < timeNow || _art->syncIP != rIP)
			_art->dmxCallback(groupNum, portNum, numberOfChannels, false);
		else
			_art->dmxCallback(groupNum, portNum, numberOfChannels, true);

		//    _art->syncIP = rIP;
	}
  if(dmxCallback)
    dmxCallback(groupNum, portNum, numberOfChannels, sync);
}

uint8_t* espArtNetRDM::getDMX(uint8_t g, uint8_t p) {
	if (g < _art->numGroups && getPort(g, p)) {
    return getPort(g, p)->dmxBuffer;
	}
	return nullptr;
}

uint16_t espArtNetRDM::numChans(uint8_t g, uint8_t p) {
	if (g < _art->numGroups && getPort(g, p)) {
    return getPort(g, p)->dmxChans;
	}
	return 0;
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
      // Delete merge buffer if it exists
      delete port->ipBuffer;
      port->ipBuffer = nullptr;

			// Update our timer variables
			port->lastPacketTime[0] = 0;
			port->lastPacketTime[1] = 0;

			// Set to LTP
			port->mergeHTP = false;

			// Cancel any pending cancel merge
			group->cancelMerge = 0;
			group->cancelMergeIP = INADDR_NONE;
		}
		break;
	}

	case ARTNET_AC_MERGE_HTP_0:
	case ARTNET_AC_MERGE_HTP_1:
	case ARTNET_AC_MERGE_HTP_2:
	case ARTNET_AC_MERGE_HTP_3: {
    uint16_t pid = command - ARTNET_AC_MERGE_HTP_0; //well no but fix. easy get port index by offset see command layout.
		// Set to HTP
		if (port) {
			port->mergeHTP = true;

			// Cancel any pending cancel merge
			group->cancelMerge = 0;
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

			// Clear the DMX output buffer
			_artClearDMXBuffer(port->dmxBuffer);
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
	uint16_t len = ARTNET_TOD_DATA_SIZE + (6 * uidTotal);
	char artTodData[len];
  memset(artTodData, 0x0, len);
  _artSetPacketHeader(artTodData, ARTNET_TOD_DATA);
	artTodData[11] = 14;                 // artNet version (14)
	artTodData[12] = 0x01;               // rdm standard Ver 1.0
	artTodData[13] = p + 1;              // port number (1-4 not 0-3)
	artTodData[20] = g + 1;              // bind index
	artTodData[21] = _art->group[g]->netSwitch;

  artTodData[22] = (state == RDM_TOD_READY)? 0x00: 0xFF;  // 0x00 TOD full, 0xFF  TOD not avail or incomplete

	artTodData[23] = (_art->group[g]->subnet << 4) | getPort(g, p)->portUni;
	artTodData[24] = uidTotal >> 8;      // number of RDM devices found
	artTodData[25] = uidTotal;

	uint8_t blockCount = 0;
	uint16_t uidPos = 0;

	uint16_t f = uidTotal;

	while (1) {
		artTodData[26] = blockCount;
		artTodData[27] = (uidTotal > 200) ? 200 : uidTotal;

		uint8_t uidCount = 0;

		// Add RDM UIDs (48 bit each) - max 200 per packet
		for (uint16_t xx = 28; uidCount < 200 && uidTotal > 0; uidCount++) {
			uidTotal--;

			artTodData[xx++] = uidMan[uidTotal] >> 8;
			artTodData[xx++] = uidMan[uidTotal];
			artTodData[xx++] = uidDev[uidTotal] >> 24;
			artTodData[xx++] = uidDev[uidTotal] >> 16;
			artTodData[xx++] = uidDev[uidTotal] >> 8;
			artTodData[xx++] = uidDev[uidTotal];
		}

		// Send packet
		eUDP.beginPacket(_art->broadcastIP, ARTNET_PORT);
		int test = eUDP.write(artTodData, len);
		eUDP.endPacket();

		if (uidTotal == 0)
			break;

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

	// Get the group number
	for (int g = 0; g < _art->numGroups; g++) {
    group_def* group = _art->group[g];
		if (net != group->netSwitch || sub != group->subnet)
      continue;

    // Get the port number
    for (int p = 0; p < ARTNET_GROUP_MAX_PORTS; p++) {
      auto port = getPort(g, p);
      if (!port || port->portType != RECEIVE_RDM)
        continue; // If the port isn't in use

      // Run callback
      if (uni == port->portUni) {
        rdmCallback(g, p, &c);

        bool ipSet = false;

        for (int q = 0; q < 5; q++) {
          // Check when last packets where received.  Clear if over 200ms
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
	uint16_t len = ARTNET_RDM_REPLY_SIZE + c->packet.Length + 1;
	uint8_t rdmReply[len]; // Initialise our reply
  memset(rdmReply, 0, len);
  _artSetPacketHeader(rdmReply, ARTNET_RDM);
	rdmReply[11] = 14;                 // artNet version (14)
	rdmReply[12] = 0x01;               // RDM version - RDM STANDARD V1.0

	rdmReply[21] = _art->group[g]->netSwitch;
	rdmReply[22] = 0x00;              // Command - 0x00 = Process RDM Packet
	rdmReply[23] = (_art->group[g]->subnet << 4) | getPort(g, p)->portUni;

	// Copy everything except the 0xCC start code
	memcpy(&rdmReply[24], &c->buffer[1], c->packet.Length + 1);

	for (int x = 0; x < 5; x++) {
		if (getPort(g, p)->rdmSenderIP[x] != INADDR_NONE) {
			eUDP.beginPacket(getPort(g, p)->rdmSenderIP[x], ARTNET_PORT);
			int test = eUDP.write(rdmReply, len);
			eUDP.endPacket();
		}
	}
}

void espArtNetRDM::_artRDMSub(uint8_t* data) {
	//Serial.println("artRDMSub");
}

IPAddress espArtNetRDM::getIP() { return _art->deviceIP; }

IPAddress espArtNetRDM::getSubnetMask() { return _art->subnet; }

bool espArtNetRDM::getDHCP() { return _art->dhcp; }


void espArtNetRDM::setIP(IPAddress ip, IPAddress subnet) {
	_art->deviceIP = ip;

	if ((uint32_t)subnet != 0)
		_art->subnet = subnet;

	_art->broadcastIP = IPAddress((uint32_t)_art->deviceIP | ~((uint32_t)_art->subnet));
}

void espArtNetRDM::setDHCP(bool d) {
	_art->dhcp = d;
}

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
	if (g >= _art->numGroups) return 0;
	return _art->group[g]->subnet;
}

void espArtNetRDM::setUni(uint8_t g, uint8_t p, uint8_t uni) {
	if (g >= _art->numGroups || !getPort(g, p)) return;
	getPort(g, p)->portUni = uni;
}

uint8_t espArtNetRDM::getUni(uint8_t g, uint8_t p) {
	if (g >= _art->numGroups || !getPort(g, p)) return 0; //oh yeah 0 is invalid/test(?) uni right?
	return getPort(g, p)->portUni;
}


void espArtNetRDM::setPortType(uint8_t g, uint8_t p, uint8_t t) {
	if (g >= _art->numGroups || !getPort(g, p)) return;
	getPort(g, p)->portType = t;
}

void espArtNetRDM::setMerge(uint8_t g, uint8_t p, bool htp) {
	if (g >= _art->numGroups || !getPort(g, p)) return;
	getPort(g, p)->mergeHTP = htp;
}

bool espArtNetRDM::getMerge(uint8_t g, uint8_t p) {
	if (g >= _art->numGroups || !getPort(g, p)) return false;
	return getPort(g, p)->mergeHTP;
}



void espArtNetRDM::setShortName(char* name) {
	memcpy(_art->shortName, name, ARTNET_SHORT_NAME_LENGTH);
}

char* espArtNetRDM::getShortName() {
	return _art->shortName;
}


void espArtNetRDM::setLongName(char* name) {
	memcpy(_art->longName, name, ARTNET_LONG_NAME_LENGTH);
}

char* espArtNetRDM::getLongName() {
	return _art->longName;
}

void espArtNetRDM::setNodeReport(char* c, uint16_t code) {
	strcpy(_art->nodeReport, c);
	_art->nodeReportCode = code;
}

void espArtNetRDM::sendDMX(uint8_t g, uint8_t p, IPAddress bcAddress, uint8_t* data, uint16_t length) {
	if (g >= _art->numGroups || !getPort(g, p)) return;

	uint8_t net = _art->group[g]->netSwitch;
	uint8_t subnet = _art->group[g]->subnet;
	uint8_t uni = getPort(g, p)->portUni;

	// length is always even and up to 512 channels
	if (length % 2)   length += 1;
	if (length > 512) length = 512;

	getPort(g, p)->dmxChans = length;

	uint8_t artDMX[ARTNET_BUFFER_MAX] = {0};
  _artSetPacketHeader(artDMX, ARTNET_ARTDMX);
	artDMX[11] = 14;              // protocol version (14)
	artDMX[12] = _dmxSeqID++;		  // sequence ID
	artDMX[13] = p;		   	        // Port ID (not really necessary)
	artDMX[14] = (subnet << 4) | uni;	// Subuni
	artDMX[15] = (net & 0x7F);		// Netswitch
	artDMX[16] = (length >> 8);		// DMX Data length
	artDMX[17] = (length & 0xFF);

  const uint8_t headerLength = 18;
  memcpy(artDMX + headerLength, data, length);

	// Send packet
	eUDP.beginPacket(bcAddress, ARTNET_PORT);
	eUDP.write(artDMX, (headerLength + length));
	eUDP.endPacket();

}

void espArtNetRDM::setProtocolType(uint8_t g, uint8_t p, uint8_t type) {
	if (!_art || _art->numGroups <= g || !getPort(g, p))
		return;

	// Increment or decrement our e131Count variable if the universe was artnet before and is now sACN
	if (getPort(g, p)->protocol == ARTNET && type != ARTNET) {
		_artClearDMXBuffer(getPort(g, p)->dmxBuffer);
	}  // if it was not an sACN before and it is an ArtNet now => decrement
	else if (getPort(g, p)->protocol != ARTNET && type == ARTNET) {
		_artClearDMXBuffer(getPort(g, p)->dmxBuffer);
	}

	getPort(g, p)->protocol = type;
}

uint8_t espArtNetRDM::getProtocolType(uint8_t g, uint8_t p) {
	return getPort(g, p)->protocol;
}

