
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
	//for (uint16_t x = 0; x < DMX_BUFFER_SIZE; x++)
	//  buf[x] = 0;
}

void _artSetPacketHeader(uint8_t* packet, uint32_t opcode) { // common bit of header only
	packet[0] = 'A';
	packet[1] = 'r';
	packet[2] = 't';
	packet[3] = '-';
	packet[4] = 'N';
	packet[5] = 'e';
	packet[6] = 't';
	packet[7] = 0;
	packet[8] = opcode;      	// op code lo-hi
	packet[9] = opcode >> 8;
}

espArtNetRDM::espArtNetRDM():
  _art(new artnet_device) {
}

espArtNetRDM::~espArtNetRDM() {
	end();
}

void espArtNetRDM::end() {
	if (!_art) return;

	eUDP.stopAll();

	for (uint8_t g = 0; g < _art->numGroups; g++) {
		for (uint8_t p = 0; p < 4; p++) {
			if (_art->group[g]->ports[p])
				delete _art->group[g]->ports[p];
		}
		delete _art->group[g];
	}
}

void espArtNetRDM::init(IPAddress ip, IPAddress subnet, bool dhcp, char* shortname, char* longname, uint16_t oem, uint16_t esta, uint8_t* mac) {
	if (_art) os_free(_art);

	// Allocate memory for our settings
	_art = (artnet_device*)os_malloc(sizeof(artnet_device));

	delay(1);

	// Store values
	_art->firmWareVersion = 0;
	_art->numGroups = 0;
	_art->nodeReportCounter = 0;
	_art->nodeReportCode = ARTNET_RC_POWER_OK;
	_art->deviceIP = ip;
	_art->subnet = ip;
	_art->broadcastIP = IPAddress((uint32_t)ip | ~((uint32_t)subnet));
	_art->dhcp = dhcp;
	_art->oemLo = (uint8_t)oem;
	_art->oemHi = (uint8_t)(oem >> 8);
	_art->estaLo = (uint8_t)esta;
	_art->estaHi = (uint8_t)(esta >> 8);
	memcpy(_art->shortName, shortname, ARTNET_SHORT_NAME_LENGTH);
	memcpy(_art->longName, longname, ARTNET_LONG_NAME_LENGTH);
	memcpy(_art->deviceMAC, mac, 6);
}

void espArtNetRDM::setFirmwareVersion(uint16_t fw) {
	if (!_art) return;

	_art->firmWareVersion = fw;
}

void espArtNetRDM::setDefaultIP() {
	if (!_art) return;

	_art->dhcp = false;
	_art->subnet = IPAddress(255, 0, 0, 0);
	_art->broadcastIP = IPAddress(2, 255, 255, 255);

	uint8_t b = _art->deviceMAC[3] + _art->oemLo + _art->oemHi;
	uint8_t c = _art->deviceMAC[4];
	uint8_t d = _art->deviceMAC[5];

	_art->deviceIP = IPAddress(2, b, c, d);
}

uint8_t espArtNetRDM::addGroup(uint8_t net, uint8_t subnet) {
	if (!_art) return 255;

	uint8_t g = _art->numGroups;

	_art->group[g] = new group_def;
	_art->group[g]->netSwitch = net & 0b01111111;
	_art->group[g]->subnet = subnet;
	_art->numGroups++;

	return g;
}

uint8_t espArtNetRDM::addPort(uint8_t g, uint8_t p, uint8_t universe, uint8_t t, bool htp, uint8_t* buf) {
	if (!_art) return 255;

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
	if (!_art || g >= _art->numGroups) return false;

	group_def* group = _art->group[g];

	if (!group->ports[p]) return true; // Port already closed

  delete group->ports[p];
	group->numPorts--;

	return true;
}

void espArtNetRDM::setArtDMXCallback(ArtDMXCallback callback) {
	if (!_art) return;
	_art->dmxCallback = callback;
}

void espArtNetRDM::setArtSyncCallback(ArtSyncCallback callback) {
	if (!_art) return;
	_art->syncCallback = callback;
}

void espArtNetRDM::setArtRDMCallback(ArtRDMCallback callback) {
	if (!_art) return;
	_art->rdmCallback = callback;
}

void espArtNetRDM::setArtIPCallback(ArtIPCallback callback) {
	if (!_art) return;
	_art->ipCallback = callback;
}

void espArtNetRDM::setArtAddressCallback(ArtAddressCallback callback) {
	if (!_art) return;
	_art->addressCallback = callback;
}

void espArtNetRDM::setTODRequestCallback(ArtTodRequestCallback callback) {
	if (!_art) return;
	_art->todRequestCallback = callback;
}

void espArtNetRDM::setTODFlushCallback(ArtTodFlushCallback callback) {
	if (!_art) return;
	_art->todFlushCallback = callback;
}

void espArtNetRDM::begin() {
	if (!_art) return;

	// Start listening for UDP packets
	eUDP.begin(ARTNET_PORT);
	eUDP.flush();

	// Start E131
	// NO Start here. Was already startet in "setProtocolType".

	// Send ArtPollReply to tell everyone we're here
	artPollReply();
}

void espArtNetRDM::pause() {
	if (!_art) return;

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

		case ARTNET_ARTPOLL:
			// This is always called at the end of this function
				//_artPoll();
			break;

		case ARTNET_ARTDMX:
			_artDMX(_artBuffer);
			break;

		case ARTNET_IP_PROG:
			_artIPProg(_artBuffer);
			break;

		case ARTNET_ADDRESS:
			_artAddress(_artBuffer);
			break;

		case ARTNET_SYNC:
			_artSync(_artBuffer);
			break;

		case ARTNET_FIRMWARE_MASTER:
			_artFirmwareMaster(_artBuffer);
			break;

		case ARTNET_TOD_REQUEST:
			_artTODRequest(_artBuffer);
			break;

		case ARTNET_TOD_CONTROL:
			_artTODControl(_artBuffer);
			break;

		case ARTNET_RDM:
			_artRDM(_artBuffer, packetSize);
			break;

		case ARTNET_RDM_SUB:
			_artRDMSub(_artBuffer);
			break;
		}
	}

	// Send artPollReply - the function will limit the number sent
	_artPoll();

}

int espArtNetRDM::_artOpCode(unsigned char *_artBuffer) {
	String test = String((char*)_artBuffer);
	if (test.equals("Art-Net")) {
		if (_artBuffer[11] >= 14) {                 //protocol version [10] hi uint8_t [11] lo uint8_t
			return _artBuffer[9] * 256 + _artBuffer[8];  //opcode lo uint8_t first
		}
	}

	return 0;
}


void espArtNetRDM::_artPoll() {
	// limit the number of artPollReply messages
	if (_art->nextPollReply > millis())
		return;
	_art->nextPollReply = millis() + 2000;

	unsigned char _artReplyBuffer[ARTNET_REPLY_SIZE]{0};
  _artSetPacketHeader(_artReplyBuffer, ARTNET_ARTPOLL_REPLY);
	_artReplyBuffer[10] = _art->deviceIP[0];        	// ip address
	_artReplyBuffer[11] = _art->deviceIP[1];
	_artReplyBuffer[12] = _art->deviceIP[2];
	_artReplyBuffer[13] = _art->deviceIP[3];
	_artReplyBuffer[14] = 0x36;               		// port lo first always 0x1936
	_artReplyBuffer[15] = 0x19;
	_artReplyBuffer[16] = _art->firmWareVersion >> 8;     // firmware hi-lo
	_artReplyBuffer[17] = _art->firmWareVersion;
	_artReplyBuffer[20] = _art->oemHi;                    // oem hi-lo
	_artReplyBuffer[21] = _art->oemLo;
	_artReplyBuffer[22] = 0;              		// ubea

	_artReplyBuffer[23] = 0b11110010;			// Device is RDM Capable
	_artReplyBuffer[24] = _art->estaLo;           	// ESTA Code (2 uint8_ts)
	_artReplyBuffer[25] = _art->estaHi;

	//short name
	for (int x = 0; x < ARTNET_SHORT_NAME_LENGTH; x++)
		_artReplyBuffer[x + 26] = _art->shortName[x];

	//long name
	for (int x = 0; x < ARTNET_LONG_NAME_LENGTH; x++)
		_artReplyBuffer[x + 44] = _art->longName[x];

	// node report - send blank
	for (int x = 0; x < ARTNET_NODE_REPORT_LENGTH; x++) {
		_artReplyBuffer[x + 108] = 0;
	}


	// Set reply code
	char tmp[7];
	sprintf(tmp, "%04x", _art->nodeReportCode);
	_artReplyBuffer[108] = '#';
  memcpy(_artReplyBuffer + 109, tmp, 4);
	_artReplyBuffer[113] = '[';

	// Max 6 digits for counter - could be longer if wanted
	sprintf(tmp, "%d", _art->nodeReportCounter++);
	if (_art->nodeReportCounter > 999999)
		_art->nodeReportCounter = 0;

	// Format counter and add to reply buffer
	uint8_t x = 0;
	for (x = 0; tmp[x] != '\0' && x < 6; x++)
		_artReplyBuffer[x + 114] = tmp[x];

	uint8_t rLen = ARTNET_NODE_REPORT_LENGTH - x - 2;
	x = x + 114;

	_artReplyBuffer[x++] = ']';
	_artReplyBuffer[x++] = ' ';

	// Append plain text report
	for (uint8_t y = 0; y < rLen && _art->nodeReport[y] != '\0'; y++)
		_artReplyBuffer[x++] = _art->nodeReport[y];

	/* _artReplyBuffer[172] = 0;             //number of ports Hi (always 0) */
	/* _artReplyBuffer[200] = 0;             // Style - 0x00 = DMX to/from Artnet */

	for (int x = 0; x < 6; x++)           // MAC Address
		_artReplyBuffer[201 + x] = _art->deviceMAC[x];

	_artReplyBuffer[207] = _art->deviceIP[0];        // bind ip
	_artReplyBuffer[208] = _art->deviceIP[1];
	_artReplyBuffer[209] = _art->deviceIP[2];
	_artReplyBuffer[210] = _art->deviceIP[3];

	_artReplyBuffer[212] = (_art->dhcp) ? 31 : 29;  // status 2

	for (int x = 213; x < ARTNET_REPLY_SIZE; x++)
		_artReplyBuffer[x] = 0;             // Reserved for future - transmit 0


	  // Set values for each group of ports and send artPollReply
	for (uint8_t groupNum = 0; groupNum < _art->numGroups; groupNum++) {
		group_def* group = _art->group[groupNum];

		if (group->numPorts == 0)
			continue;

		_artReplyBuffer[18] = group->netSwitch;       // net
		_artReplyBuffer[19] = group->subnet;          // subnet
		_artReplyBuffer[173] = group->numPorts;       //number of ports (Lo uint8_t)

		_artReplyBuffer[211] = groupNum + 1;    	  // Bind Index

		// Port details
		for (int port = 0; port < 4; port++) {

			// Send blank values for empty ports
      for(auto i: {174, 178, 182, 186, 190})
        _artReplyBuffer[i + port] = 0;

			if (group->ports[port] == 0) continue; // This port isn't in use

			// DMX or RDM out port
			if (group->ports[port]->portType != SEND_DMX) {

				// Get values for Good Output field
				uint8_t go = 0;
				if (group->ports[port]->dmxChans != 0)
					go |= 128;						// data being transmitted
				if (group->ports[port]->merging)
					go |= 8;						// artnet data being merged
				if (!group->ports[port]->mergeHTP)
					go |= 2;						// Merge mode LTP
				if (group->ports[port]->protocol != ARTNET)
					go |= 1;						// sACN

				_artReplyBuffer[174 + port] |= 128;			//Port Type (128 = DMX out)
				_artReplyBuffer[182 + port] = go;				//Good output (128 = data being transmitted)
				_artReplyBuffer[190 + port] = group->ports[port]->portUni;  	// swOut - port address

			  // DMX In port info
			}
			else if (group->ports[port]->portType == SEND_DMX) {
				_artReplyBuffer[174 + port] |= 64;				// Port type (64 = DMX in)

				if (group->ports[port]->dmxChans != 0)
					_artReplyBuffer[178 + port] = 128;       		// Good input (128 = data being received)

				_artReplyBuffer[186] = group->ports[0]->portUni;  	// swIn

			}
		}

		// Send packet
		eUDP.beginPacket(_art->broadcastIP, ARTNET_PORT);
		eUDP.write(_artReplyBuffer, ARTNET_REPLY_SIZE);
		eUDP.endPacket();

		delay(0);
	}
}


void espArtNetRDM::artPollReply() {
	if (!_art) return;

	_artPoll();
}

void espArtNetRDM::_artDMX(unsigned char *_artBuffer) {
	group_def* group = 0;

	IPAddress rIP = eUDP.remoteIP();

	uint8_t net = (_artBuffer[15] & 0x7F);
	uint8_t sub = (_artBuffer[14] >> 4);
	uint8_t uni = (_artBuffer[14] & 0x0F);

	// Number of channels hi uint8_t first
	uint16_t numberOfChannels = _artBuffer[17] + (_artBuffer[16] << 8);
	uint16_t startChannel = 0;

	// Loop through all groups
	for (int x = 0; x < _art->numGroups; x++) {
		if (net == _art->group[x]->netSwitch && sub == _art->group[x]->subnet) {
			group = _art->group[x];

			// Loop through each port
			for (int y = 0; y < 4; y++) {
				if (group->ports[y] == 0 || group->ports[y]->portType == SEND_DMX)
					continue;

				// If this port has the correct Net, Sub & Uni then save DMX to buffer
				if (uni == group->ports[y]->portUni)
					_saveDMX(&_artBuffer[ARTNET_ADDRESS_OFFSET], numberOfChannels, x, y, rIP, startChannel);
			}
		}
	}
}

void espArtNetRDM::_saveDMX(unsigned char *dmxData, uint16_t numberOfChannels, uint8_t groupNum, uint8_t portNum, IPAddress rIP, uint16_t startChannel) {
	group_def* group = _art->group[groupNum];
	port_def* port = group->ports[portNum];

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
}

uint8_t* espArtNetRDM::getDMX(uint8_t g, uint8_t p) {
	if (!_art) return NULL;

	if (g < _art->numGroups) {
		if (_art->group[g]->ports[p] != 0)
			return _art->group[g]->ports[p]->dmxBuffer;
	}
	return NULL;
}

uint16_t espArtNetRDM::numChans(uint8_t g, uint8_t p) {
	if (!_art) return 0;

	if (g < _art->numGroups) {
		if (_art->group[g]->ports[p] != 0)
			return _art->group[g]->ports[p]->dmxChans;
	}
	return 0;
}

void espArtNetRDM::_artIPProg(unsigned char *_artBuffer) {
	// Don't do anything if it's the same command again
	if ((_art->lastIPProg + 20) > millis())
		return;
	_art->lastIPProg = millis();

	uint8_t command = _artBuffer[14];

	// Enable DHCP
	if ((command & 0b11000000) == 0b11000000) {
		_art->dhcp = true;

		// Disable DHCP
	}
	else if ((command & 0b11000000) == 0b10000000) {
		_art->dhcp = false;

		// Program IP
		if ((command & 0b10000100) == 0b10000100)
			_art->deviceIP = IPAddress(_artBuffer[16], _artBuffer[17], _artBuffer[18], _artBuffer[19]);

		// Program subnet
		if ((command & 0b10000010) == 0b10000010) {
			_art->subnet = IPAddress(_artBuffer[20], _artBuffer[21], _artBuffer[22], _artBuffer[23]);
			_art->broadcastIP = IPAddress((uint32_t)_art->deviceIP | ~((uint32_t)_art->subnet));
		}

		// Use default address
		if ((command & 0b10001000) == 0b10001000)
			setDefaultIP();
	}

	// Run callback - must be before reply for correct dhcp setting
	if (_art->ipCallback != 0)
		_art->ipCallback();

	// Send reply
	_artIPProgReply();

	// Send artPollReply
	artPollReply();
}

void espArtNetRDM::_artIPProgReply() {
	// Initialise our reply
	char ipProgReply[ARTNET_IP_PROG_REPLY_SIZE]{0};
  _artSetPacketHeader(ipProgReply, ARTNET_IP_PROG_REPLY);

	ipProgReply[11] = 14;                 // artNet version (14)
	ipProgReply[12] = 0;
	ipProgReply[13] = 0;
	ipProgReply[14] = 0;
	ipProgReply[15] = 0;
	ipProgReply[16] = _art->deviceIP[0];  // ip address
	ipProgReply[17] = _art->deviceIP[1];
	ipProgReply[18] = _art->deviceIP[2];
	ipProgReply[19] = _art->deviceIP[3];
	ipProgReply[20] = _art->subnet[0];    // subnet address
	ipProgReply[21] = _art->subnet[1];
	ipProgReply[22] = _art->subnet[2];
	ipProgReply[23] = _art->subnet[3];
	ipProgReply[26] = (_art->dhcp) ? (1 << 6) : 0;  // DHCP enabled

	// Send packet
	eUDP.beginPacket(eUDP.remoteIP(), ARTNET_PORT);
	int test = eUDP.write(ipProgReply, ARTNET_IP_PROG_REPLY_SIZE);
	eUDP.endPacket();
}

void espArtNetRDM::_artAddress(unsigned char *_artBuffer) {
	// _artBuffer[13]    bindIndex
	uint8_t g = _artBuffer[13] - 1;

	// Set net switch
	if ((_artBuffer[12] & 0x80) == 0x80)
		_art->group[g]->netSwitch = _artBuffer[12] & 0x7F;

	// Set short name
	if (_artBuffer[14] != '\0') {
		for (int x = 0; x < ARTNET_SHORT_NAME_LENGTH; x++)
			_art->shortName[x] = _artBuffer[x + 14];
	}

	// Set long name
	if (_artBuffer[32] != '\0') {
		for (int x = 0; x < ARTNET_LONG_NAME_LENGTH; x++)
			_art->longName[x] = _artBuffer[x + 32];
	}

	// Set Port Address
	for (int x = 0; x < 4; x++) {
		if ((_artBuffer[100 + x] & 0xF0) == 0x80 && _art->group[g]->ports[x] != 0)
			_art->group[g]->ports[x]->portUni = _artBuffer[100 + x] & 0x0F;
	}

	// Set subnet
	if ((_artBuffer[104] & 0xF0) == 0x80) {
		_art->group[g]->subnet = _artBuffer[104] & 0x0F;
	}

	// Get port number
	uint8_t p = _artBuffer[106] & 0x0F;

	// Command
	switch (_artBuffer[106]) {
	case ARTNET_AC_CANCEL_MERGE:
		_art->group[g]->cancelMergeTime = millis();
		_art->group[g]->cancelMergeIP = eUDP.remoteIP();

		/*
		for (int x = 0; x < 4; x++) {
		  if (_art->group[g]->ports[x] == 0)
			continue;

		  // Delete merge buffer if it exists
		  if (_art->group[g]->ports[x]->ipBuffer != 0) {
			os_free(_art->group[g]->ports[x]->ipBuffer);
			_art->group[g]->ports[x]->ipBuffer = 0;
		  }

		  // Update our timer variables
		  _art->group[g]->ports[x]->lastPacketTime[0] = 0;
		  _art->group[g]->ports[x]->lastPacketTime[1] = 0;
		}
		*/
		break;

	case ARTNET_AC_MERGE_LTP_0:
	case ARTNET_AC_MERGE_LTP_1:
	case ARTNET_AC_MERGE_LTP_2:
	case ARTNET_AC_MERGE_LTP_3:
		if (_art->group[g]->ports[p] != 0) {
			// Delete merge buffer if it exists
			if (_art->group[g]->ports[p]->ipBuffer != 0) {
				os_free(_art->group[g]->ports[p]->ipBuffer);
				_art->group[g]->ports[p]->ipBuffer = 0;
			}

			// Update our timer variables
			_art->group[g]->ports[p]->lastPacketTime[0] = 0;
			_art->group[g]->ports[p]->lastPacketTime[1] = 0;

			// Set to LTP
			_art->group[g]->ports[p]->mergeHTP = false;

			// Cancel the cancel merge
			_art->group[g]->cancelMerge = 0;
			_art->group[g]->cancelMergeIP = INADDR_NONE;
		}
		break;

	case ARTNET_AC_MERGE_HTP_0:
	case ARTNET_AC_MERGE_HTP_1:
	case ARTNET_AC_MERGE_HTP_2:
	case ARTNET_AC_MERGE_HTP_3:
		// Set to HTP
		if (_art->group[g]->ports[p] != 0) {
			_art->group[g]->ports[p]->mergeHTP = true;

			// Cancel the cancel merge
			_art->group[g]->cancelMerge = 0;
			_art->group[g]->cancelMergeIP = INADDR_NONE;
		}
		break;

	case ARTNET_AC_CLEAR_OP_0:
	case ARTNET_AC_CLEAR_OP_1:
	case ARTNET_AC_CLEAR_OP_2:
	case ARTNET_AC_CLEAR_OP_3:
		if (_art->group[g]->ports[p] == 0) {
			// Delete merge buffer if it exists
			if (_art->group[g]->ports[p]->ipBuffer != 0) {
				os_free(_art->group[g]->ports[p]->ipBuffer);
				_art->group[g]->ports[p]->ipBuffer = 0;
			}

			// Clear the DMX output buffer
			_artClearDMXBuffer(_art->group[g]->ports[p]->dmxBuffer);
		}
		break;


	case ARTNET_AC_ARTNET_SEL_0:
	case ARTNET_AC_ARTNET_SEL_1:
	case ARTNET_AC_ARTNET_SEL_2:
	case ARTNET_AC_ARTNET_SEL_3:
		for (uint8_t x = 0; x < 4; x++) {
			if (_art->group[g]->ports[x] == 0)
				setProtocolType(g, x, protocol_type::ARTNET);
		}
		break;

	case ARTNET_AC_ACN_SEL_0:
	case ARTNET_AC_ACN_SEL_1:
	case ARTNET_AC_ACN_SEL_2:
	case ARTNET_AC_ACN_SEL_3:
		for (uint8_t x = 0; x < 4; x++) {
			if (_art->group[g]->ports[p] == 0)
				setProtocolType(g, p, protocol_type::SACN_UNICAST);
		}
		break;

	}

	// Send reply
	artPollReply();

	// Run callback
	if (_art->addressCallback != 0)
		_art->addressCallback();
}

void espArtNetRDM::_artSync(unsigned char *_artBuffer) {
	// Update sync timer
	_art->lastSync = millis();

	// Run callback
	if (_art->syncCallback != 0)// && _art->syncIP == eUDP.remoteIP())
		_art->syncCallback();
}

void espArtNetRDM::_artFirmwareMaster(unsigned char *_artBuffer) {
	//Serial.println("artFirmwareMaster");
}

void espArtNetRDM::_artTODRequest(unsigned char *_artBuffer) {
	uint8_t net = _artBuffer[21];
	group_def* group;

	uint8_t numAddress = _artBuffer[23];
	uint8_t addr = 24;

	// Handle artTodControl requests
	if (_artOpCode(_artBuffer) == ARTNET_TOD_CONTROL) {
		numAddress = 1;
		addr = 23;
	}

	for (int g = 0; g < _art->numGroups; g++) {
		group = _art->group[g];

		// Net matches so loop through the addresses
		if (group->netSwitch == net) {
			for (int y = 0; y < numAddress; y++) {

				// Subnet doesn't match, try the next address
				if (group->subnet != (_artBuffer[addr + y] >> 4))
					continue;

				// Subnet matches so loop through the 4 ports and check universe
				for (int p = 0; p < 4; p++) {

					if (group->ports[p] == 0)
						continue;

					port_def* port = group->ports[p];

					if (port->portUni != (_artBuffer[addr + y] & 0x0F))
						continue;

					port->lastTodCommand = millis();

					// Flush TOD
					if (_artBuffer[22] == 0x01)
						_art->todFlushCallback(g, p);

					// TOD Request
					else
						_art->todRequestCallback(g, p);
				}
			}


		}
	}

}

void espArtNetRDM::artTODData(uint8_t g, uint8_t p, uint16_t* uidMan, uint32_t* uidDev, uint16_t uidTotal, uint8_t state) {
	if (!_art) return;

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

	if (state == RDM_TOD_READY)
		artTodData[22] = 0x00;             // TOD full
	else
		artTodData[22] = 0xFF;             // TOD not avail or incomplete

	artTodData[23] = (_art->group[g]->subnet << 4) | _art->group[g]->ports[p]->portUni;
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

void espArtNetRDM::_artTODControl(unsigned char *_artBuffer) {
	_artTODRequest(_artBuffer);
}

void espArtNetRDM::_artRDM(unsigned char *_artBuffer, uint16_t packetSize) {
	if (!_art->rdmCallback) return;

	IPAddress remoteIp = eUDP.remoteIP();

	uint8_t net = _artBuffer[21] * 0x7F;
	uint8_t sub = _artBuffer[23] >> 4;
	uint8_t uni = _artBuffer[23] & 0x0F;

	// Get RDM data into out buffer ready to send
	rdm_data c;
	c.buffer[0] = 0xCC;
	memcpy(&c.buffer[1], &_artBuffer[24], _artBuffer[25] + 2);

	group_def* group = 0;
	unsigned long timeNow = millis();

	// Get the group number
	for (int x = 0; x < _art->numGroups; x++) {
		if (net == _art->group[x]->netSwitch && sub == _art->group[x]->subnet) {
			group = _art->group[x];

			// Get the port number
			for (int y = 0; y < 4; y++) {

				// If the port isn't in use
				if (group->ports[y] == 0 || group->ports[y]->portType != RECEIVE_RDM)
					continue;

				// Run callback
				if (uni == group->ports[y]->portUni) {
					_art->rdmCallback(x, y, &c);

					bool ipSet = false;

					for (int q = 0; q < 5; q++) {
						// Check when last packets where received.  Clear if over 200ms
						if (timeNow >= (group->ports[y]->rdmSenderTime[q] + 200))
							group->ports[y]->rdmSenderIP[q] = INADDR_NONE;

						// Save our IP
						if (!ipSet) {
							if (group->ports[y]->rdmSenderIP[q] == INADDR_NONE || group->ports[y]->rdmSenderIP[q] == remoteIp) {
								group->ports[y]->rdmSenderIP[q] = remoteIp;
								group->ports[y]->rdmSenderTime[q] = timeNow;
								ipSet = true;
							}
						}
					}
				}
			}
		}
	}
}

void espArtNetRDM::rdmResponse(rdm_data* c, uint8_t g, uint8_t p) {
	if (!_art) return;

	uint16_t len = ARTNET_RDM_REPLY_SIZE + c->packet.Length + 1;
	// Initialise our reply
	char rdmReply[len];
  memset(rdmReply, 0x0, len);
  _artSetPacketHeader(rdmReply, ARTNET_RDM);
	rdmReply[11] = 14;                 // artNet version (14)
	rdmReply[12] = 0x01;               // RDM version - RDM STANDARD V1.0

	rdmReply[21] = _art->group[g]->netSwitch;
	rdmReply[22] = 0x00;              // Command - 0x00 = Process RDM Packet
	rdmReply[23] = (_art->group[g]->subnet << 4) | _art->group[g]->ports[p]->portUni;

	// Copy everything except the 0xCC start code
	memcpy(&rdmReply[24], &c->buffer[1], c->packet.Length + 1);

	for (int x = 0; x < 5; x++) {
		if (_art->group[g]->ports[p]->rdmSenderIP[x] != INADDR_NONE) {
			// Send packet
			eUDP.beginPacket(_art->group[g]->ports[p]->rdmSenderIP[x], ARTNET_PORT);
			int test = eUDP.write(rdmReply, len);
			eUDP.endPacket();
		}
	}
}

void espArtNetRDM::_artRDMSub(unsigned char *_artBuffer) {
	//Serial.println("artRDMSub");
}

IPAddress espArtNetRDM::getIP() {
	if (!_art) return INADDR_NONE;
	return _art->deviceIP;
}

IPAddress espArtNetRDM::getSubnetMask() {
	if (!_art) return INADDR_NONE;
	return _art->subnet;
}

bool espArtNetRDM::getDHCP() {
	if (!_art) return false;
	return _art->dhcp;
}


void espArtNetRDM::setIP(IPAddress ip, IPAddress subnet) {
	if (!_art) return;
	_art->deviceIP = ip;

	if ((uint32_t)subnet != 0)
		_art->subnet = subnet;

	_art->broadcastIP = IPAddress((uint32_t)_art->deviceIP | ~((uint32_t)_art->subnet));
}

void espArtNetRDM::setDHCP(bool d) {
	if (!_art) return;
	_art->dhcp = d;
}

void espArtNetRDM::setNet(uint8_t g, uint8_t net) {
	if (!_art || g >= _art->numGroups) return;
	_art->group[g]->netSwitch = net;
}

uint8_t espArtNetRDM::getNet(uint8_t g) {
	if (!_art || g >= _art->numGroups) return 0;
	return _art->group[g]->netSwitch;
}

void espArtNetRDM::setSubNet(uint8_t g, uint8_t sub) {
	if (!_art || g >= _art->numGroups) return;
	_art->group[g]->subnet = sub;
}

uint8_t espArtNetRDM::getSubNet(uint8_t g) {
	if (!_art || g >= _art->numGroups) return 0;
	return _art->group[g]->subnet;
}

void espArtNetRDM::setUni(uint8_t g, uint8_t p, uint8_t uni) {
	if (!_art || g >= _art->numGroups || !_art->group[g]->ports[p]) return;
	_art->group[g]->ports[p]->portUni = uni;
}

uint8_t espArtNetRDM::getUni(uint8_t g, uint8_t p) {
	if (!_art || g >= _art->numGroups || !_art->group[g]->ports[p]) return 0; //oh yeah 0 is invalid/test(?) uni right?
	return _art->group[g]->ports[p]->portUni;
}


void espArtNetRDM::setPortType(uint8_t g, uint8_t p, uint8_t t) {
	if (!_art || g >= _art->numGroups || !_art->group[g]->ports[p]) return;

	_art->group[g]->ports[p]->portType = t;
}

void espArtNetRDM::setMerge(uint8_t g, uint8_t p, bool htp) {
	if (!_art || g >= _art->numGroups || !_art->group[g]->ports[p]) return;
	_art->group[g]->ports[p]->mergeHTP = htp;
}

bool espArtNetRDM::getMerge(uint8_t g, uint8_t p) {
	if (!_art || g >= _art->numGroups || !_art->group[g]->ports[p]) return false;
	return _art->group[g]->ports[p]->mergeHTP;
}



void espArtNetRDM::setShortName(char* name) {
	if (!_art) return;
	memcpy(_art->shortName, name, ARTNET_SHORT_NAME_LENGTH);
}

char* espArtNetRDM::getShortName() {
	if (!_art) return NULL;
	return _art->shortName;
}


void espArtNetRDM::setLongName(char* name) {
	if (!_art) return;
	memcpy(_art->longName, name, ARTNET_LONG_NAME_LENGTH);
}

char* espArtNetRDM::getLongName() {
	if (!_art) return NULL;
	return _art->longName;
}

void espArtNetRDM::setNodeReport(char* c, uint16_t code) {
	if (!_art) return;

	strcpy(_art->nodeReport, c);
	_art->nodeReportCode = code;
}

void espArtNetRDM::sendDMX(uint8_t g, uint8_t p, IPAddress bcAddress, uint8_t* data, uint16_t length) {
	if (!_art || g >= _art->numGroups || !_art->group[g]->ports[p]) return;

	uint8_t net = _art->group[g]->netSwitch;
	uint8_t subnet = _art->group[g]->subnet;
	uint8_t uni = _art->group[g]->ports[p]->portUni;

	// length is always even and up to 512 channels
	if (length % 2)   length += 1;
	if (length > 512) length = 512;

	_art->group[g]->ports[p]->dmxChans = length;

	uint8_t artDMX[ARTNET_BUFFER_MAX]{0};
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
	if (!_art || _art->numGroups <= g || !_art->group[g]->ports[p])
		return;

	// Increment or decrement our e131Count variable if the universe was artnet before and is now sACN
	if (_art->group[g]->ports[p]->protocol == ARTNET && type != ARTNET) {

		// Clear the DMX output buffer
		_artClearDMXBuffer(_art->group[g]->ports[p]->dmxBuffer);

	}  // if it was not an sACN before and it is an ArtNet now => decrement
	else if (_art->group[g]->ports[p]->protocol != ARTNET && type == ARTNET)
	{

		// Clear the DMX output buffer
		_artClearDMXBuffer(_art->group[g]->ports[p]->dmxBuffer);
	}

	_art->group[g]->ports[p]->protocol = type;
}

uint8_t espArtNetRDM::getProtocolType(uint8_t g, uint8_t p)
{
	return _art->group[g]->ports[p]->protocol;
}

