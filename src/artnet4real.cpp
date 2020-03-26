#include "artnet4real.h"

namespace an4r::artnet {


// Internal packet processing and callback handles, hidden from header.
// Must be initialized with ptr to Driver.
struct Driver::Process {
  Driver* self;

  OpCode onPacket(OpCode opCode, uint8_t* data, size_t length);
  void poll(packet::art::Poll*);
  void pollReply(packet::art::PollReply*);
	void dmx(packet::art::DMX*);
	void ipProg(packet::art::IpProg*);
	void ipProgReply(); // doesnt belong here
	void address(packet::art::Address*);
	void sync(packet::art::Sync*);
	void firmwareMaster(uint8_t*); //(packet::art::FirmwareMaster*);
	void todRequest(packet::art::TODRequest*);
	void todControl(packet::art::TODControl*);
	void rdm(packet::art::RDM*, uint16_t);
	void rdmSub(uint8_t*);
} process;

  // void Driver::setArtDMXCallback(ArtDMXCallback cb)            { dmxCallback = cb; }
  // void Driver::setArtSyncCallback(ArtSyncCallback cb)          { syncCallback = cb; }
  // void Driver::setArtRDMCallback(ArtRDMCallback cb)            { rdmCallback = cb; }
  // void Driver::setArtIPCallback(ArtIPCallback cb)              { ipCallback = cb; }
  // void Driver::setArtAddressCallback(ArtAddressCallback cb)    { addressCallback = cb; }
  // void Driver::setTODRequestCallback(ArtTodRequestCallback cb) { todRequestCallback = cb; }
  // void Driver::setTODFlushCallback(ArtTodFlushCallback cb)     { todFlushCallback = cb; }


Driver::Driver(const char* shortName, const char* longName, uint16_t oem, uint16_t esta):
  names(shortName, longName), deviceInfo(oem, esta, 0) {
    process.self = this;
  } //still makes sense having a sep init so can eg create then wait until online and got IP, and is needed before actual allocs etc

void Driver::init(const IPAddress& ip, const IPAddress& subnet, uint8_t* mac, bool dhcp) {
  network = DeviceNetwork(ip, subnet, mac, true);
}

void Driver::setDefaultIP() {
  auto oem = deviceInfo.oem;

	uint8_t b = network.mac[3] + (uint8_t)oem + (uint8_t)(oem >> 8);
	uint8_t c = network.mac[4];
	uint8_t d = network.mac[5];
  network = DeviceNetwork(IPAddress(2, b, c, d),
                          IPAddress(255, 0, 0, 0),
                          network.mac.data());
}

uint8_t Driver::addGroup(uint8_t net, uint8_t subnet) {
  size_t index = groups.size();
  groups.emplace_back(std::make_unique<Group>(index, net, subnet));
  return index;
}

int Driver::addPort(uint8_t g, uint8_t p, uint8_t portAddr, PortMode t) {
  if(portAddr > 15 || p >= protocol::numPorts || g >= groups.size())
    return -1;
  return groups[g]->addPort(p, portAddr, t); // tho really nothing wrong with interfacing closer to actual groups ooor
} // nah have to be able to make them fully invisible and just think universes.

bool Driver::closePort(uint8_t g, uint8_t p) {
	if (!getPort(g, p)) return false; //seems off? if reply means "yup port was/is now closed"
  groups[g]->closePort(p);
	return true;
}

// void Driver::pause() { }

// dont finish this bs now but yeah: hides impl from header without allout pimpl madness,
// also makes clearer in fns what is passed/created and accessed.
//
// - clean ctors alt for all packets
// - apart from ctor prefer ext helpers for packets
// - packets go in their own header
// - enums and bs helper class fucks apart
// - figure out neat Port supremacy userfacing
//


int Driver::onPacket(IPAddress ip, uint8_t* data, size_t length) { // also not for here but baby steps
  static uint64_t counter = 0; counter++;
  static uint64_t rawCounter = 0; rawCounter++;
  static uint64_t malformed = 0xFFFF;

  if(ip == INADDR_NONE) {
    // uint8_t mac[7]{0};
    // packet.remoteMac(mac);
    // Serial.printf("mac: %2x %2x %2x %2x %2x %2x\n",
    //     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    Serial.printf("Weird packet: %s\n", ip.toString().c_str() );

    sendPacket(network.broadcastIP, data, length);
    Serial.println("Weird shit, see wireshark");
    return ++malformed;
  }

	if(length > 0 && length <= protocol::bufferMax) {
    auto header = reinterpret_cast<packet::art::HeaderExt*>(data);
    if(header->protocolVer < 14) {
      return -14; // TODO log some error
    }
    // lastRemoteIP.initOrUpdate(ip, true);
    lastRemoteIP = ip;
    // return onPacket(header->opCode, data, length);
    return process.onPacket(header->opCode, data, length);
  }
  return -1;
}

// side effects may vary - should signal somehow that PollReply is different...
// then again they all ("must") use existing state (made explicit through self->
// and hopefully further minimized as go along) so eh.
// no ok, here's the point: pollreply only one not strictly called from this dispatch fn
// and doesnt process nuffin.
// hence it shouldn't be here? or rather, vary naming. We DO need an incoming-not-outgoing
// pollreply fn so...
OpCode Driver::Process::onPacket(OpCode opCode, uint8_t* data, size_t length) {
  switch((uint16_t)opCode) { // avoid missing cases warning
    case OpPoll:           poll(reinterpret_cast<packet::art::Poll*>(data)); break;
    case OpPollReply:      pollReply(reinterpret_cast<packet::art::PollReply*>(data)); break;
    case OpDmx:            dmx(reinterpret_cast<packet::art::DMX*>(data)); break;
    case OpIpProg:         ipProg(reinterpret_cast<packet::art::IpProg*>(data)); break;
    case OpAddress:        address(reinterpret_cast<packet::art::Address*>(data)); break;
    case OpSync:           sync(reinterpret_cast<packet::art::Sync*>(data)); break;
    case OpFirmwareMaster: firmwareMaster(data); break;  // parse then send to reg updater process.
    case OpTodRequest:     todRequest(reinterpret_cast<packet::art::TODRequest*>(data)); break;
    case OpTodControl:     todControl(reinterpret_cast<packet::art::TODControl*>(data)); break;
    case OpRdm:            rdm(reinterpret_cast<packet::art::RDM*>(data), length); break;
    case OpRdmSub:         rdmSub(data); break;
    case OpCommand:        break;
    case OpInput:          break; // toggle inputs state
  }
  return opCode;
}


void Driver::Process::poll(packet::art::Poll* packet) {
  // TODO store the talktome bs
  self->sendPollReply();
}

void Driver::Process::pollReply(packet::art::PollReply* packet) {
  for(auto& uni: packet->activeInputs()) { // feels like OLA is backwards.  it advertises its inputs as outputs?
    // here we COULD look at status2 portAddress15Bit bit well we should, really.
    // but OLA pos fucking sets it despite lacking support (? seems even more limited - 16 unis...) so doesnt help there specifically...
    // Serial.printf("Receiver: %u\n", uni.address);
    auto* port = Port::atAddress(uni);   // meaning must be I'm thinking backwards.
    // or more like, it depends on whether config is in/out/hub
    if(port) port->receivers.insert(packet->ip); // reckon should be bindip? but eg LumiNetMonitor doesnt put correct one, but 0.0.0.0...
    // oh wait should be senders after all not raw ip, bc need to process timeouts...
  }
  // also premature opt but other benefit i guess of central reg,
  // already know about receivers before adding port -> comes on instant.
  // haha xtupid
  // in any case should check lapsing periodically and not on-send
  // then wont be a prob even w humongous amts.
}


void Driver::sendPollReply() {
	for(auto& group: groups) {
		if(group->ports.empty()) continue;

    auto packet = packet::art::PollReply(network, names, deviceInfo, *group);
    nodeReport.toBuffer(packet.nodeReport); // Set reply code

		for(auto& port: group->ports) { // Port details
      int p = port->index;
      packet.type[p].mode = port->portType;
			if(port->portType == PortArtnetIn || port->portType == PortArtnetHub) {               // DMX In port packet
				packet.swIn[p]                    = port->addr.portAddr; //
        packet.goodInput[p].receivingData = true;      //
			}
      if(port->portType == PortArtnetOut || port->portType == PortArtnetHub) {        // DMX or RDM out port
				packet.swOut[p]                   = port->addr.portAddr;  // swOut - port address
        packet.goodOutput[p].isMerging    = port->merge; // will distill to bool no?
        packet.goodOutput[p].mergeLPT     = !port->mergeHTP;
        packet.goodOutput[p].sendingData = true;      //
				if(port->protocol != ARTNET)
          packet.goodOutput[p].sacn = true;        // sACN. Should stay in whether or not lib retains support - artnet itself supports flag.
			}
		}
    sendPacket(network.broadcastIP, &packet);
	}
}


static int _handleAndGetSender(Port* port, IPAddress rIP) {
	int senderID = -1;  // Will be set to 0 or 1 if valid later
  for(int i=0; i<=1; i++) { // expire lapsed sender. Shouldnt we try to update first tho lol give it better chance to not expire
    port->sender[i].letTimeoutIfExpired();
  }
  for(int i=1; i>=0; i--) { // guess we start trying to fill 1
    if(port->sender[i].initOrUpdate(rIP)) {
      senderID = i; break;
    }
  }
  // Serial.printf("IP: %s, id: %d\n", rIP.toString().c_str(), senderID);
  return senderID; // if(senderID == -1) return ; // Unseen IP, so drop packet (Artnet v4 only allows for merging 2 DMX streams - but time out)
}


// XXX FIGURE OUT:
// when not receiving data ping goes up to like 200ms.
// down again right away when something's sending.
void Driver::Process::dmx(packet::art::DMX* packet) {

  auto addr = Universe(packet->subUni, packet->net);
  auto port = Port::atAddress(addr);
  // if(!port || port->portType != PortArtnetOut) // per below/prev which continues/skips on artnetin.
  if(!port) {
    Serial.printf("Unrequested Dmx packet at subuni %d \n", addr.subUni);
    return; // no match! thro some error...
  } else if(port->portType != PortArtnetIn && port->portType != PortArtnetHub) {
    Serial.printf("Port not input: %d \n", addr.subUni);
  // } else if(port->portType != PortArtnetOut) {
  //   Serial.printf("Port not output: %d \n", addr.subUni);
  }

  int senderID = _handleAndGetSender(port, self->lastRemoteIP.ip);
  if(senderID < 0) return; // both slots full, and ip not recognized.

  // bool multipleSenders = (port->sender[(senderID ^ 0x01)].ip != INADDR_NONE); // Check if we're merging (the other IP will be non zero)
  bool multipleSenders = (port->sender[(senderID ^ 0x01)]); // Check if we're merging (the other IP will be non zero)
  if(multipleSenders) {
    if(port->group->sourceLock)
      port->group->sourceLock.letTimeoutIfExpired();
    else
      port->setMerge(true); // noop if already active, not HTP, etc
  }
  // further fuck this off to w/e processing tho... 1. update group mc state
  // it tells ports. etc. only doing this here bc timeout stuff + a cancel request supposed to flush on next dmx frame...
  // REALLY must fix naming on letTimeoutIfExpired... updateAndSetState
	if(port->merge) { //makes more sense
		// if(port->group->sourceLock.isOwner(port->sender[senderID].ip)) { // This is the correct IP, enable cancel merge
		if(port->group->sourceLock == port->sender[senderID]) { // This is the correct IP, enable cancel merge
			port->setMerge(false); // dtors go boom XXX and then nuke the other sender IP I guess and also blacklist it or what

		// } else if(port->group->sourceLock.active) { // If the merge cancel is imminent but IP isn't correct, ignore this packet
		} else if(port->group->sourceLock) { // If the merge cancel is imminent but IP isn't correct, ignore this packet
        // return;
    }
	}

  // port->dmxChans = std::max(port->dmxChans, length); // update size if has grown...
  bool sync = false;
	if (multipleSenders) {     // XXX here we might well re-enable merge _JUST_ after having cancelled.
    // port->setMerge(true); // noop if already active, not HTP, etc
	} else { // No merge: copy data directly into output buffer
    sync = (!self->syncSender.letTimeoutIfExpired() &&
             // self->syncSender.ip == self->lastRemoteIP.ip); // Check if Sync is enabled - XXX fix
             self->syncSender == self->lastRemoteIP); // Check if Sync is enabled - XXX fix
	}
  port->updateBuffer(packet->data, packet->dmxDataLen(), senderID); //sender discarded if merging.

  // self->lastDmxFrameSender.initOrUpdate(self->lastRemoteIP.ip, true);
  self->lastDmxFrameSender = self->lastRemoteIP;
  if(self->dmxCallback)
    // dmxCallback(port->group->index, port->index, packet->dmxDataLen(), false); // temp
    self->dmxCallback(port->group->index, port->index, packet->dmxDataLen(), sync);
}


uint8_t* Driver::getDMX(uint8_t g, uint8_t p) {
  auto port = getPort(g, p);
  return port? port->dmxBuffer.data(): nullptr;
}

void Driver::Process::ipProg(packet::art::IpProg* packet) {
  Serial.println("Got IPProg");
  static uint32_t lastCmdTime = 0;
	if (millis() < (lastCmdTime + 20)) return; // ignore duplicate requests
	lastCmdTime = millis();

  if(packet->programming) {
    auto& cfg = self->network;

    cfg.dhcp = packet->enableDHCP;

    if(packet->setCustomIP)
			cfg.ip = packet->ip;

    if(packet->setCustomSubnetMask) {
			cfg.subnet = packet->subMask;;
			cfg.broadcastIP = IPAddress((uint32_t)cfg.ip | ~((uint32_t)cfg.subnet));
		}

		if(packet->restoreToDefault)
			self->setDefaultIP();
  }

	if (self->ipCallback) self->ipCallback(); // Run callback - must be before reply for correct dhcp setting
	self->sendIPProgReply(); // Send reply
  self->sendPollReply();
}

void Driver::sendIPProgReply() {
  packet::art::IpProgReply packet{network};
  // sendPacket(lastRemoteIP.ip, &packet, sizeof(packet::art::IpProgReply));
  sendPacket(lastRemoteIP.ip, &packet);
}

void Driver::Process::address(packet::art::Address* packet) {
  Serial.println("Got ArtAddress");

  auto& group = self->groups.at(packet->bindIndex - 1);

	// if (packet->netSwitch.program) { // TODO Fix so is like this! Set net switch
		// group->netSwitch = packet->netSwitch.param;
	if((packet->netSwitch & 0x80) == 0x80) { // Set net switch
		// group->netSwitch = packet->netSwitch & 0x7F;
	}
  // TODO handle these through ArtNodeName...
  if(packet->names.shortName[0] != '\0'){};  // Set short name
  if(packet->names.longName[0] != '\0'){};  // Set long name

	// for (int x = 0; x < protocol::numPorts; x++) { // Set Port Address
	// 	if (((data[100 + x] & 0xF0) == 0x80) && group->ports[x])
	// 		group->ports[x]->addr.portAddr = data[100 + x] & 0x0F;
	// }

	// if ((packet.subSwitch & 0xF0) == 0x80) { // Set subnet
	// 	group->subSwitch = packet.subSwitch & 0x0F;
	// }

	// Get port number
	// uint8_t p = packet->command & 0x0F; // extract port from Command - dangerous bc not all are even port/index based
  try {
    auto ac = packet->command;
    int p = ac.getAndClearPortIndex(); // so ugly
    // if(ac.cmd >= Ac::MergeLtp) { // is port-indexed cmd
    //   p = ac.port, ac.port = 0; // cleave off index so can use base
    // }
    // auto ac = packet->command;
    // int p = 0;
    // if(ac.cmd >= Ac::MergeLtp) { // is port-indexed cmd
    //   p = ac.port, ac.port = 0; // cleave off index so can use base
    // }
    auto& port = *(group->ports.at(p)); // much dumber way than & 0x0F but whatever i lurv

    switch (ac.cmd) { // (Possible truncated) Command

    case Ac::None: break;
    case Ac::CancelMerge: { // a sender has requested we stop merging in the other sender
      group->sourceLock.start(self->lastRemoteIP.ip); break; // what if busy?
    }
    case Ac::LedNormal: case Ac::LedMute: case Ac::LedLocate: break;
    case Ac::ResetRxFlags: break;
    case Ac::AnalysisOn: case Ac::AnalysisOff:  break;

    case Ac::MergeLtp: {
      port.setMerge(false);
      // port.sender[0].timeStamp = 0; // "latest" is a question for the future.
      // port.sender[1].timeStamp = 0;
			port.mergeHTP = false; // Set to LTP
      group->sourceLock.stop(); // tho isnt it overridding this stuff or?
      break;
    }
    case Ac::MergeHtp: {
			port.mergeHTP = true; // Set to HTP
      group->sourceLock.stop(); // rly?
      break;
    }
    case Ac::ClearOp: {
      port.setMerge(false); // memset(port->dmxBuffer, 0, DMX_BUFFER_SIZE);
      break;
    }
    case Ac::ArtNetSel: { // if(port) setProtocolType(g, p, protocol_type::ARTNET);
      break;
    }
    case Ac::AcnSel: { // if(port) setProtocolType(g, p, protocol_type::SACN_UNICAST);
      break;
    }
  }
  } catch(std::out_of_range& e) {
    // not our problem. guess send diag tho
  }
  self->sendPollReply();
	if(self->addressCallback) self->addressCallback();
}

void Driver::Process::sync(packet::art::Sync* packet) {
  Serial.println("Got ArtSync");
  // self->syncSender.initOrUpdate(self->lastRemoteIP.ip); // should force tho I guess or?
  self->syncSender = self->lastRemoteIP; // should force tho I guess or?
  // ip must be same as last dmx packet. Sync is ignored when merging.
	if(self->syncCallback && self->lastDmxFrameSender == self->lastRemoteIP) // && merge handled since dmx recv fn not passing sync status on unless !murge
		self->syncCallback();
}

void Driver::Process::firmwareMaster(uint8_t* data) {
	Serial.println("artFirmwareMaster");
}

void Driver::Process::todRequest(packet::art::TODRequest* packet) {
  Serial.println("Got TODRequest");

  for(int i=0; i < packet->adCount; i++) {
    auto* port = Port::atAddress(Universe(packet->address[i], packet->net)); // XXX wrong i think, switched from subuni to subswitch...
    if(!port) continue;
    port->tod.lastCommandTime = millis();

    if(self->todRequestCallback)
      self->todRequestCallback(port->group->index, port->index);
    // but mostly need to fucking respond and that?
  }
}

// XXX this one is a massive mess (on top of being broken). fix the poor fucker.
// void Driver::artTODData(Port* port, std::vector<RdmUid>& devices,
void Driver::artTODData(Port* port, uint16_t* uidMan, uint32_t* uidDev,
                              uint16_t uidTotal, uint8_t state) {

  // packet::art::TODData packet{port, state, uidTotal}; // should be recreated so dont reuse garbage

  uint16_t uidRemaining = uidTotal;
	uint8_t blockCount = 0;
	do { // fill device slots up to maximum allowed per packet - send multiple packets if needed
    packet::art::TODData packet{port, state, uidRemaining};
		packet.blockCount = blockCount;
		// packet.uidCount   = std::clamp(uidTotal, (uint16_t)0, packet::art::TODData::maxUidCount);
		packet.uidCount   = std::clamp(uidRemaining, (uint16_t)0, packet::art::TODData::maxUidCount);

		// uint8_t uidCount = 0;
		// for(int i = 0;
		for(int i = 0;
         i < packet::art::TODData::maxUidCount && uidRemaining > 0;
         i++, uidRemaining--) {
      packet.device[i] = RdmUid(uidMan[uidRemaining], uidDev[uidRemaining]); // well this way goes backwards. no official directiiiiiiion tho i suppose heh
		}

    sendPacket(network.broadcastIP, &packet, packet.getLength());
		blockCount++;
	} while(uidTotal != 0);
}

void Driver::Process::todControl(packet::art::TODControl* packet) {
  Serial.println("Got TODControl");
  auto* port = Port::atAddress(Universe(packet->address, packet->net));
  if(!port) return;
  port->tod.lastCommandTime = millis();

  if(packet->command == packet::art::TODControl::Flush && self->todFlushCallback) { // None and Flush only commands...
    self->todFlushCallback(port->group->index, port->index);
  }
}

// RDM / response diff layout?
void Driver::Process::rdm(packet::art::RDM* packet, uint16_t packetSize) {
  Serial.println("Got RDM");
	if (!self->rdmCallback) return;

  // packet::RdmData c{}; // Get RDM data into out buffer ready to send
	// c.buffer[0] = 0xCC;
	// memcpy(&c.buffer[1], packet->data, data[25] + 2); // ?? 25, das inside data buffer

  auto* port = Port::atAddress(Universe(packet->address, packet->netSwitch));
  if(!port) return;
  // XXX first flip 16s and that...
  self->rdmCallback(port->group->index, port->index, &packet->rdmData);

  bool ipSet = false;
  for(auto& sender: port->rdmSender) {
    // const int rdmTimeout = 200; // ms.  Check when last packets received.  Clear if over 200ms
    // sender.letTimeoutIfExpired(rdmTimeout); // they should be created with this timeout tho
    sender.letTimeoutIfExpired(); // they should be created with this timeout tho

    // if(ipSet || (sender.ip != INADDR_NONE && sender.ip != self->lastRemoteIP.ip))
    if(ipSet || (sender && sender != self->lastRemoteIP))
      continue; //  Bail if already set, or uh slot already set and is not free

    sender = self->lastRemoteIP; // Save the IP.
    ipSet = true;
  }
}

void Driver::sendRdmResponse(packet::rdm::RdmData* c, Port* port) {
  Serial.println("Sending RdmResponse");
	uint16_t len = protocol::rdmReplySize + c->packet.length + 1;
  packet::art::RDM packet(c, port);

	for(auto& sender: port->rdmSender) {
		if(sender) { // if(sender.ip != INADDR_NONE) {
      sendPacket(sender.ip, &packet, len);
		}
	}
}

void Driver::Process::rdmSub(uint8_t* data) {
  Serial.println("artRDMSub");
}

void Driver::setIP(IPAddress ip, IPAddress subnet) {
	network.ip = ip;
	if ((uint32_t)subnet != 0)
		network.subnet = subnet;
	network.broadcastIP = IPAddress((uint32_t)network.ip | ~((uint32_t)network.subnet));
  // and send out pollreply?...
}

//whatever this just to replace old useless fns g / p is dumb.
Universe Driver::getAddr(uint8_t groupIndex, int portIndex) {
  auto addr = groups.at(groupIndex)->addr;
  if(portIndex >= 0 && portIndex < 4)
    addr = groups.at(groupIndex)->ports.at(portIndex)->addr;
  return addr;
}


void Driver::setPortType(uint8_t g, uint8_t p, PortMode t) {
	if (!getPort(g, p)) return;
	getPort(g, p)->portType = t;
}


void Driver::setShortName(char* name) { names.setShort(name); }
void Driver::setLongName(char* name) { names.setLong(name); }
char* Driver::getShortName() { return names.shortName; }
char* Driver::getLongName() { return names.longName; }

void Driver::setNodeReport(char* c, RC code) { nodeReport.update(c, code); }


static uint8_t getSeqID() {
  static uint8_t _dmxSeqID = 0; // 0 not used. and XXX isnt this per group/port if anything or?
  if(++_dmxSeqID != 0)
    return _dmxSeqID;
  return ++_dmxSeqID;
}

void Driver::sendDMX(uint8_t g, uint8_t p, uint8_t* data, uint16_t length) {
  auto* port = getPort(g, p);
	if(port == nullptr || port->receivers.empty())
    return;

	if(length % 2)   length++; // length is always even and up to 512 channels
	if(length > 512) length = 512;
	port->dmxChans = length;

  packet::art::DMX packet{getSeqID(), port, data, length};

  const uint8_t headerLength = 18;
  // auto receivers = port->receivers.size() < 40? port->receivers: {network.broadcastIP};
  // auto receivers = port->receivers.size() < 40? port->receivers: network.broadcastIP;
  // if(port->receivers.size() >= 40) { // broadcast
  //   sendPacket(network.broadcastIP, &packet, (headerLength + length));
  // } else {
    // for(auto& ip: port->receivers)
    for(auto& ip: port->receivers.size() < 40?
                  port->receivers:
                  std::initializer_list({network.broadcastIP})) // p sweet bruh
      sendPacket(ip, &packet, (headerLength + length));
  // }
}

// void Driver::setProtocolType(uint8_t g, uint8_t p, uint8_t type) {
//   auto port = getPort(g, p);
// 	if(!port) return;

// 	// Increment or decrement our e131Count variable if the universe was artnet before and is now sACN
// 	if (port->protocol == ARTNET && type != ARTNET) {
// 		// memset(port->dmxBuffer, 0, DMX_BUFFER_SIZE);
// 	}  // if it was not an sACN before and it is an ArtNet now => decrement
// 	else if (port->protocol != ARTNET && type == ARTNET) {
// 		// memset(port->dmxBuffer, 0, DMX_BUFFER_SIZE);
// 	}
// 	getPort(g, p)->protocol = type;
// }

// uint8_t Driver::getProtocolType(uint8_t g, uint8_t p) { return getPort(g, p)->protocol; }

} // end ns an4
