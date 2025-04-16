#include "artnet4real.h"

namespace anfr {


// Internal packet processing and callback handles, hidden from header.
// Must be initialized with ptr to Driver.
struct Driver::Process {
  Driver* self;

  OpCode onPacket(OpCode opCode, uint8_t* data, size_t length);
  void poll(packet::art::Poll*);
  void pollReply(packet::art::PollReply*);
  IPSender lastDmxFrameSender; // gets set on successful dmx packet recv
	void dmx(packet::art::DMX*);
	void ipProg(packet::art::IpProg*);
	void ipProgReply(); // doesnt belong here
	void address(packet::art::Address*);
  IPSender syncSender;
	void sync(packet::art::Sync*);
	void firmwareMaster(uint8_t*); //(packet::art::FirmwareMaster*);
	void todRequest(packet::art::TODRequest*);
	void todControl(packet::art::TODControl*);
  void todData(packet::art::TODData*);
	void rdm(packet::art::RDM*, uint16_t);
	void rdmSub(uint8_t*);
} process;



Driver::Driver(const char* shortName, const char* longName, uint16_t oem, uint16_t esta):
  names(shortName, longName), deviceInfo(oem, esta, 0) {
    process.self = this;
  } //still makes sense having a sep init so can eg create then wait until online and got IP, and is needed before actual allocs etc


void Driver::init(IPv4 ip, IPv4 subnet, uint8_t* mac, bool dhcp) {
  network = DeviceNetwork(ip, subnet, mac, dhcp);
}

void Driver::setDefaultIP() {
  auto oem = deviceInfo.oem;

  // XXX but now presumably presumes init has been called... or will be 0 plus some weird shit for mac?
	uint8_t b = network.mac[3] + (uint8_t)oem + (uint8_t)(oem >> 8);
	uint8_t c = network.mac[4];
	uint8_t d = network.mac[5];
  network = DeviceNetwork(IPv4(2, b, c, d),
                          IPv4(255, 0, 0, 0),
                          network.mac.data());
}

Group* Driver::addGroup(uint8_t net, uint8_t subnet) { // these are backwards from Universe ctor btw
  size_t index = groups.size();
  groups.push_back(std::make_unique<Group>(index, net, subnet, deviceInfo));
  return groups[index].get(); // return index;
}

Group* Driver::addGroup(Universe baseAddr) {
  return addGroup(baseAddr.netSwitch, baseAddr.subSwitch);
}

int Driver::addPort(uint8_t g, uint8_t p, uint8_t portAddr, PortMode t) {
  if(portAddr > 15 || p >= def::numPorts || g >= groups.size())
    return -1; // XXX or rather throw?
  return groups[g]->addPort(p, portAddr, t); // tho really nothing wrong with interfacing closer to actual groups ooor
} // nah have to be able to make them fully invisible and just think universes.

// Port* addPort(Universe& universe, PortMode type = PortArtnetIn) {

// }

bool Driver::closePort(uint8_t g, uint8_t p) {
	if (!getPort(g, p)) return false; //seems off? if reply means "yup port was/is now closed"
  groups[g]->closePort(p);
	return true;
}

std::vector<Port*>& Driver::setupBulkInputs(Universe baseAddr, uint8_t* dataStart, size_t bytes) {
  // so to start wont account for existing shit...
  // auto portCount = bytes / def::dmxBufferSize; // + 1, fairly likely... 513/512 = 1, should be 2. but 512/512 = 1 should be 1 argh!
  auto portCount = 1 + --bytes / def::dmxBufferSize; // + 1, fairly likely... 513/512 = 1, should be 2. but 512/512 = 1 should be 1 argh!
  Group* group;
  uint8_t* ptr = dataStart;
  Universe addr = baseAddr;
  for(int p=0; p < portCount; p++) {
    auto gp = p % def::numPorts; 				// mod p to 0-3 and keep adding groups to accommodate ports
		if(gp == 0) { 											// group needed
			// group = addGroup(baseAddr);       // XXX shouldn't this increment???
			group = addGroup(addr);           // more reasonable?
		}
    if(group) // well there'd be other checks afa capacity but... 
      // group->addPort(gp, addr++.portAddr, PortArtnetIn, ptr); // still think gotta re(re)name In/out right? Input gateway turns HW dmx into Artnet. Output turns artnet to DMX (or, primarily in my case, strip-bs)
      group->addPort(gp, addr++.portAddr, PortArtnetOut, ptr); // still think gotta re(re)name In/out right? Input gateway turns HW dmx into Artnet. Output turns artnet to DMX (or, primarily in my case, strip-bs)
    ptr += def::dmxBufferSize;
  }

  return Port::allPorts;
}


int Driver::onPacket(IPv4 ip, uint8_t* data, size_t length) { // mostly debug stuff, in future malformed/error/attack mitigation? not that should be needed hah
  static uint64_t malformed = 0;

  if(*ip == INADDR_NONE) {
    sendPacket(network.broadcastIP, data, length);
    logf("Weird shit INADDR_NONE, see wireshark\n");
    return ++malformed;
  }
  if(*ip == INADDR_NONE) {
    sendPacket(network.broadcastIP, data, length);
    logf("Weird shit INADDR_ANY, see wireshark\n");
    return ++malformed;
  }

	if(length > 0 && length <= def::bufferMax) {
    auto header = reinterpret_cast<packet::art::HeaderExt*>(data);
    if(header->protocolVer < 14) {
      return -14; // TODO log some error
    }
    lastRemoteIP = ip;
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
  switch(opCode) { // avoid missing cases warning
    case OpPoll:           poll(reinterpret_cast<packet::art::Poll*>(data)); break;
    case OpPollReply:      pollReply(reinterpret_cast<packet::art::PollReply*>(data)); break;
    case OpDmx:            dmx(reinterpret_cast<packet::art::DMX*>(data)); break;
    case OpIpProg:         ipProg(reinterpret_cast<packet::art::IpProg*>(data)); break;
    case OpAddress:        address(reinterpret_cast<packet::art::Address*>(data)); break;
    case OpSync:           sync(reinterpret_cast<packet::art::Sync*>(data)); break;
    case OpFirmwareMaster: firmwareMaster(data); break;  // parse then send to reg updater process.
    case OpTodRequest:     todRequest(reinterpret_cast<packet::art::TODRequest*>(data)); break;
    case OpTodControl:     todControl(reinterpret_cast<packet::art::TODControl*>(data)); break;
    case OpTodData:        todData(reinterpret_cast<packet::art::TODData*>(data)); break;
    case OpRdm:            rdm(reinterpret_cast<packet::art::RDM*>(data), length); break;
    case OpRdmSub:         rdmSub(data); break;
    case OpCommand:        break;
    case OpInput:          break; // toggle inputs state
    default:               break;
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
    // logf("Receiver: %u\n", uni.address);
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
			auto type = port->portType;
      packet.type[p].mode = port->portType;
			if(type == PortArtnetIn || type == PortArtnetHub) {  // DMX In port packet
				packet.swIn[p]                    = port->addr.portAddr; //
        packet.goodInput[p].receivingData = true;      //
			}
      if(type == PortArtnetOut || type == PortArtnetHub) { // DMX or RDM out port
				packet.swOut[p]                   = port->addr.portAddr;  // swOut - port address
        packet.goodOutput[p].isMerging    = port->merge; // will distill to bool no?
        packet.goodOutput[p].mergeLPT     = !port->mergeHTP;
        packet.goodOutput[p].sendingData = true;      //
				if(port->protocol != ARTNET)
          packet.goodOutput[p].sacn = true;        // sACN. Should stay in whether or not lib retains support - artnet itself supports flag.
			}
		}
    // logf("send artnet pollreply");
    sendPacket(network.broadcastIP, &packet);
    sendPacket(process.self->lastRemoteIP.ip, &packet);
    // logf("did send artnet pollreply");
	}
}


static Port::SenderID handleAndGetSender(Port* port, IPv4 rIP) {
  for(auto& sender: port->sender)
    sender.update(); 
  for(int i=Port::SenderID::Primary; i <= Port::SenderID::Last; i++) { // port->sender.size()
    int otheridx = (int)!i; // well would break if had more slots but
    if(!(rIP == port->sender[otheridx].ip) && (uint32_t)rIP != INADDR_ANY && // check ip not that of potential other sender
    // if(!(rIP == port->sender[otheridx].ip) &&  // check ip not that of potential other sender
         port->sender[i].initOrRefresh(rIP)) {
      return static_cast<Port::SenderID>(i);
    }
  } // logf("IP: %s, id: %d\n", rIP.toString().c_str(), senderID);
  return Port::SenderID::Invalid; // if(senderID == -1) return ; // Unseen IP, so drop packet (Artnet v4 only allows for merging 2 DMX streams - but time out)
}


// XXX FIGURE OUT:
// when NOT receiving data ping goes up to like 200ms.
// down again right away when something's sending to us.
// aaand then it stopped before I could figure it out. So beware return.
// Could the coming and going be dep on which core we end up?
// Since async_udp (all arduino shit really) seems pinned by default...
void Driver::Process::dmx(packet::art::DMX* packet) {

  auto addr = Universe(packet->subUni, packet->net);
  auto port = Port::atAddress(addr);
  if(!port) {
    logf("Unrequested Dmx packet at subuni %d \n", addr.subUni);
    return; // no match! thro some error...
  // } else if(port->portType != PortArtnetIn && port->portType != PortArtnetHub) {
  } else if(port->portType != PortArtnetOut && port->portType != PortArtnetHub) { // XXX seems I misunderstood in and out
    logf("Port not input: %d \n", addr.subUni);
  }

  auto senderIdx = handleAndGetSender(port, self->lastRemoteIP.ip);
  if(senderIdx == Port::SenderID::Invalid) return; // both slots full, and ip not recognized.
  // logf("Sender idx: %d, ip: %d\n", senderIdx, port->sender[senderIdx].ip[0]);

  bool multipleSenders = (port->sender[(int)!(int)senderIdx]); // Check if we're merging (the other IP will be non zero)
  if(multipleSenders) { // potential merge situation
    bool mightBeMerging = true;

    port->group->sourceLock.update();
    if(port->group->sourceLock) { // cancelMerge in effect
      if(port->group->sourceLock.ip != port->sender[senderIdx].ip)
        return;                   // from other sender -> discard data
      else
        mightBeMerging = false;   // from this sender -> dont merge, but accept data
    }

    logf("Multiple senders, %d.%d.%d.%d, %d.%d.%d.%d",
        port->sender[0].ip[0], port->sender[0].ip[1], port->sender[0].ip[2], port->sender[0].ip[3],
        port->sender[1].ip[0], port->sender[1].ip[1], port->sender[1].ip[2], port->sender[1].ip[3]);
    port->setMerge(mightBeMerging); // noop if already active, not HTP, etc. Else creates merge struct with additional buffers etc. Or nukes it...
  }                                // also to consider if this is to have any point: what to do if running out of memory... disabling merging makes sense, but could first move to reusing endstate buf or w/e all highly pointless to fret over at this point lol
  else {
    // logf("Single sender %d.%d.%d.%d", self->lastRemoteIP.ip[0], self->lastRemoteIP.ip[1], self->lastRemoteIP.ip[2], self->lastRemoteIP.ip[3]);
  }

  bool deferFlush = false;
  if(!port->merge) { // potential sync situation
    syncSender.update();
    deferFlush = (syncSender == self->lastRemoteIP); // tbh should prob keep both checks just for clarity...
  }

  port->updateBuffer(packet->data, packet->dmxDataLen(), senderIdx); //senderID discarded if not merging.

  lastDmxFrameSender = self->lastRemoteIP; // lastRemoteIP needs to go though. Pass it along!!
  if(self->dmxCallback)
    self->dmxCallback(port->group->index, port->index, port->bufRaw,
                      packet->dmxDataLen(), deferFlush);
}


void Driver::Process::ipProg(packet::art::IpProg* packet) {
  logf("Got IPProg\n");
  static uint32_t lastCmdTime = 0;
	if (uptimeMs() < (lastCmdTime + 20)) return; // ignore duplicate requests
	lastCmdTime = uptimeMs();

  if(packet->programming) {
    auto& cfg = self->network;

    cfg.dhcp = packet->enableDHCP;

    if(packet->setCustomIP)
			cfg.ip = packet->ip;

    if(packet->setCustomSubnetMask) {
			cfg.subnet = packet->subMask;
			cfg.broadcastIP = IPv4((uint32_t)cfg.ip | ~((uint32_t)cfg.subnet));
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
  sendPacket(lastRemoteIP.ip, &packet);
}

void Driver::Process::address(packet::art::Address* packet) {
  logf("Got ArtAddress\n");

  try { // here (and elsewhere?) def should refrain from letting crash on unexpected data hahah.
    auto& group = self->groups.at(packet->bindIndex - 1);

	// if (packet->netSwitch.program) { // TODO Fix so is like this! Set net switch
		// group->netSwitch = packet->netSwitch.param;
	if((packet->netSwitch & 0x80) == 0x80) { // Set net switch
		// group->netSwitch = packet->netSwitch & 0x7F;
	}
  // TODO handle these through ArtNodeName...
  if(packet->names.shortName[0] != '\0'){};  // Set short name
  if(packet->names.longName[0] != '\0'){};  // Set long name

	// for (int x = 0; x < def::numPorts; x++) { // Set Port Address
	// 	if (((data[100 + x] & 0xF0) == 0x80) && group->ports[x])
	// 		group->ports[x]->addr.portAddr = data[100 + x] & 0x0F;
	// }

	// if ((packet.subSwitch & 0xF0) == 0x80) { // Set subnet
	// 	group->subSwitch = packet.subSwitch & 0x0F;
	// }

  auto ac = packet->command;
  int p = ac.getAndClearPortIndex(); // so ugly
  auto& port = group->ports.at(p); // much dumber way than & 0x0F but whatever i lurv

	switch(ac.cmd) { // (Possible truncated) Command

    case Ac::None: break;
    case Ac::CancelMerge: { // a sender has requested we stop merging in the other sender
      // group->sourceLock.start(self->lastRemoteIP.ip); break; // what if busy?
      group->sourceLock = self->lastRemoteIP; break;
    }
    case Ac::LedNormal: case Ac::LedMute: case Ac::LedLocate: break;
    case Ac::ResetRxFlags: break;
    case Ac::AnalysisOn: case Ac::AnalysisOff:  break;

    case Ac::MergeLtp: {
			port->mergeHTP = false; // Set to LTP
      port->setMerge(false);
      for(auto& sender: port->sender)
        // sender.timeStamp = 0; // doesnt seem necessary? also it'd be...
        sender.reset(); // I guess
      group->sourceLock.reset(); // tho isnt it overridding this stuff or?
      break;
    }
    case Ac::MergeHtp: {
			port->mergeHTP = true; // Set to HTP
      group->sourceLock.reset(); // rly?
      break;
    }
    case Ac::ClearOp: {
      port->setMerge(false);
      break;
    }
    [[fallthrough]]
    case Ac::ArtNetSel:
    case Ac::AcnSel: {
      port->protocol = ac.cmd; // well ehh bit confusing haha
      break;
    }
    default: break;
  }
  } catch(std::out_of_range& e) {
    // not our problem. guess send diag tho
  }
  self->sendPollReply();
	if(self->addressCallback) self->addressCallback();
}

void Driver::Process::sync(packet::art::Sync* packet) {
  logf("Got ArtSync\n");
  syncSender = self->lastRemoteIP;
  // ip must be same as last (successfully processed) dmx packet - Sync is ignored when merging.
	if(self->syncCallback && lastDmxFrameSender == self->lastRemoteIP)
		self->syncCallback();
}

void Driver::Process::firmwareMaster(uint8_t* data) {
	logf("artFirmwareMaster\n");
}

void Driver::Process::todRequest(packet::art::TODRequest* packet) {
  // logf("Got TODRequest\n");
  // if(!self->todRequestCallback) return;

  for(int i=0; i < packet->adCount; i++) {
    auto* port = Port::atAddress(Universe(packet->address[i], packet->net));
    if(!port) continue;
    port->tod.lastCommandTime = uptimeMs();
    self->sendTODData(port);
    if(self->todRequestCallback)
      self->todRequestCallback(port->group->index, port->index); // not sure what we'd actually do with this?
  }
}

void Driver::Process::todData(packet::art::TODData* packet) {
  // we use these to build up a table of devices (as well as processing RDM on physical ports...)
  // Really need to split/specify node/controller/etc stuff yo.
  auto* port = Port::atAddress(Universe(packet->address, packet->netSwitch));
  if(!port) return;
  port->tod.lastCommandTime = uptimeMs();
  for(int i=0; i < packet->uidCount; i++) {
    // port->tod.devices.insert(packet->device[i]);  // yeah gotta be a set yo...
    // super inefficient lol, fix... then again this isnt how it's supposed to even work so ;)
    auto it = std::find(port->tod.devices.begin(), port->tod.devices.end(),
												packet->device[i]);
    if(it != port->tod.devices.end())
      port->tod.devices.push_back(packet->device[i]);  // yeah gotta be a set yo...
  }
}

// XXX this one is a massive mess (on top of being broken). fix the poor fucker.
// void Driver::artTODData(Port* port, std::vector<RdmUid>& devices,
// void Driver::artTODData(Port* port, uint16_t* uidMan, uint32_t* uidDev,
//                         uint16_t uidTotal, uint8_t state) {
void Driver::sendTODData(Port* port) {
  // packet::art::TODData packet{port, state, uidTotal}; // should be recreated so dont reuse garbage

  uint16_t uidTotal = port->tod.devices.size();
  // if(uidTotal == 0) {
  //   packet::art::TODData packet{port, uidTotal};
  // }

  uint16_t uidRemaining = uidTotal;
	uint8_t blockCount = 0;
	do { // fill device slots up to maximum allowed per packet - send multiple packets if needed
    packet::art::TODData packet{port, uidTotal, blockCount};

		for(int i = 0; i < packet.uidCount && uidRemaining > 0; i++) {
      packet.device[i] = port->tod.devices[--uidRemaining]; // well this way goes backwards. no official directiiiiiiion tho i suppose heh
		// for(int i = 0; i < packet.uidCount && uidRemaining > 0;
                   // i++,                   uidRemaining--) {
      // packet.device[i] = port->tod.devices[uidRemaining - 1]; // well this way goes backwards. no official directiiiiiiion tho i suppose heh
		}
    sendPacket(network.broadcastIP, &packet, packet.getLength());
		blockCount++;
	} while(uidRemaining > 0);
}

void Driver::Process::todControl(packet::art::TODControl* packet) {
  logf("Got TODControl");
  auto* port = Port::atAddress(Universe(packet->address, packet->net));
  if(!port) return;
  port->tod.lastCommandTime = uptimeMs();

  if(packet->command == TODCommand::Flush && self->todFlushCallback) { // None and Flush only commands...
    self->todFlushCallback(port->group->index, port->index);
  }
}

// RDM / response diff layout?
void Driver::Process::rdm(packet::art::RDM* packet, uint16_t packetSize) {
  logf("Got RDM");
	// if (!self->rdmCallback) return;

  auto* port = Port::atAddress(Universe(packet->address, packet->netSwitch));
  if(!port) return;

  for(auto& sender: port->rdmSender)
    sender.update(); // ideally: find(sender) && refresh || init
  // auto it = std::find(port->rdmSender, port->rdmSender+4, self->lastRemoteIP);
  // if(it == port->rdmSender+4)
  //   it = std::find(port->rdmSender, port->rdmSender+4, INADDR_NONE);
  // it->initOrRefresh(self->lastRemoteIP.ip);
  for(auto& sender: port->rdmSender) {
    if(sender.initOrRefresh(self->lastRemoteIP.ip)) // will return false until either hits or initalizes
      break; // might cause duplicates tho again need some algorithm fu on this. Or general "think from spec not the old brain murdering code"
  }        // vector (well, map/set) + reserve/max size would generally work moore smarter than fixed slots and objs w null-state

  using namespace packet::rdm;
  auto resp = packet->rdmData;
  // resp.cmdClass += (int)ResponseOffset; // turn Discovery/Get/SetCommand into -Response.
  resp.packet.cmdClass = CmdClass((uint8_t)resp.packet.cmdClass
																	+ (uint8_t)CmdClass::ResponseOffset); // turn Discovery/Get/SetCommand into -Response.

  switch(resp.packet.pid) {
    case PID::SupportedParameters: {
        auto list = {PID::DeviceInfo, PID::DeviceLabel, PID::UNSUPPORTED_ID};
        int b = 0; for(auto& item: list) {
          (uint16_t&)resp.packet.data[b] = (uint16_t)item;
          b += sizeof(item);
        }
        break;
      }
    default: {}
  }
  if(true) { // was handled in our switch
    self->sendRdmResponse(&resp, port);
  } else if(self->rdmCallback) {
    self->rdmCallback(port->group->index, port->index, &packet->rdmData); // well but w stuff parsed out a bit tho...
  }
  // XXX first flip 16s and that...

  // bool ipSet = false;
  // for(auto& sender: port->rdmSender) {
  //   sender.update();
  //   if(ipSet || (sender && sender != self->lastRemoteIP))
  //     continue; //  Bail if already set, or uh slot already set and is not free
  //   sender = self->lastRemoteIP; // Save the IP.
  //   ipSet = true;
  // }
}

// void Driver::handleRdm() {
// }

void Driver::sendRdmResponse(packet::rdm::RdmData* c, Port* port) {
  logf("Sending RdmResponse\n");
	uint16_t len = def::rdmReplySize + c->packet.length + 1;
  packet::art::RDM packet(c, port);

	for(auto& sender: port->rdmSender) {
		if(sender) // better if sender is vec but then still need to enforce size limit
      sendPacket(sender.ip, &packet, len); // btw arent we responding to uh, the specific sender?
	}
}

void Driver::Process::rdmSub(uint8_t* data) {
  logf("artRDMSub\n");
}

void Driver::setIP(IPv4 ip, IPv4 subnet) {
	network.ip = ip;
	if ((uint32_t)subnet != 0)
		network.subnet = subnet;
	network.broadcastIP = IPv4((uint32_t)network.ip | ~((uint32_t)network.subnet));
  
  sendPollReply();
}

//whatever this just to replace old useless fns g / p is dumb.
Universe Driver::getAddr(uint8_t groupIndex, int portIndex) {
  auto addr = groups.at(groupIndex)->addr;
  if(portIndex >= 0 && portIndex < 4)
    addr = groups.at(groupIndex)->ports.at(portIndex)->addr;
  return addr;
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

void Driver::sendDMX(uint8_t g, uint8_t p, uint8_t* data, size_t length) {
// void Driver::sendDMX(Port* port, uint8_t* data, uint16_t length) {
  auto* port = getPort(g, p);
	if(!port || port->receivers.empty())
    return;

	if(length % 2)   length++; // length is always even and up to 512 channels
	if(length > 512) length = 512;
	port->dmxChans = length; // "length of last sent and/or received buf" remnant of old lib, needs better design

  packet::art::DMX packet{getSeqID(), port, data, (uint16_t)length};

  for(auto& ip: port->receivers.size() < 40?
                port->receivers:
                std::initializer_list({network.broadcastIP})) // p sweet bruh. XXX haha no. fix eet
    sendPacket(ip, &packet, (packet::art::DMX::headerLength + length));
}


} // end ns an4
