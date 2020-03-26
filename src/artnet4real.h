/* artnet4real v.0.0.1-alpha library
 * Copyright Joen Tolgraven 2020
 * figure out license and that
*/

#pragma once

#include <functional>
#include <vector>
#include <memory>
#include <unordered_set>

#include "platform.h"
#include "protocol.h"
#include "packet.h"
#include "components.h"

namespace an4r::artnet {

using namespace protocol;

using ArtDMXCallback		= std::function<void(uint8_t, uint8_t, uint16_t, bool)>;
using ArtSyncCallback		= std::function<void()>;
using ArtRDMCallback		= std::function<void(uint8_t, uint8_t, packet::rdm::RdmData*)>;
using ArtIPCallback			= std::function<void()>;
using ArtAddressCallback	= std::function<void()>;
using ArtTodRequestCallback	= std::function<void(uint8_t, uint8_t)>;
using ArtTodFlushCallback	= std::function<void(uint8_t, uint8_t)>;


class Driver { // sooeh, static members possibly
  DeviceNetwork network;
  IPSender syncSender, lastDmxFrameSender;
  IPSender lastRemoteIP; // XXX temp, just keep latest rIP here

  NodeName names{}; //prob overk
  NodeReport nodeReport;
  DeviceInfo deviceInfo{};

  std::vector<std::unique_ptr<Group>> groups;
  bool active = false;

public:
	Driver(const char* shortName, const char* longName = nullptr,
         uint16_t oem = protocol::defaultOem, uint16_t esta = protocol::defaultEstaMan);
  Driver(Driver&& rhs) = delete;
	~Driver() {}

	void init(const IPAddress& ip, const IPAddress& subnet, uint8_t* mac, bool dhcp = true);
	void init() { setDefaultIP(); }

  // also just abstract away groups amap, add ports directly, groups are created to hold them as needed
	uint8_t addGroup(uint8_t, uint8_t); // Group& addGroup(uint8_t, uint8_t);
	int addPort(uint8_t g, uint8_t p, uint8_t portAddr, PortMode type = PortArtnetIn);
	bool closePort(uint8_t, uint8_t);

  void begin() { // well what else do if not our socket.
    active = true;
    sendPollReply(); // Send initial unsolicited ArtPollReply to tell everyone we're here
  }
  void pause() { active = false; }
  
	uint8_t* getDMX(uint8_t, uint8_t);
	// dmx_buf_t getDMX(Universe uni);

	// void setProtocolType(uint8_t, uint8_t, uint8_t); // protocol functions type: 0 = ARTNET, 1 = SACN_UNICAST, 2 = SACN_MULTICAST
	// uint8_t getProtocolType(uint8_t, uint8_t); /* void setE131Uni(uint8_t, uint8_t, uint16_t); */

  int onPacket(IPAddress ip, uint8_t* data, size_t length); // check validity and pass on to internal fns

  using PacketSendFn = std::function<void(IPAddress&, uint8_t*, size_t, uint16_t)>;
  void setPacketSendFn(PacketSendFn fn) { packetSender = fn; }

  void setArtDMXCallback(ArtDMXCallback cb) { dmxCallback = cb; }
  void setArtSyncCallback(ArtSyncCallback cb) { syncCallback = cb; }
  void setArtRDMCallback(ArtRDMCallback cb) { rdmCallback = cb; }
  void setArtIPCallback(ArtIPCallback cb) { ipCallback = cb; }
  void setArtAddressCallback(ArtAddressCallback cb) { addressCallback = cb; }
  void setTODRequestCallback(ArtTodRequestCallback cb) { todRequestCallback = cb; }
  void setTODFlushCallback(ArtTodFlushCallback cb) { todFlushCallback = cb; }

  // these will go. once Group / Port classes encapsulated enough lib user getting
  // and manipulating them directly is perfectly safe.
  Universe getAddr(uint8_t groupIndex, int portIndex = -1);
	// void setNet(uint8_t, uint8_t);
	// void setSubSwitch(uint8_t, uint8_t);
	// void setUni(uint8_t, uint8_t, uint8_t);
	void setPortType(uint8_t, uint8_t, PortMode t);

  // template<class T> void setShortName(T shortName);
  // template<class T> void setLongName(T longName);
	void setShortName(char*);
	char* getShortName();
	void setLongName(char*);
	char* getLongName();

	void setFirmwareVersion(uint16_t fw) { deviceInfo.fwVersion = fw; }
	void setDefaultIP();
  void setIP(IPAddress ip, IPAddress subnet = IPAddress(255,255,255,0));
  const DeviceNetwork& getNetworkCfg() const { return network; };
  void setNetworkCfg(DeviceNetwork& newConfig) { network = newConfig; }; // and do w/e refresh

	void setNodeReport(char*, RC); // void setNodeReport(const String& text);
	void setArtDiagData(char* diagString, uint8_t priority = (uint8_t)DiagPriority::Low); //fix this yo. tho also per port i guess
	void sendRdmResponse(packet::rdm::RdmData*, Port* port);
	void artTODData(Port* port, uint16_t*, uint32_t*, uint16_t, uint8_t);

  void sendIPProgReply();
	void sendPollReply(); // since not polling on reg
	void sendDMX(uint8_t group, uint8_t port, uint8_t* data, uint16_t length);
	void sendDMX(Port* port);

  Port* getPort(uint8_t g, uint8_t p) {
    auto& group = groups[g];
    if(group) {
      auto& port = group->ports[p];
      if(port) return port.get();
    }
    return nullptr;
    // return groups[g]?
    //        &*(groups[g]->ports[p]): // will bang here if p oor
    //        nullptr;
	}

private:
  template<class Packet>
  void sendPacket(IPAddress dest, Packet* packet, uint16_t length = sizeof(Packet)) {
    if(active && packetSender) {
      packetSender(dest, reinterpret_cast<uint8_t*>(packet), length, protocol::defaultUdpPort);
    } else {
      // error "not active or no sendfn"
    }
  }

  struct Process;

  PacketSendFn packetSender;

	ArtDMXCallback dmxCallback; // using from header not taking?
	ArtSyncCallback syncCallback;
	ArtRDMCallback rdmCallback;
	ArtIPCallback ipCallback;
	ArtAddressCallback addressCallback;
	ArtTodRequestCallback todRequestCallback;
	ArtTodFlushCallback todFlushCallback;
};

} // END NAMESPACE an4
