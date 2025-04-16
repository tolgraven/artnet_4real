/* artnet4real v.0.0.1-alpha library
 * Copyright Joen Tolgraven 2020
 * figure out license and that
*/

#pragma once

#include <functional>
#include <vector>
#include <memory>

#include "platform.h"
#include "protocol.h"
#include "packet.h"
#include "components.h"

namespace anfr { // better like before (wrapper meant for using; then more) except that gets too hectic in compiler errors...

using namespace def; // tho mostly explicit now. try to extend to fully so.

using groupid_t = uint16_t;
using portid_t  = uint8_t;
namespace cb {
using DMX        = std::function<void(uint8_t, uint8_t, uint8_t*, uint16_t, bool)>;
using Sync       = std::function<void()>;
using RDM        = std::function<void(uint8_t, uint8_t, packet::rdm::RdmData*)>;
using IP         = std::function<void()>;
using Address    = std::function<void()>;
using TodRequest = std::function<void(uint8_t, uint8_t)>;
using TodFlush   = std::function<void(uint8_t, uint8_t)>;
}

class Configuration {
  DeviceNetwork network;
  NodeName names{}; // well noneed
  DeviceInfo deviceInfo{};

};

class Driver { // sooeh, static members possibly? guess might to sep some stuff to actually run different driver instances on same device w different netwworks or similar
  DeviceNetwork network;
  IPSender lastRemoteIP; // XXX temp, just keep latest rIP here

  NodeName names{}; //prob overk
  NodeReport nodeReport;
  DeviceInfo deviceInfo{};

  // Configuration cfg; // gather all the crap tbh. Get state vs config clean and organized...
  // Driver(cfg).init(state);
  // but basically any config change will at most result in same thing: push out new poll/reply
  // to inform others of new state. So can eschew (sp??) all wrapper bs.

  std::vector<std::unique_ptr<Group>> groups;
  bool active = false;

public:
	Driver(const char* shortName, const char* longName = nullptr,
         uint16_t oem = def::defaultOem, uint16_t esta = def::defaultEstaMan);
  Driver(Driver&&) = delete;
  Driver(const Driver&) = delete; // for now
	~Driver() {}

	void init(IPv4 ip, IPv4 subnet, uint8_t* mac, bool dhcp = true);
	// void init() { setDefaultIP(); } // broken for now

  // ideally we're not really explicitly dealing with groups from outside tho...
	Group* addGroup(uint8_t, uint8_t); // Group& addGroup(uint8_t, uint8_t);
	Group* addGroup(Universe); // Group& addGroup(uint8_t, uint8_t);
	// Group* getGroup(uint8_t) { return;  } 
	int addPort(uint8_t g, uint8_t p, uint8_t portAddr, PortMode type = PortArtnetIn); //return Port* instead?
	Port* addPort(Universe& universe, PortMode type = PortArtnetIn); // as it should be. Handle logic of what group and port number it is internally, mostly ininteresting to end user.
	// Port* addPort(uint8_t g, uint8_t p, uint8_t portAddr, PortMode type = PortArtnetIn); //return Port* instead?
	bool closePort(uint8_t, uint8_t);

  std::vector<Port*>& setupBulkInputs(Universe baseAddr, uint8_t* dataStart, size_t bytes); // or whatever will be called....

  // some states: pre-begin, paused, running w traffic, w/o new data, without receiving... (send repeats 4s)
  void begin() { // well what else do if not our socket.
    active = true;
    sendPollReply(); // Send initial unsolicited ArtPollReply to tell everyone we're here. Would be ArtPoll if we're the server, etc...
  }
  void stop() { active = false; }
  bool isActive() { return active; }
  
	// uint8_t* getDMX(uint8_t, uint8_t); // doesnt make much sense. Callback sends buffer loc. Ports can provide that info directly other times.
	// dmx_buf_t getDMX(Universe uni);

  int onPacket(IPv4 ip, uint8_t* data, size_t length); // check validity and pass on to internal fns

  using PacketSendFn = std::function<void(IPv4&, uint8_t*, size_t, uint16_t)>;
  void setPacketSendFn(PacketSendFn fn) { packetSender = fn; }

  void setArtDMXCallback(cb::DMX&& cb) { dmxCallback = std::move(cb); }
  void setArtSyncCallback(cb::Sync cb) { syncCallback = cb; }
  void setArtRDMCallback(cb::RDM cb) { rdmCallback = cb; }
  void setArtIPCallback(cb::IP cb) { ipCallback = cb; }
  void setArtAddressCallback(cb::Address cb) { addressCallback = cb; }
  void setTODRequestCallback(cb::TodRequest cb) { todRequestCallback = cb; }
  void setTODFlushCallback(cb::TodFlush cb) { todFlushCallback = cb; }


  // template<class T> void setShortName(T&& shortName) {}
  // template<class T> void setLongName(T&& longName) {}
	void setShortName(char*);
	char* getShortName();
	void setLongName(char*);
	char* getLongName();

	// void setFirmwareVersion(uint16_t fw) { deviceInfo.fwVersion = fw; }
	void setDefaultIP();
  void setIP(IPv4 ip, IPv4 subnet = IPv4(255,255,255,0));
  const DeviceNetwork& getNetworkCfg() const { return network; };
  void setNetworkCfg(DeviceNetwork& newConfig) { network = newConfig; }; // and do w/e refresh
  const DeviceInfo& getDeviceInfo() const { return deviceInfo; };
  // void setNetworkCfg(DeviceInfo& newInfo) { network = newConfig; }; // and do w/e refresh

	void setNodeReport(char*, RC);
	void setArtDiagData(char* diagString, DiagPriority priority = DiagPriority::Low); //fix this yo. tho also per port i guess
	void sendRdmResponse(packet::rdm::RdmData*, Port* port);
	void sendTODData(Port* port);

  void sendIPProgReply();
	void sendPollReply(); // since not polling on reg
	void sendDMX(uint8_t group, uint8_t port, uint8_t* data, size_t length);
	void sendDMX(Port* port, uint8_t* data, size_t length); // should be std - easy to get port from g+p, saved handle, Universe...
	void sendDMX(Universe addr, uint8_t* data, size_t length); // should be std - easy to get port from g+p, saved handle, Universe...

  Universe getAddr(uint8_t groupIndex, int portIndex = -1);
  Port* getPort(uint8_t g, uint8_t p) {
    auto& group = groups[g];
    if(group) {
      return group->getPort(p);
      // auto& port = group->ports[p];
      // if(port) return port.get();
    }
    return nullptr;
	}

private:
  // first strategy should be call packet length method if available.
  // Some nice c++17 exts to that...
  template<class Packet>
  void sendPacket(IPv4 dest, Packet* packet, uint16_t length = sizeof(Packet)) {
    static bool didWarn = false;
    if(!active) {
      if(didWarn) return;
      logf("Driver not active, won't send\n");
      didWarn = true;
    } else if(!packetSender) {
      if(didWarn) return;
      logf("No PacketSendFn installed in Driver, can't send\n");
      didWarn = true;
    } else {
      packetSender(dest, reinterpret_cast<uint8_t*>(packet), length, def::defaultUdpPort);
      didWarn = false;
    }
  }

  struct Process;

  PacketSendFn packetSender;

	cb::DMX dmxCallback;
	cb::Sync syncCallback;
	cb::RDM rdmCallback;
	cb::IP ipCallback;
	cb::Address addressCallback;
	cb::TodRequest todRequestCallback;
	cb::TodFlush todFlushCallback;
};

} // END NAMESPACE an4r::artnet
