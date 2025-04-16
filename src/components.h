#pragma once

#include <vector>
#include <array>
#include <unordered_set>
#include <memory>
#include <algorithm>

#include "protocol.h"
#include "platform.h"

// this has a shitty name. figure something out.

namespace anfr {

using namespace def;

using mac_t       = std::array<uint8_t, 6>;
using dmx_buf_t   = std::array<uint8_t, def::dmxBufferSize>;



struct IPSender { // needs new name to clarify it's a purpose-specific rIP timestamp, hence same IP might figure in many sep instances, so currently nonsense.
  // might want to be able to use this to lookup further device info as well? eg store ref to future
  // generalized RemoteDevice or w/e struct
  IPSender(uint32_t timeoutMs = def::KEEPALIVE_INTERVAL):
    senderTimeoutMs(timeoutMs) {

      // logf("New sender instance with ip %d.%d.%d.%d",
      //     ip[0], ip[1], ip[2], ip[3]);
    }
  IPSender(IPv4 rIP, uint32_t timeoutMs = def::KEEPALIVE_INTERVAL):
  ip(rIP), senderTimeoutMs(timeoutMs) {
      // logf("New sender instance with ip %d.%d.%d.%d",
      //     ip[0], ip[1], ip[2], ip[3]);
    initOrRefresh(rIP);
  }
  IPSender(const IPSender& rhs):
    ip(rhs.ip), timeStamp(rhs.timeStamp),
    senderTimeoutMs(rhs.senderTimeoutMs) // DONT copy timeout, just details.
    // shouldnt it be other way round? copy timeout but not timestamp or
  {
      // logf("New sender instance with ip %d.%d.%d.%d",
      //     ip[0], ip[1], ip[2], ip[3]);
  }
  operator bool() const { return ip != INADDR_NONE; }
  bool operator ==(IPv4& rhs) { return ip == rhs; } // might bite me in ass somehow, but to avoid getting 0.0.0.0 as extra source...
  bool operator ==(IPSender& rhs) { return ip == rhs.ip; }
  // bool operator ==(IPv4& rhs) { return ip == rhs || rhs == INADDR_ANY; } // might bite me in ass somehow, but to avoid getting 0.0.0.0 as extra source...
  // bool operator ==(IPSender& rhs) { return ip == rhs.ip || rhs.ip == INADDR_ANY; }
  // IPSender& operator =(IPv4& rhs) { initOrRefresh(rhs, true); return *this; }
  // IPSender& operator =(IPSender& rhs) { initOrRefresh(rhs.ip, true); return *this; }

  bool initOrRefresh(IPv4 rIP, bool force = false) { // normally does nothing if "slot" already occupied
    // if(force || !ip) {
    if(force || !(bool)ip) {
      logf("New sender ip %d.%d.%d.%d, old %d.%d.%d.%d, force %d",
          rIP[0], rIP[1], rIP[2], rIP[3],
          ip[0], ip[1], ip[2], ip[3],
          force);
      ip = rIP;

      logf("Set sender ip to %d.%d.%d.%d",
          ip[0], ip[1], ip[2], ip[3]);
    }
    if(ip == rIP) {
      timeStamp = uptimeMs();
      return true;
    }
    return false;
  }
  void update() { // stupid trying to roll process + state into one. also better if process async anyways if got loads of these...
    if(timeStamp > 0 && uptimeMs() > timeStamp + senderTimeoutMs) {
      logf("IPSender %d.%d.%d.%d timed out", ip[0], ip[1], ip[2], ip[3]);
      reset();
    }
  }
  void reset() {
    ip = INADDR_NONE;
    timeStamp = 0; // gotta restore for timeout-check. but then yeah what about "not even enabled"
  }
  IPv4 ip = INADDR_NONE;
  uint32_t timeStamp = 0;
  uint32_t senderTimeoutMs = def::KEEPALIVE_INTERVAL;
};

struct ReceivingDevice: IPSender {
  // I guess like this - add unis to sender as needed, if dont hear from sender all
  // lapse at once...
  ReceivingDevice(IPv4 ip): IPSender(ip, def::KEEPALIVE_INTERVAL) {}
  // std::set<Universe> universes;
};

union RdmUid { // guessing this is same as defined  for tod, uid man/serial?
  using uid_t = std::array<uint8_t, 6>;
  RdmUid() = default;
  RdmUid(uint8_t* bytes): uid(*(uid_t*)bytes) {}
  RdmUid(uint16_t man, uint32_t dev): man(man), dev(dev) {}
  bool operator==(const RdmUid& rhs) const { return uid == rhs.uid; }

  uid_t uid{0}; //= {0};
  struct {
    uint16_t man;
    uint32_t dev;
  };
};


#pragma pack(push, 1) //ok actually wasnt the issue, it was fucking arduino shit duh

struct NodeName { //pack everything going into packets ffs
  NodeName() = default;
  NodeName(const NodeName& names): NodeName(names.shortName, names.longName) {}
  NodeName(const char* name, const char* longName = nullptr) {
    setShort(name); if(!longName) setLong(name);
  }
  void setShort(const char* name) { strncpy(shortName, name, def::shortNameLength - 1); }
  void setLong(const char* name)  { strncpy(longName,  name, def::longNameLength - 1); }// overflows despite??
	char shortName[def::shortNameLength] = {0},
       longName[def::longNameLength] = {0};
};


union Universe {
  Universe(uint16_t address = 0): address(address) {} // beware 8/16 confusion here tho w subUni...
  Universe(uint8_t subUni, uint8_t net = 0): subUni(subUni), netSwitch(net) {}
  Universe(uint8_t portAddr, uint8_t subSwitch, uint8_t net):
    portAddr(portAddr), subSwitch(subSwitch), netSwitch(net) {}

  Universe operator++(int) {
    auto curr = Universe(address);
    if(++subUni == 0) {
      netSwitch++; // urh, guess that's it??
    }
    // return *this;
    return curr; // uh so modifies in place AND returns a copy, hmmm seems like weird mash of in-place and not
  }
  // Universe operator+(uint8_16_t addressOffset) {
  //   auto curr = Universe(address);
  //   (if )
  // }

  struct { // order sorted. beware bitfields will fuck us on crossplatform stuff. just fun.
    union {
      uint8_t subUni; // bit 0-7, aka LowAddress. 256 base universes of artnet v2.
      struct {
        uint8_t portAddr: 4,  // bit 0-3: 'port' aint right tho. Art-Net.h says "Port Address"... SwIn / SwOut.
                subSwitch: 4;  // bit 4-7: Sub-Net, "subswitch"
      };
    };
    uint8_t netSwitch :7, :1;   // bit 8-14: "netswitch"
  };
  uint16_t :4, netSub: 11, :1; // net + subswitch
  uint16_t address: 15, :1; // complete

  void print(std::string desc = "") {
    logf("%sUNIVERSE STATS:  full: %u, netSwitch %u, subSwitch %u, subUni %u, portAddr %u",
        desc.c_str(), address, netSwitch, subSwitch, subUni, portAddr);
  }
};
#pragma pack(pop)

// template<class Packet>
// Universe getUniverse(Packet* packet) {
//   // well diff a bit but net/address real common.
//   // bunch of other template stuff can be done. too
// }
struct Group;

// needs support for simul in and out. with different universes etc...
// maybe should just keep as sep objects and allow 8 ports as long as well you get
struct Port {
  inline static std::vector<Port*> allPorts; // all ports. would ensure sort and whatnot laterz. of groups are semi satural for that but better if also keep sorted and can fetch by index?
  static Port* atAddress(Universe addr);

  Port(Group* parent, uint8_t portAddr, Universe baseUni, int index, // XXX order is flipped compared to fn in Device, Group...
       PortMode type, uint8_t* dataLoc = nullptr);
  ~Port();

  Group* group = nullptr; // handle to parent
	PortMode portType = PortArtnetIn; //
  std::unordered_set<IPv4, std::hash<uint32_t>> receivers; // when is Output...
  // ^ XXX so: gotta be IPSender so can process and lapse.  PLUS: bit fkn expensive checking each receiver for each port each time.
  // most other devices will have many unis = share...  so, central reg of receivers, process, push to ports?
  // then we're back to IPv4 again. heh!
	uint8_t protocol = ARTNET; // ArtNet or sACN - prob substruct w htp and such "port settings" stuff
  int index; // 0-3 or 1-4 or like yeah
	/* uint16_t e131Uni; */ /* uint16_t e131Sequence; */ /* uint8_t e131Priority; */ // sACN settings

  Universe addr;
	uint16_t dmxChans = 0; // seems a bit, eh. Reactive is the word I guess. Not in the fancy wya.
  bool extBuf = false;
  // union HURR
  uint8_t* bufRaw;
  // dmx_buf_t& dmxBuffer;
  // dmx_buf_t dmxBuffer; // DMX final values buffer

  enum SenderID: int {
    Invalid = -2, Disregard = -1, Primary = 0, Secondary = 1, Last = 1
  };

  void updateBuffer(dmx_buf_t& data, size_t length, SenderID senderID = SenderID::Disregard);

  void setMerge(bool enable = true);
	bool mergeHTP = true;
  std::array<IPSender, def::senderSlots> sender; // the two slots of DMX senders to receive from. so also merge rel...

  struct Merge {
    // Merge(dmx_buf_t& target): target(target) {}
    Merge(uint8_t* target): target(target) {}

    void updateAndApply(dmx_buf_t& data, size_t length, SenderID senderID) {
      inputBuffer[(int)senderID] = data;
      // length, dmxChans, w/e shorter, w/e longer?
      for(uint16_t ch = 0; ch < length; ch++) { // might not use entire buf
        target[ch] = std::max(inputBuffer[0][ch], inputBuffer[1][ch]);
      }
    }
    dmx_buf_t inputBuffer[2]; // like, or these could just be ptrs lol
    // dmx_buf_t& target;
    uint8_t* target;
  }; Merge* merge = nullptr; //still keep a sep structure for rest of that shit too. fkn annoying.
  // std::unique_ptr<Merge> merge; // Merge* merge = nullptr; //still keep a sep structure for rest of that shit too. fkn annoying.

  public:
  static const int rdmTimeout = 200; // ms.  Check when last packets received.  Clear if over 200ms
  IPSender rdmSender[5] = {rdmTimeout}; // IP and timestamp for last 5 RDM commands (within last 200ms?)
  struct { // RDM Variables.
    bool available = false;
    uint64_t lastCommandTime = 0;
    std::vector<RdmUid> devices; // devices at this physical port (when Output Gateway)
    // std::set<RdmUid> devices; // devices at this physical port (when Output Gateway)
  } tod;
};


struct DeviceInfo;

// still Q, is add/rm Port something done by a Group, or to it.
// Latter prob more sense if v existance of Groups trying to be relegated to more impl detail.

struct Group {
	Group(int index, uint8_t netSwitch, uint8_t subSwitch, DeviceInfo& devInfo); //
  
  Universe addr; // guess no need specify that it's baseline.
  int index;
  DeviceInfo& devInfo;
  
  std::vector<std::shared_ptr<Port>> ports;
	// uint16_t numPorts = 0; // so, eh vector eh

  int addPort(int p, uint8_t portAddr, PortMode type = PortArtnetIn, uint8_t* extBuf = nullptr);
  // Port* addPort(int p, uint8_t portAddr, PortMode type = PortArtnetIn, uint8_t* extBuf = nullptr);
  Port* getPort(int p) {
    auto port = std::find_if(ports.begin(), ports.end(),
                            [p](auto& po) { return po->index == p; });
    if(port != ports.end())
      return (*port).get();
    return nullptr;
  }
  
  void closePort(Port& port);
  void closePort(uint8_t p);

  IPSender sourceLock{def::cancelMergeTimeout};
};


struct NodeReport { // goddamnit extra stuff breaks oh wait this data structure aint ahah what horrible beast this was and still is
  static constexpr size_t size = def::nodeReportLength - def::nodeReportHeaderLength;
  static constexpr char  fmt[] = "#%04x[%d] %s"; // RC code, counter, text...

  NodeReport() = default;
  NodeReport(const char* data, RC statusCode = RC::PowerOk) {
      update(data, statusCode);
  }

  void update(const char* data, RC statusCode = RC::PowerOk) { //RC goes in report. Also update goes to intermittant buf no? update anytime, goes out next report
    code = statusCode;
    strncpy(report, data, size);
  }
  void toBuffer(char* destination) { // get'd be better. but maybe just as well, avoiding std::string, bc pussies
    sprintf(destination, fmt, code, counter++, report);
    if(counter > 999999) counter = 0; // Max 6 digits for counter - could be longer if wanted
  }
  RC code = RC::PowerOk;
  uint32_t counter = 0;
  char     report[size] = {0}; //make string n that.
}; // eh guess code and counter sep so can put straight in packets


// TODO maybe: add/contain rdm uid stuff and some IPSender yada so can use this not just
struct DeviceNetwork { // for self but all other known devices?
  DeviceNetwork() = default;
  DeviceNetwork(IPv4 deviceIP, IPv4 subnet, //IPv4 broadcastIP,
                const uint8_t deviceMAC[6], bool dhcp = true):
    ip(deviceIP), subnet(subnet),
    broadcastIP(IPv4((uint32_t)ip | ~((uint32_t)subnet))),
    mac(*(mac_t*)deviceMAC), dhcp(dhcp) { }
  DeviceNetwork(const DeviceNetwork& rhs):
    DeviceNetwork(rhs.ip, rhs.subnet, rhs.mac.data(), rhs.dhcp) {}
  IPv4 ip, subnet, broadcastIP;
  mac_t mac;
  bool dhcp = true;
};


struct DeviceInfo { // or something. p related.
  DeviceInfo(uint16_t oem = def::defaultOem, uint16_t estaMan = def::defaultEstaMan, uint16_t fwVersion = 0):
    oem(oem), estaMan(estaMan), fwVersion(fwVersion) {}
  uint16_t oem        = def::defaultOem; // hi, lo. OEM code registered with Artistic License. Default UNKNOWN
  uint16_t estaMan    = def::defaultEstaMan; // hi, lo. ESTA manufacturer code. Default RESERVED FOR PROTOTYPING
  // there's also an ESTA_DEV some RDM ID for making guids. put here too?  and  "UBEA version"
  // yeah what's our 6byte uid? guess oem + esta is man, but dev?
  uint16_t fwVersion  = 0;    // "Version info", manufacturer defined firmware version.
  enum DeviceType {
    Controller,
    Node,
    MediaServer
  } type = Node; // XXX reuse Style from pollreply
}; // dunno why the fuck this...


}
