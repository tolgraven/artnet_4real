#pragma once

#include "protocol.h"

namespace an4r::artnet {

using namespace protocol;

using mac_t       = std::array<uint8_t, 6>;
using dmx_buf_t   = std::array<uint8_t, protocol::dmxBufferSize>;


class IPv4 { // stolen + cleaned from vtable and such, from Arduino's. Good to have own type for mult platform stuff
  public:
    IPv4(uint32_t ip): data(ip) {}
    IPv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d): data(a, b, c, d) {}
    IPv4(const uint8_t* ip): data(ip) {}
    IPv4(const IPv4& ip): IPv4(uint32_t(ip)) {}
    bool operator==(const IPv4& addr) const { return *(*this) == *addr; }
    bool operator==(const uint8_t* addr) const {
      return memcmp(addr, data.bytes, sizeof(data.bytes)) == 0;
    };
    uint32_t operator*() const { return data.dword; }
    operator uint32_t() const { return data.dword; }
    // operator bool()     const { return data.dword != 0; } // this was causing me mad issues when modding (then forgetting about having done so) IPAddress haha! no const = cast becomes assignment, const = breaks == operator(!!) which is nonsense bc why would it attempt to bounce down to bool to compare stuff?? optimizing "both false?" or w/e would happen out of sight soo. where are you, ghost mentor?
    // Overloaded index operator to allow getting and setting individual octets of the address
    uint8_t operator[](int index) const { return data.bytes[index]; }
    uint8_t& operator[](int index)      { return data.bytes[index]; }
    // Overloaded copy operators to allow initialisation of IPv4 objects from other types
    IPv4& operator=(const uint8_t* ip) { memcpy(data.bytes, ip, sizeof(data.bytes)); return *this; }
    IPv4& operator=(uint32_t ip) { data.dword = ip; return *this; }

    static IPv4 NONE() { return IPv4(0U); }
  private:
    union Data {
      uint8_t bytes[4];   // IPv4 address
      uint32_t dword = 0;
      Data(uint32_t ip): dword(ip) {}
      Data(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
        bytes[0] = a; bytes[1] = b; bytes[2] = c; bytes[3] = d;
      };
      // Data(const uint8_t* ip) { memcpy(bytes, ip, sizeof(bytes)); }
      Data(const uint8_t* ip): dword(*(uint32_t*)ip) {}
    } data;

public: // but for Arduino should prob handle the normal type, eh...
#if defined(ARDUINO)  // etc then add other code for other platforms
    IPv4(const IPAddress& ip): IPv4(uint32_t(ip)) {}
    bool operator==(const IPAddress& ip) const { return *(*this) == uint32_t(ip); }
    IPv4& operator=(const IPAddress& ip) { data.dword = uint32_t(ip); return *this; }
    operator IPAddress() const { return IPAddress(data.dword); }
#endif
};

struct IPSender {
  IPSender(uint32_t timeoutMs = protocol::KEEPALIVE_INTERVAL):
    senderTimeoutMs(timeoutMs) {}
  IPSender(IPAddress rIP, uint32_t timeoutMs = protocol::KEEPALIVE_INTERVAL):
  senderTimeoutMs(timeoutMs) {
    initOrUpdate(rIP);
  }
  IPSender(const IPSender& rhs):
    ip(rhs.ip), timeStamp(rhs.timeStamp) //,
    // senderTimeoutMs(rhs.senderTimeoutMs) // DONT copy timeout, just details.
  {}
  operator bool() const { return ip != INADDR_NONE; }
  bool operator ==(IPAddress& rhs) { return ip == rhs; }
  bool operator ==(IPSender& rhs) { return ip == rhs.ip; }
  IPSender& operator =(IPAddress& rhs) { initOrUpdate(rhs, true); return *this; }

  bool initOrUpdate(IPAddress rIP, bool force = false) { // normally does nothing if "slot" already occupied
    if(force || !ip) // they've impl this right?
      ip = rIP;
    if(ip == rIP) {
      timeStamp = millis();
      return true;
    }
    return false;
  }
  bool letTimeoutIfExpired(uint32_t timeoutMs = 0) {// fuckit side effects get di libs btw. and back to clj lol
    if(timeoutMs == 0) timeoutMs = senderTimeoutMs;
    if(timeStamp > 0 && millis() > timeStamp + timeoutMs) {
      reset();
      return true;
    }
    return false;
  }
  void reset() {
    ip = INADDR_NONE;
    timeStamp = 0; // gotta restore for timeout-check. but then yeah what about "not even enabled"
  }
  IPAddress ip = INADDR_NONE;
  uint32_t timeStamp = 0;
  uint32_t senderTimeoutMs = protocol::KEEPALIVE_INTERVAL;
};

struct ReceivingDevice: IPSender {
  // I guess like this - add unis to sender as needed, if dont hear from sender all
  // lapse at once...
  ReceivingDevice(IPAddress ip): IPSender(ip, protocol::KEEPALIVE_INTERVAL) {}

  // std::set<Universe> universes;
};

union RdmUid { // guessing this is same as defined  for tod, uid man/serial?
  using uid_t = std::array<uint8_t, 6>;
  RdmUid() = default;
  RdmUid(uint8_t* bytes): uid(*(uid_t*)bytes) {}
  RdmUid(uint16_t man, uint32_t dev): man(man), dev(dev) {}

  uid_t uid{0}; //= {0};
  struct {
    uint16_t man;
    uint32_t dev;
  };
};
struct Group;


#pragma pack(push, 1) //ok actually wasnt the issue, it was fucking arduino shit duh

struct NodeName { //pack everything going into packets ffs
  NodeName() = default;
  NodeName(const NodeName& names): NodeName(names.shortName, names.longName) {}
  NodeName(const char* name, const char* longName = nullptr) {
    setShort(name); if(!longName) setLong(name);
  }
  void setShort(const char* name) { strncpy(shortName, name, protocol::shortNameLength - 1); }
  void setLong(const char* name)  { strncpy(longName,  name, protocol::longNameLength - 1); }// overflows despite??
	char shortName[protocol::shortNameLength] = {0},
       longName[protocol::longNameLength] = {0};
};


union Universe {
  Universe(uint16_t address = 0): address(address) {} // beware 8/16 confusion here tho w subUni...
  Universe(uint8_t subUni, uint8_t net = 0): subUni(subUni), netSwitch(net) {}
  Universe(uint8_t portAddr, uint8_t subSwitch, uint8_t net):
    portAddr(portAddr), subSwitch(subSwitch), netSwitch(net) {}

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

  void print() {
    Serial.printf("\nUNIVERSE STATS:  full: %u, netSwitch %u, subSwitch %u, subuni %u, port %u\n\n",
        address, netSwitch, subSwitch, subUni, portAddr);
  }
};
#pragma pack(pop)

// template<class Packet>
// Universe getUniverse(Packet* packet) {
//   // well diff a bit but net/address real common.
//   // bunch of other template stuff can be done. too
// }


struct Port {
  inline static std::vector<Port*> allPorts; // all ports. would ensure sort and whatnot laterz. of groups are semi satural for that but better if also keep sorted and can fetch by index?
  // static Port* atAddress(Universe addr);
  static Port* atAddress(Universe addr) {
    auto hit = std::find_if(allPorts.begin(), allPorts.end(),
        [&addr](auto port) { return addr.address == port->addr.address; });
      if(hit != allPorts.end())
        return *hit;
      return nullptr;
  }
	// Port(Group* parent, uint8_t portAddr, Universe baseUni, int index, PortMode type = PortArtnetIn);
  Port(Group* parent, uint8_t portAddr, Universe baseUni, int index, PortMode type):
    group(parent), portType(type), index(index), addr(baseUni) {
      addr.portAddr = portAddr;
      addr.print();
      allPorts.push_back(this);
  }
  ~Port() {
  // auto cmon = std::find(allPorts.begin(), allPorts.end(), this);
  // auto cmon = std::find_if(allPorts.begin(), allPorts.end(),
  //     [this](std::shared_ptr<Port>& ou) { return this == ou.get(); });
  // if(cmon != allPorts.end()) cmon->reset();

  // allPorts.erase(cmon);
  // allPorts.assign(cmon, nullptr); // like, dont wanna delete my shit goddamnit guess weak ptr after all then but like arghgh. they want me to optional i know it.
  // ports.erase(std::find_if(ports.begin(), ports.end(), [this](auto* that) { return this == that; }));
  // if(merge) delete merge;
  }

  Group* group = nullptr; // handle to parent
	PortMode portType = PortArtnetIn; //
  // std::unordered_set<IPAddress, std::hash<(uint32_t)IPAddress>> receivers; // when is Output...
  std::unordered_set<IPAddress, std::hash<uint32_t>> receivers; // when is Output...
  // ^ XXX so: gotta be IPSender so can process and lapse.
  // PLUS: bit fkn expensive checking each receiver for each port each time.
  // most other devices will have many unis = share...
  // so, central reg of receivers, process, push to ports?
  // then we're back to IPAddress again. heh!
	uint8_t protocol = ARTNET; // ArtNet or sACN - prob substruct w htp and such "port settings" stuff
  int index; // 0-3 or 1-4 or like yeah
	/* uint16_t e131Uni; */ /* uint16_t e131Sequence; */ /* uint8_t e131Priority; */ // sACN settings

  Universe addr;
	uint16_t dmxChans = 0; // seems a bit, eh. Reactive is the word I guess. Not in the fancy wya.
  dmx_buf_t dmxBuffer; // DMX final values buffer

  void updateBuffer(dmx_buf_t& data, size_t length, int senderID = -1) { // too unclear tho, not nice.
    if(merge != nullptr && senderID >= 0)
      merge->updateAndApply(data, length, senderID);
    else
      dmxBuffer = data; // XXX all buffers will be 512 so account for actual incoming len
    dmxChans = length; // well not, however could save per sender.
  }

  void setMerge(bool enable = true) {
    if(enable && mergeHTP && !lockedToSource && !merge) {
       merge = new Merge(dmxBuffer); // merge.reset(new Merge(dmxBuffer));
    } else if(!enable && merge) {
       delete merge; merge = nullptr; // merge.reset();
    }
  }
	bool mergeHTP = true,
       lockedToSource = false;
  IPSender sender[2]; // the two slots of DMX senders to receive from. so also merge rel...

  // private:
  struct Merge { // best just let this destruct when not used
    Merge(dmx_buf_t& target): target(target) {}

    void updateAndApply(dmx_buf_t& data, size_t length, int senderID) {
      inputBuffer[senderID] = data;
      // length, dmxChans, w/e shorter, w/e longer?
      for(uint16_t ch = 0; ch < length; ch++) { // might not use entire buf
        target[ch] = std::max(inputBuffer[0][ch], inputBuffer[1][ch]);
      }
    }
    dmx_buf_t inputBuffer[2]; // like, or these could just be ptrs lol
    dmx_buf_t& target;
  }; Merge* merge = nullptr; //still keep a sep structure for rest of that shit too. fkn annoying.
  // std::unique_ptr<Merge> merge; // Merge* merge = nullptr; //still keep a sep structure for rest of that shit too. fkn annoying.

  public:
  const int rdmTimeout = 200; // ms.  Check when last packets received.  Clear if over 200ms
  IPSender rdmSender[5] = {rdmTimeout}; // IP and timestamp for last 5 RDM commands (within last 200ms?)
  struct { // RDM Variables
    bool available = false;
    uint16_t uidTotal = 0;
    uint64_t lastCommandTime = 0;
    std::array<RdmUid, 50> device;
  } tod;
};

// std::vector<Port*> Port::allPorts; // but shouldnt be needed if nothing here is accessing it?
// Port* Port::atAddress(Universe addr) {
//   auto hit = std::find_if(allPorts.begin(), allPorts.end(),
//       [&addr](auto port) { return addr.address == port->addr.address; });
//     if(hit != allPorts.end())
//       return *hit;
//     return nullptr;
// }

// Port::Port(Group* parent, uint8_t portAddr,
//                          Universe baseUni, int index, PortMode type):
//   group(parent), portType(type), index(index), addr(baseUni) {
//     addr.portAddr = portAddr;
//     addr.print();
//     allPorts.push_back(this);
// }
// Port::~Port() {

// still Q, is add/rm Port something done by a Group, or to it.
// Latter prob more sense if v existance of Groups trying to be relegated to more impl detail.
struct Group {
	Group(int index, uint8_t netSwitch, uint8_t subSwitch): //
    addr{0, subSwitch, netSwitch}, index(index), sourceLock(this) {
      addr.print();
    }
  Universe addr; // tbh no need specify root? no shit it aiint full or like...
  int index;
  std::vector<std::shared_ptr<Port>> ports;
	uint16_t numPorts = 0; // so, eh vector eh

  int addPort(int p, uint8_t portAddr, PortMode type = PortArtnetIn) { // nuking ability to pass own buffer at least for now.
    if(p < 4 && ports.size() <= 4) { // && p-index isnt busy XXX
      // ports[p].reset(new Port(this, portAddr, addr, type, p));
        ports.emplace_back(std::make_shared<Port>(this, portAddr, addr, p, type));
      numPorts++;
      return p;
    }
    return -1; // well, throw some shit but laterz
  }
  void closePort(Port& port) { }
  void closePort(uint8_t p) {
    auto port = std::find_if(ports.begin(), ports.end(),
                            // [p](auto& po) { return po.index == p; });
                            [p](auto& po) { return po->index == p; });
    if(port != ports.end()) { // find
      // ports.erase(*port); // why cant it erase using an iterator?
      // ports[p].reset(); // just nukes port keeps ptr.
      numPorts--;
    } // should prob trigger flush pollreply etc
  }

  struct SourceLock: IPSender { // XXX makes more sense lol
    SourceLock(Group* group):
      IPSender(protocol::cancelMergeTimeout), group(group) {} //

    void start(IPAddress rIP) {
      initOrUpdate(rIP);
      for(auto& port: group->ports)
        // port.setMerge(false); // ahh wait gotta wait til next frame before, yada. super mini detail i guess
        port->lockedToSource = true;
    }
    void stop() {
      reset();
    }
    Group* group;
  } sourceLock;

  // struct SourceLock { // "cancel merge" aka. only use my messages
  // // struct SourceLock: IPSender { // XXX makes more sense lol
  //   SourceLock(Group* group): group(group) {} //
  //   operator bool() { return active; }

  //   void start(IPAddress rIP) {
  //     active = true;
  //     source.initOrUpdate(rIP);
  //     for(auto& port: group->ports)
  //       // port.setMerge(false); // ahh wait gotta wait til next frame before, yada. super mini detail i guess
  //       port->lockedToSource = true;
  //   }
  //   void stop() {
  //     active = false;
  //     source.reset();
  //   }
  //   bool letTimeoutIfExpired() {
  //     if(source.letTimeoutIfExpired(ARTNET_CANCEL_MERGE_TIMEOUT)) {
  //       stop();
  //       return true;
  //     } else return false; // dunno if return true or false on "not timed out, not active, fuckoff"
  //   }
  //   bool isOwner(const IPAddress& rIP) {
  //     return (rIP == source.ip);
  //   }

  //   IPSender source = {};
  //   bool active = false; //
  //   Group* group;
  // } sourceLock; // CancelMerge* mergeCancel = nullptr; // would prefer this...
};


struct NodeReport { // goddamnit extra stuff breaks oh wait this data structure aint ahah what horrible beast this was and still is
  static constexpr size_t size = protocol::nodeReportLength - protocol::nodeReportHeaderLength;
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


// const IPAddress directedBcastIP{2, 255, 255, 255}; // supposed to be where power-up poll-replies go etc.
// TODO maybe: add/contain rdm uid stuff and some IPSender yada so can use this not just
// for self but all other known devices?
struct DeviceNetwork {
  DeviceNetwork() = default;
  DeviceNetwork(IPAddress deviceIP, IPAddress subnet, //IPAddress broadcastIP,
                const uint8_t deviceMAC[6], bool dhcp = true):
    ip(deviceIP), subnet(subnet),
    broadcastIP(IPAddress((uint32_t)ip | ~((uint32_t)subnet))),
    mac(*(mac_t*)deviceMAC), dhcp(dhcp) {
    }
  DeviceNetwork(const DeviceNetwork& rhs):
    DeviceNetwork(rhs.ip, rhs.subnet, rhs.mac.data(), rhs.dhcp) {}
  IPAddress ip, subnet, broadcastIP;
  mac_t mac;
  bool dhcp = true;
  // static constexpr IPAddress directedBcastIP = IPAddress(2, 255, 255, 255); // supposed to be where power-up poll-replies go etc.
};


struct DeviceInfo { // or something. p related.
  DeviceInfo(uint16_t oem = protocol::defaultOem, uint16_t estaMan = protocol::defaultEstaMan, uint16_t fwVersion = 0):
    oem(oem), estaMan(estaMan), fwVersion(fwVersion) {}
  uint16_t oem        = protocol::defaultOem; // hi, lo. OEM code registered with Artistic License. Default UNKNOWN
  uint16_t estaMan    = protocol::defaultEstaMan; // hi, lo. ESTA manufacturer code. Default RESERVED FOR PROTOTYPING
  // there's also an ESTA_DEV some RDM ID for making guids. put here too?  and  "UBEA version"
  // yeah what's our 6byte uid? guess oem + esta is man, but dev?
  uint16_t fwVersion  = 0;    // "Version info", manufacturer defined firmware version.
  enum DeviceType { Controller, Node, MediaServer } type = Node; // XXX reuse Style from pollreply
}; // dunno why the fuck this...


}
