#include "components.h"  // again, shit name

namespace anfr {

Port* Port::atAddress(Universe addr) { // is problem if multiple ports same uni or
  auto hit = std::find_if(allPorts.begin(), allPorts.end(),
      [&addr](auto port) { return addr.address == port->addr.address; });
    if(hit != allPorts.end())
      return *hit;
    return nullptr;
}
Port::Port(Group* parent, uint8_t portAddr, Universe baseUni, int index, PortMode type, uint8_t* dataLoc):
  group(parent), portType(type), index(index), addr(baseUni),
  extBuf(dataLoc),
  bufRaw(dataLoc? dataLoc: new uint8_t[def::dmxBufferSize]) //,
  // dmxBuffer((dmx_buf_t&)bufRaw)
  {
    addr.portAddr = portAddr;
    addr.print();
    allPorts.push_back(this);

    tod.devices.emplace_back(group->devInfo.estaMan, (uint32_t)index ^ addr.address);
}

Port::~Port() {
  if(merge) delete merge;
  if(!extBuf) delete bufRaw;
  auto it = std::find(allPorts.begin(), allPorts.end(), this);
  // auto it = std::find_if(allPorts.begin(), allPorts.end(), [this](std::shared_ptr<Port>& ou) { return this == ou.get(); });
  if(it != allPorts.end()) allPorts.erase(it);
  // XXX also remove from Group maybe or uh nah
}

void Port::updateBuffer(dmx_buf_t& data, size_t length, SenderID senderID) { // too unclear tho, not nice.
  if(merge && senderID > SenderID::Disregard)
    merge->updateAndApply(data, length, senderID);
  else
    // dmxBuffer = data; // XXX all buffers will be 512 so account for actual incoming len
    memcpy(bufRaw, data.data(), length); // XXX all buffers will be 512 so account for actual incoming len
  dmxChans = length; // well not, however could save per sender.
}

void Port::setMerge(bool enable) {
  // if(enable && mergeHTP && !lockedToSource && !merge) {
  if(enable && mergeHTP && !merge) {
      // merge = new Merge(dmxBuffer); // merge.reset(new Merge(dmxBuffer));
      merge = new Merge(bufRaw); // merge.reset(new Merge(dmxBuffer));
  } else if(!enable && merge) {
      delete merge; merge = nullptr; // merge.reset();
  }
}

Group::Group(int index, uint8_t netSwitch, uint8_t subSwitch, DeviceInfo& devInfo):
  addr{0, subSwitch, netSwitch}, index(index), devInfo(devInfo)  {
    addr.print();
}

// yada yada ::forward or ::fwd-tuple-ctor-thingz ya?
int Group::addPort(int p, uint8_t portAddr, PortMode type, uint8_t* extBuf) { // nuking ability to pass own buffer at least for now.
  // if(p < 4 && ports.size() <= 4) { // && p-index isnt busy XXX
    // above cant be right, if size is 4 then full no?
  if(p < 4 && ports.size() < 4) { // && p-index isnt busy XXX
    // ports[p].reset(new Port(this, portAddr, addr, type, p));
    ports.push_back(std::make_shared<Port>(this, portAddr, addr, p, type, extBuf));
    return p;
  }
  return -1; // well, throw some shit but laterz
}
void Group::closePort(Port& port) { closePort(port.index); }
void Group::closePort(uint8_t p) {
  auto port = std::find_if(ports.begin(), ports.end(),
                          [p](auto& po) { return po->index == p; });
  if(port != ports.end()) { // find
    ports.erase(port); // why cant it erase using an iterator?
  } // should prob trigger flush pollreply etc
}


}
