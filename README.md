# artnet4real

artnet4real aims to be a modern, cross-platform, feature-complete, self-documenting,
standalone C++ Art-Net v4 library including RDM and sACN switching support,
sender merging, and apart from Node/receiver also full Controller/server functionality.
It is likely very few of those things. Or actually it should be pretty full featured by now, but a lot of stuff is untested at this point since I have no application that utilizes remotely all parts of it.

Initially (aka. currently) developed for my own usage with esp-idf v4.0 and C++17,
and still migrating away from Arduino headers.
I'm very much still learning proper modern C++ as I go along, and am aware the code reflects
this. Scrutiny incredibly welcome, contributions even moreso.

Packet definition == packet parsing == packet construction:
- yay bitfield and union abuse bonanza-fest
- nay getters and setters
This makes the driver itself lean and limited to business logic.
It's also probably terrible for cross-platform aims.

While eventually (re)built from scratch it's indebted to existing 
libraries like ArtNode, ola-artnet, espArtNetRDM/espArtNetNode as well as
headers from Artistic-License.

## USAGE
```
using namespace an4r;
auto driver = std::make_unique<artnet::Driver>(...);
```

### Example Configuration:

You need to provide your own networking functions.
With Arduino AsyncUDP:
```
driver->init(ip, sub, mac);

udp.listen(artnet::protocol::defaultUdpPort);
udp.onPacket([this](AsyncUDPPacket& packet) { // mind this bugs out on esp32 without PR #3290
      this->driver->onPacket((uint32_t)packet.remoteIP(), packet.data(), packet.length());
    });

driver->setPacketSendFn([this](ip4_addr_t dest, uint7_t* data, uint16_t length) {
      AsyncUDPMessage packet{length};
      packet.write(data, length);
      this->udp.sendTo(packet, dest, artnet::protocol::defaultUdpPort);
    });

driver->set{bunchOfOtherCallbacks};

driver->begin();
```

More information:
[ArtNet OEM](https://art-net.org.uk/join-the-club/oem-code-listing/),
[ESTA Manufacturer Code](http://tsp.esta.org/tsp/working_groups/CP/mfctrIDs.php),

Future aim is to (optionally) abstract away Groups (4-slots of Artnet ports)
as much as possible. Not yet fully the case. So first add a Group:
```
auto groupId = artnet->...
```
Then add ports:
```
driver->addPort(groupId, portNum, artnet::Universe(...));
```

There is a function to setup bulk ports for a larger buffer and have stuff hamdled reasonably. Works, but needs work.

### Receiving ArtNet/sACN data:

Setup a callback function:
```
driver->setArtDMXCallback([this](...) { ... });
```

### Send Data to ArtNet/sACN:

To send data either provide Universe and data each time (currently supported):
```
  driver->sendDMX(artnet::Universe(...), dataPtr, len);
```
...or set up your ports with persistent output buffers and simply signal to flush:
```
  
  driver->sendDMX(artnet::Universe(...));
```


The driver keeps track of destinations per Art-Net spec.


### Packet examples:

Wha
```
  driver->sendDMX(artnet::Universe(...));
```

### Ethos:
```
union Universe {
  struct {
    union {
      uint8_t subUni;
      struct { uint8_t portAddr: 4, subSwitch: 4; };
    };
    uint8_t netSwitch :7, :1;
  };
  uint16_t :4, netSub: 11, :1;
  uint16_t address: 15, :1;
}
```

