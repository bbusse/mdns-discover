# mdns-discover
mDNS Service Discovery

## Installation
```
$ go install github.com/bbusse/mdns-discover@latest
```

## Usage
Show help
```
$ mdns-discover help
```
Run with filter  
Regular expressions are not supported  
The service type without the domain needs to be an exact match
```
$ MDNS_SERVICE_FILTER="_workstation._tcp" mdns-discover
```
## Build
```
$ git clone https://github.com/bbusse/mdns-discover
$ cd mdns-discover
$ go build
```
## Resources
[mDNS Wikipedia](https://en.wikipedia.org/wiki/Multicast_DNS)  
[mDNS by Stuart Cheshire](http://www.multicastdns.org/)  
[https://github.com/hashicorp/mdns](https://github.com/hashicorp/mdns)  
[https://github.com/grandcat/zeroconf/](https://github.com/grandcat/zeroconf/)  
