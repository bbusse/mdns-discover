# mdns-discover
mDNS Service discovery

## Installation
```
$ go install github.com/bbusse/mdns-discover@latest
```

## Usage
Show help
```
$ mdns-discover help
```
Run
```
$ mdns-discover
```
Run with filter, regular expressions are not supported
```
$ MDNS_SERVICE_FILTER="" mdns-discover
```
## Build
```
$ git clone https://github.com/bbusse/mdns-discover
$ cd mdns-discover
$ go build
```
## Resources
[mDNS Source: Wikipedia](https://en.wikipedia.org/wiki/Multicast_DNS)  
[https://github.com/hashicorp/mdns](https://github.com/hashicorp/mdns)  
[https://github.com/grandcat/zeroconf/](https://github.com/grandcat/zeroconf/)  
