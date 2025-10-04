# mdns-discover
mDNS Service Discovery

## Installation
```
$ go install github.com/bbusse/mdns-discover@latest
```

### From source with man page
```
$ git clone https://github.com/bbusse/mdns-discover
$ cd mdns-discover
# Build binary and install man page (uses PREFIX, DESTDIR)
$ make install
```
Default PREFIX is /usr/local. Override:
```
$ make install PREFIX=$HOME/.local
```
(or set DESTDIR for packaging: `make install DESTDIR=/tmp/pkgroot`)

After install, validate:
```
$ which mdns-discover
$ man mdns-discover
```

## Usage
### Show help
```
$ mdns-discover help
```
### Discover all services
```
$ mdns-discover
```
### Specify a timeout (Overrides MDNS_TIMEOUT env)
```
$ mdns-discover --timeout=30s
```
### Discover specific service
Regular expressions are not supported  
The service type without the domain needs to be an exact match
```
$ MDNS_SERVICE_FILTER="_workstation._tcp" mdns-discover
```
### Limit output to specified fields
```
# List of fields must be quoted and comma delimited
$ mdns-discover show-fields "hostname, address, text"
# or via environment
$ MDNS_FIELD_FILTER="hostname, address, text" mdns-discover
```

Allowed field names (case-sensitive): `count`, `service`, `hostname`, `address`, `port`, `text`.
Unknown field names are ignored

### JSON output format
When using `--output=json` the tool prints a single JSON array. Each element (additional fields may appear over time, never removed):
```
{
	"service": "_workstation._tcp",
	"hostname": "Device.local.",
	"address": "192.168.1.23",
	"port": 12345,
	"text": "kv1=v1;kv2=v2",
	"txtMap": { "kv1": "v1", "kv2": "v2" }
}
```
Example
```
$ mdns-discover --output=json
[
	{
		"service": "_raop._tcp",
		"hostname": "MyDevice.local.",
		"address": "192.168.1.23",
		"port": 7000,
		"text": "fv=p20.1",
		"txtMap": { "fv": "p20.1" }
	},
	{
		"service": "_workstation._tcp",
		"hostname": "Another.local.",
		"address": "fe80::1ff:fe23:4567:890a",
		"port": 9,
		"text": ""
	}
]
```

### Concurrency control
Discovery across the built-in service list runs with a bounded number of simultaneous lookups

```
$ mdns-discover --concurrency=5
```

Environment override:
```
$ MDNS_CONCURRENCY=20 mdns-discover
```
Default: 10

### Environment variables summary
| Variable | Purpose | Example |
|----------|---------|---------|
| MDNS_SERVICE_FILTER | Restrict discovery to a single service type | `_workstation._tcp` |
| MDNS_FIELD_FILTER | Comma list of output fields | `hostname,address,port` |
| MDNS_TIMEOUT | Discovery timeout duration | `30s` |
| MDNS_DEBUG | Enable verbose debug (1 / true) | `1` |
| MDNS_CONCURRENCY | Max concurrent service lookups | `15` |


## Build
```
$ git clone https://github.com/bbusse/mdns-discover
$ cd mdns-discover
$ go build
```

### Exit codes
| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Runtime error (discovery or internal failure) |
| 2 | Usage error (invalid flags / arguments) |

### Man page
A machine-generated mdoc man page can be emitted with:
```
$ mdns-discover --man
```
This uses the same metadata source as the interactive help.

## Resources
[mDNS Wikipedia](https://en.wikipedia.org/wiki/Multicast_DNS)  
[mDNS by Stuart Cheshire](http://www.multicastdns.org/)  
[https://github.com/hashicorp/mdns](https://github.com/hashicorp/mdns)  
[https://github.com/grandcat/zeroconf/](https://github.com/grandcat/zeroconf/)  

## Services
| Service Type | Description |
|--------------|-------------|
| _1password._tcp | 1Password Password Manager data sharing and synchronization protocol. |
| _a-d-sync._tcp | Altos Design Synchronization protocol. |
| _abi-instrument._tcp | Applied Biosystems Universal Instrument Framework. |
| _accessdata-f2d._tcp | FTK2 Database Discovery Service. |
| _accessdata-f2w._tcp | FTK2 Backend Processing Agent Service. |
| _accessone._tcp | Strix Systems 5S/AccessOne protocol. |
| _accountedge._tcp | MYOB AccountEdge. |
| _acrobatsrv._tcp | Adobe Acrobat. |
| _actionitems._tcp | ActionItems. |
| _activeraid._tcp | Active Storage Proprietary Device Management Protocol. |
| _activeraid-ssl._tcp | Encrypted transport of Active Storage Proprietary Device Management Protocol. |
| _addressbook._tcp | Address-O-Matic. |
| _adobe-vc._tcp | Adobe Version Cue. |
| _adisk._tcp | Automatic Disk Discovery. |
| _adpro-setup._tcp | ADPRO Security Device Setup. |
| _aecoretech._tcp | Apple Application Engineering Services. |
| _aeroflex._tcp | Aeroflex instrumentation and software. |
| _afpovertcp._tcp | Apple File Sharing. |
| _airport._tcp | AirPort Base Station. |
| _airplay._tcp | Apple AirPlay for streaming audio/video. |
| _airprojector._tcp | AirProjector. |
| _airsharing._tcp | Air Sharing. |
| _airsharingpro._tcp | Air Sharing Pro. |
| _amba-cam._tcp | Ambarella Cameras. |
| _amiphd-p2p._tcp | P2PTapWar Sample Application from "iPhone SDK Development" Book. |
| _animolmd._tcp | Animo License Manager. |
| _animobserver._tcp | Animo Batch Server. |
| _anquetsync._tcp | Anquet map synchronization between desktop and handheld devices. |
| _appelezvous._tcp | Appelezvous. |
| _apple-ausend._tcp | Apple Audio Units. |
| _apple-midi._tcp | Apple MIDI. |
| _apple-sasl._tcp | Apple Password Server. |
| _applerdbg._tcp | Apple Remote Debug Services (OpenGL Profiler). |
| _appletv._tcp | Apple TV. |
| _appletv-itunes._tcp | Apple TV discovery of iTunes. |
| _appletv-pair._tcp | Apple TV Pairing. |
| _aquamon._tcp | AquaMon. |
| _asr._tcp | Apple Software Restore. |
| _astnotify._tcp | Asterisk Caller-ID Notification Service. |
| _astralite._tcp | Astralite. |
| _async._tcp | address-o-sync. |
| _atlassianapp._tcp | Atlassian Application discovery service. |
| _av._tcp | Allen Vanguard Hardware Service. |
| _axis-video._tcp | Axis Video Cameras. |
| _auth._tcp | Authentication Service. |
| _b3d-convince._tcp | 3M Unitek Digital Orthodontic System. |
| _babyphone._tcp | BabyPhone. |
| _bdsk._tcp | Bedside Scanner. |
| _beacon._tcp | Beacon. |
| _beamer._tcp | Beamer. |
| _beatpack._tcp | BeatPack. |
| _beep._tcp | BEEP Protocol. |
| _bfagent._tcp | BitTorrent File Transfer Protocol. |
| _bigbangchess._tcp | Big Bang Chess. |
| _bigbangmancala._tcp | Big Bang Mancala. |
| _bittorrent._tcp | BitTorrent. |
| _blackbook._tcp | BlackBook. |
| _bluevertise._tcp | BlueVertise. |
| _bookworm._tcp | Bookworm. |
| _bootps._tcp | Bootstrap Protocol Server. |
| _boundaryscan._tcp | Boundary Scan. |
| _bousg._tcp | BOUSG. |
| _bri._tcp | BRI. |
| _bsqdea._tcp | Backup! Server. |
| _busycal._tcp | BusyCal. |
| _caltalk._tcp | CalTalk. |
| _cardsend._tcp | CardSend. |
| _cctv._tcp | CCTV. |
| _cheat._tcp | Cheat. |
| _chess._tcp | Chess. |
| _chfts._tcp | CHFTS. |
| _chili._tcp | Chili. |
| _cip4discovery._tcp | CIP4 Discovery. |
| _clipboard._tcp | Clipboard. |
| _clique._tcp | Clique. |
| _clscts._tcp | CLSCTS. |
| _collection._tcp | Collection. |
| _com-ocs-es-mcc._tcp | Microsoft OCS Enhanced Presence. |
| _contactserver._tcp | Contact Server. |
| _corroboree._tcp | Corroboree. |
| _cpnotebook2._tcp | Canon Photo Notebook 2. |
| _cvspserver._tcp | CVS pserver. |
| _cw-codetap._tcp | CodeTap. |
| _cw-dpitap._tcp | DPI Tap. |
| _cw-oncetap._tcp | OnceTap. |
| _cw-powertap._tcp | PowerTap. |
| _cytv._tcp | CyTV. |
| _daap._tcp | iTunes Sharing. |
| _dacp._tcp | Digital Audio Control Protocol. |
| _dancepartner._tcp | Dance Partner. |
| _dataturbine._tcp | Data Turbine. |
| _device-info._tcp | Generic device information service. |
| _difi._tcp | DIFI. |
| _disconnect._tcp | Disconnect. |
| _dist-opencl._tcp | OpenCL Distributed. |
| _distcc._tcp | DistCC. |
| _ditrios._tcp | DitriOS. |
| _divelogsync._tcp | Dive Log Sync. |
| _dltimesync._tcp | DL Time Sync. |
| _dns-llq._tcp | DNS LLQ. |
| _dns-sd._tcp | DNS-SD. |
| _dns-update._tcp | DNS Update. |
| _domain._tcp | Domain. |
| _dop._tcp | DOP. |
| _dossier._tcp | Dossier. |
| _dpap._tcp | Digital Photos Access Protocol. |
| _dropcopy._tcp | Drop Copy. |
| _dsl-sync._tcp | DSL Sync. |
| _dtrmtdesktop._tcp | DTRMT Desktop. |
| _dvbservdsc._tcp | DVB Service Discovery. |
| _dxtgsync._tcp | DXTG Sync. |
| _ea-dttx-poker._tcp | EA DT TX Poker. |
| _earphoria._tcp | Earphoria. |
| _eb-amuzi._tcp | EB Amuzi. |
| _ebms._tcp | EBMS. |
| _ecms._tcp | ECMS. |
| _ebreg._tcp | EBREG. |
| _ecbyesfsgksc._tcp | ECB Yes FSG KSC. |
| _edcp._tcp | EDCP. |
| _egistix._tcp | Egistix. |
| _eheap._tcp | EHeap. |
| _embrace._tcp | Embrace. |
| _ep._tcp | EP. |
| _eppc._tcp | Apple Events. |
| _erp-scale._tcp | ERP Scale. |
| _esp._tcp | ESP. |
| _eucalyptus._tcp | Eucalyptus. |
| _eventserver._tcp | Event Server. |
| _evs-notif._tcp | EVS Notification. |
| _ewalletsync._tcp | EWallet Sync. |
| _example._tcp | Example. |
| _exec._tcp | Exec. |
| _extensissn._tcp | Extensis SN. |
| _eyetvsn._tcp | EyeTV SN. |
| _facespan._tcp | FaceSpan. |
| _fairview._tcp | Fairview. |
| _faxstfx._tcp | FaxStFX. |
| _feed-sharing._tcp | Feed Sharing. |
| _firetask._tcp | FireTask. |
| _fish._tcp | Fish. |
| _fix._tcp | FIX. |
| _fjork._tcp | Fjork. |
| _fl-purr._tcp | FL Purr. |
| _fmpro-internal._tcp | FMPro Internal. |
| _fmserver-admin._tcp | FM Server Admin. |
| _fontagentnode._tcp | FontAgent Node. |
| _foxtrot-serv._tcp | Foxtrot Serv. |
| _foxtrot-start._tcp | Foxtrot Start. |
| _frameforge-lic._tcp | FrameForge Lic. |
| _freehand._tcp | FreeHand. |
| _frog._tcp | Frog. |
| _ftp._tcp | File Transfer Protocol. |
| _ftpcroco._tcp | FTPCroco. |
| _fv-cert._tcp | FV Cert. |
| _fv-key._tcp | FV Key. |
| _fv-time._tcp | FV Time. |
| _garagepad._tcp | GaragePad. |
| _gbs-smp._tcp | GBS SMP. |
| _gbs-stp._tcp | GBS STP. |
| _gforce-ssmp._tcp | GForce SSMP. |
| _glasspad._tcp | GlassPad. |
| _glasspadserver._tcp | GlassPadServer. |
| _glrdrvmon._tcp | GLRDrvMon. |
| _gpnp._tcp | GPnP. |
| _grillezvous._tcp | GrillezVous. |
| _growl._tcp | Growl. |
| _guid._tcp | GUID. |
| _h323._tcp | H.323. |
| _helix._tcp | Helix. |
| _help._tcp | Help. |
| _hg._tcp | HG. |
| _hinz._tcp | Hinz. |
| _hmcp._tcp | HMCP. |
| _home-sharing._tcp | Home Sharing. |
| _homeauto._tcp | HomeAuto. |
| _honeywell-vid._tcp | Honeywell VID. |
| _hotwayd._tcp | Hotwayd. |
| _howdy._tcp | Howdy. |
| _hpr-bldlnx._tcp | HPR BLD LNX. |
| _hpr-bldwin._tcp | HPR BLD WIN. |
| _hpr-db._tcp | HPR DB. |
| _hpr-rep._tcp | HPR REP. |
| _hpr-toollnx._tcp | HPR Tool LNX. |
| _hpr-toolwin._tcp | HPR Tool WIN. |
| _hpr-tstlnx._tcp | HPR TST LNX. |
| _hpr-tstwin._tcp | HPR TST WIN. |
| _hs-off._tcp | HS Off. |
| _htsp._tcp | HTSP. |
| _http._tcp | Web server (HTTP). |
| _https._tcp | Secure Web server (HTTPS). |
| _hydra._tcp | Hydra. |
| _hyperstream._tcp | HyperStream. |
| _iax._tcp | IAX. |
| _ibiz._tcp | iBiz. |
| _ica-networking._tcp | ICA Networking. |
| _ican._tcp | ICAN. |
| _ichalkboard._tcp | iChalkboard. |
| _ichat._tcp | iChat. |
| _iconquer._tcp | iConquer. |
| _idata._tcp | iData. |
| _idsync._tcp | ID Sync. |
| _ifolder._tcp | iFolder. |
| _ihouse._tcp | iHouse. |
| _ii-drills._tcp | II Drills. |
| _ii-konane._tcp | II Konane. |
| _ilynx._tcp | iLynx. |
| _imap._tcp | IMAP. |
| _imidi._tcp | iMidi. |
| _indigo-dvr._tcp | Indigo DVR. |
| _inova-ontrack._tcp | Inova OnTrack. |
| _ipbroadcaster._tcp | IP Broadcaster. |
| _ipp._tcp | Internet Printing Protocol. |
| _ipspeaker._tcp | IPSpeaker. |
| _irelay._tcp | iRelay. |
| _irmc._tcp | IRMC. |
| _iscsi._tcp | iSCSI. |
| _isparx._tcp | iSparx. |
| _ispq-vc._tcp | ISPQ VC. |
| _ishare._tcp | iShare. |
| _isticky._tcp | iSticky. |
| _istorm._tcp | iStorm. |
| _itis-device._tcp | iTIS Device. |
| _itsrc._tcp | iTunes Socket Remote Control. |
| _ivef._tcp | Inter VTS Exchange Format. |
| _iwork._tcp | iWork Server. |
| _jcan._tcp | Northrup Grumman/TASC/JCAN Protocol. |
| _jeditx._tcp | JEdit X. |
| _jini._tcp | Jini. |
| _jtag._tcp | JTAG. |
| _kerberos._tcp | Kerberos. |
| _kerberos-adm._tcp | Kerberos Admin. |
| _ktp._tcp | KTP. |
| _labyrinth._tcp | Labyrinth. |
| _lan2p._tcp | LAN2P. |
| _lapse._tcp | Lapse. |
| _lanrevagent._tcp | LanRevAgent. |
| _lanrevserver._tcp | LanRevServer. |
| _ldap._tcp | LDAP. |
| _leaf._tcp | Leaf. |
| _lexicon._tcp | Lexicon. |
| _liaison._tcp | Liaison. |
| _library._tcp | Library. |
| _llrp._tcp | LLRP. |
| _llrp-secure._tcp | LLRP Secure. |
| _lobby._tcp | Lobby. |
| _logicnode._tcp | LogicNode. |
| _login._tcp | Login. |
| _lonbridge._tcp | LonBridge. |
| _lontalk._tcp | LonTalk. |
| _lonworks._tcp | LonWorks. |
| _lsys-appserver._tcp | LSYS AppServer. |
| _lsys-camera._tcp | LSYS Camera. |
| _lsys-ezcfg._tcp | LSYS EZCFG. |
| _lsys-oamp._tcp | LSYS OAMP. |
| _lux-dtp._tcp | LUX DTP. |
| _lxi._tcp | LXI. |
| _lyrics._tcp | Lyrics. |
| _macfoh._tcp | MacFOH. |
| _macfoh-admin._tcp | MacFOH Admin. |
| _macfoh-audio._tcp | MacFOH Audio. |
| _macfoh-events._tcp | MacFOH Events. |
| _macfoh-data._tcp | MacFOH Data. |
| _macfoh-db._tcp | MacFOH DB. |
| _macfoh-remote._tcp | MacFOH Remote. |
| _macminder._tcp | MacMinder. |
| _maestro._tcp | Maestro. |
| _magicdice._tcp | Magic Dice. |
| _mandos._tcp | Mandos. |
| _matrix._tcp | Matrix. |
| _mbconsumer._tcp | MB Consumer. |
| _mbproducer._tcp | MB Producer. |
| _mbserver._tcp | MB Server. |
| _mconnect._tcp | MConnect. |
| _mcrcp._tcp | MCRCP. |
| _mediaboard1._tcp | MediaBoard1. |
| _mesamis._tcp | MesAmis. |
| _mimer._tcp | Mimer. |
| _mi-raysat._tcp | MI RaySat. |
| _modolansrv._tcp | ModolanSrv. |
| _moneysync._tcp | MoneySync. |
| _moneyworks._tcp | MoneyWorks. |
| _moodring._tcp | MoodRing. |
| _mother._tcp | Mother. |
| _movieslate._tcp | MovieSlate. |
| _mp3sushi._tcp | MP3Sushi. |
| _mqtt._tcp | MQTT. |
| _mslingshot._tcp | MSLingshot. |
| _mumble._tcp | Mumble. |
| _raop._tcp | Remote Audio Output Protocol. |
| _rdlink._tcp | Remote Desktop Link. |
| _rdp._tcp | Remote Desktop Protocol. |
| _sftp-ssh._tcp | SSH File Transfer Protocol. |
| _sonos._tcp | Sonos. |
| _spotify-connect._tcp | Spotify Connect. |
| _spotify-social-listening._tcp | Spotify Social Listening. |
| _ssh._tcp | Secure Shell. |
| _wled._tcp | WLED. |
| _workstation._tcp | Workstation. |
