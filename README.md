# mruby-pcap

mruby interface to libpcap Packet Capture library.

## API

- ``Pcap`` module
  - ``Pcap.lookupdev`` -> String
      - returns a network device name suitable for use with
        ``Pcap::Capture.open_live`` and ``Pcap::lookupnet``.
  - ``Pcap.lookupnet``
  - ``Pcap::DLT_NULL`` ``Pcap::DLT_EN10MB`` ``Pcap::DLT_PPP`` ``Pcap::RAW``
- ``Pcap::Capture`` class
  - .open\_live(device, snaplen, promisc, to\_ms)
      - creates a Capture object to capture packets on live.
  - #capture
  - #close
    - closes sockets to be used to capture packets.
  - #datalink
    - returns the link layer type.
  - #inject(str)
    - injects a raw packet.
  - #setfilter(str)
    - sets a BPF filter program.


## License

Copyright (c) 2013 Internet Initiative Japan Inc.

Permission is hereby granted, free of charge, to any person obtaining a 
copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation 
the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the 
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in 
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
DEALINGS IN THE SOFTWARE.
