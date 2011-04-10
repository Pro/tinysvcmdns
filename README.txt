tinysvcmdns
============
tinysvcmdns is a tiny MDNS responder implementation for publishing services.

This implementation is only concerned with publishing services, without a 
system-wide daemon like Bonjour or Avahi. Its other goal is to be extremely 
small, embeddable, and have no external dependencies.

It only answers queries related to its own hostname (the A record), the 
service PTRs, and the "_services.dns-sd._udp.local" name, which advertises 
all services on a particular host.

Services consist of a single SRV and TXT record.

Decoding of MDNS packets is only done to retrieve the questions and answer RRs.
The purpose for decoding answer RRs is to make sure the service PTR is not 
sent out if it is already included in the answer RRs.

It also only utilizes multicast packets, so no "QU" queries are accepted.

There is no name collision detection, so this means no queries are generated
before publishing the services. However compliant responders will avoid using 
our names, since the implementation will respond to queries that match our 
name.


TODO
-----
 * better, more stable & complete API
 * name collision detection


FILES
------
 * mdns.c - provides data structures, parsing & encoding of MDNS packets
 * mdnsd.c - implements the server socket, communication and thread
 * testmdnsd.c - an example that creates an instance until terminated


LICENSE
--------
Copyright (C) 2011 Darell Tan

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

