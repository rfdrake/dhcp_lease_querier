
# dhcpleasequery - an HTTP daemon that sends a LEASEQUERY request to a DHCP server and formats the reply as JSON object

This server will only talk to one DHCP server and it blocks waiting for a
response.  I wanted to support querying multiple servers but decided you could
just run multiple daemons and move the concurrency to the requester if you
needed it.

The blocking is an issue.  It may not truly block except in the case of an
unreachable server (that is the only situation I was able to verify the
problem exists).  Getting around it might be difficult because of the protocol
design (you need to use UDP/67 to send and receive).

The replies are extremely quick so I haven't seen problems with it so far, but
if you needed to make hundreds of concurrent requests you might see problems.

## Prerequisites:

    # on Debian you can type this:
    apt-get install net-dhcp-perl libmojolicious-perl

    # on most other systems you can use the Makefile.PL:
    perl Makefile.PL


## Usage:

    sudo perl dhcpleasequery daemon <dhcpserverip>

## In a browser address bar type this:

    http://localhost:3000?address=10.1.1.1

## the reply should look like this:

    [{"DHO_DHCP_MESSAGE_TYPE(53)":"DHCPLEASEUNASSIGNED","DHO_DHCP_SERVER_IDENTIFIER(54)":"192.168.99.15","htype":"0","giaddr":"192.168.1.1","flags":"0","padding [0]":"","DHO_TFTP_SERVER(66)":"code","DHO_DOMAIN_NAME_SERVERS(6)":"10.1.1.2","yiaddr":"0.0.0.0","secs":"0","DHO_DOMAIN_NAME(15)":"direcpath.net","op":"BOOTREPLY","hops":"0","mac_address":"","siaddr":"0.0.0.0","file":"","xid":"93f8446a","ciaddr":"10.1.1.1","sname":"","chaddr":"","hlen":"0"}]


