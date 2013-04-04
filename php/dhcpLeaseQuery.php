<?

/**
 * This class performs a dhcp lease query and passes back
 * all info pertaining to the lease. 
 *
 * Copyright (c) 2010 by Pat Winn (pat@patwinn.com)
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND PAT WINN DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL PAT WINN BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * Portions of the parser code were adapted from code originally written by
 * Angelo R. DiNardi (angelo@dinardi.name). 
 * 
 * Many thanks also to all those in the ISC DHCP hacker community and the
 * folks at ISC who chimed in to help figure this stuff out. Without the
 * input..I would never have gotten to this point.  :-)
 *
 * If this file looks funky to you, try setting tab stops=4.
 *
 * @author Pat Winn (pat@patwinn.com)
 * @date 06/17/2010
 * @version 1.0
 */

require_once("dhcpAPI.php");

class dhcpLeaseQuery
{

	// contains packet data
	private $packet 	= Array();

	// actual packet to be sent or received
	private $myPacket 	= '';

	// what to use for our giaddr (where will we send the leaseactive/etc. packets back to)
	private $my_giaddr 	= '';

	// IP address of the dhcpd server
	private $my_server = '';

	// our socket handle
	private $socket 	= '';

	// the lease info packet we hope to get back
	public $lease = '';

	// data types for given options
	private $options = '';

	// array containing the various message types we may encounter
	private $messageTypes = '';

	/**
	 * Constructor
	 * @$myGiaddr = IP address to use for giaddr field
	 * @$dhcpServer = IP address of the dhcpd server we want to query
	 * @returns nothing
	 */
	function __construct(&$myGiaddr, &$dhcpServer) {
		$this->my_giaddr = $myGiaddr;
		$this->my_server = $dhcpServer;

	    $this->options = array(
			1  => array('name' => 'subnet_mask', 'type' => 'ip'),
			2  => array('name' => 'time_offset', 'type' => 'int'),
			3  => array('name' => 'router', 'type' => 'ip'),
			6  => array('name' => 'dns_server', 'type' => 'ip'),
			7  => array('name' => 'log_server', 'type' => 'ip'),
			12 => array('name' => 'host_name', 'type' => 'string'),
			15 => array('name' => 'domain_name', 'type' => 'string'),
			23 => array('name' => 'ttl', 'type' => 'int'),
			28 => array('name' => 'broadcast_address', 'type' => 'ip'),
			43 => array('name' => 'vendor_specific', 'type' => 'string'),
			50 => array('name' => 'requested_ip_address', 'type' => 'ip'),
			51 => array('name' => 'lease_time', 'type' => 'int'),
			53 => array('name' => 'message_type', 'type' => 'messageType'),
			54 => array('name' => 'server_id', 'type' => 'ip'),
			55 => array('name' => 'parameter_request', 'type' => 'binary'),
			57 => array('name' => 'max_message_size', 'type' => 'int'),
			58 => array('name' => 'renewal_time', 'type' => 'int'),
			59 => array('name' => 'rebinding_time', 'type' => 'int'),
			61 => array('name' => 'client_id', 'type' => 'mac'),
			60 => array('name' => 'vendor_class_identifier', 'type' => 'string'),
			66 => array('name' => 'tftp_server', 'type' => 'string'),
			82 => array('name' => 'option-82', 'type' => 'string'),
			91 => array('name' => 'client-last-transaction-time', 'type' => 'int'),
			92 => array('name' => 'associated-ip', 'type' => 'string')
		);

		$this->messageTypes = array(
			1 => 'discover',
			2 => 'offer',
			3 => 'request',
			4 => 'decline',
			5 => 'ack',
			6 => 'nak',
			7 => 'release',
			8 => 'inform',
			10 => 'DHCPLEASEQUERY',
			11 => 'DHCPLEASEUNASSIGNED',
			12 => 'DHCPLEASEUNKNOWN',
			13 => 'DHCPLEASEACTIVE'
		);

		// build the basic packet 
		$this->packet['op'] 	= D_BOOTREQUEST;
		$this->packet['htype'] 	= D_ETHERNET;
		$this->packet['hlen'] 	= '06';
		$this->packet['hops'] 	= '00';
		$this->packet['xid'] 	= sprintf("%08x\n", mt_rand(0, 0xFFFFFF));
		$this->packet['secs'] 	= '0000';
		$this->packet['flags'] 	= '0000';
		$this->packet['yiaddr'] = $this->ip2hex("0.0.0.0");
		$this->packet['siaddr'] = $this->ip2hex("0.0.0.0");
		$this->packet['giaddr'] = $this->ip2hex($myGiaddr);
		$this->packet['chaddr'] = $this->pad('', 32);
		$this->packet['sname'] 	= $this->pad('', 128);
		$this->packet['file'] 	= $this->pad('', 256);
		$this->packet['magic'] 	= D_MAGIC;
		$this->packet['options']  = $this->int2hex(53) . $this->int2hex(1) . D_LEASEQUERY;
		$this->packet['options'] .= $this->int2hex(55) . $this->int2hex(count($this->options));

		// add all possible options to the list and see what all we get back..
		foreach($this->options as $k => $v) {
			$this->packet['options'] .= $this->int2hex($k);
		}

		// don't forget the end octet!
		$this->packet['options'] .= $this->int2hex(255);
	}

	/**
	 * Send a DHCPLEASEQUERY packet to the remote dhcpd
	 * @$ipaddr = IP address to query information for
	 * @returns true if sent, false if not
	 */
	public function sendQuery(&$ipaddr) {
		// add the client ip that we want to query for to the packet
		$this->packet['ciaddr'] = $this->ip2hex($ipaddr);

		// pack it into binary fun..
		$this->myPacket = 
			pack("H2H2H2H2H8H4H4H8H8H8H8H32H128H256H8H*",
				$this->packet['op'], $this->packet['htype'], $this->packet['hlen'], 
				$this->packet['hops'], $this->packet['xid'], $this->packet['secs'], 
				$this->packet['flags'], $this->packet['ciaddr'], $this->packet['yiaddr'], 
				$this->packet['siaddr'], $this->packet['giaddr'], $this->packet['chaddr'], 
				$this->packet['sname'], $this->packet['file'],
				$this->packet['magic'], $this->packet['options']
			);

		// open a socket to the server
		$this->socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
		socket_set_option($this->socket, SOL_SOCKET, SO_BROADCAST, 1);
		socket_bind($this->socket, $this->my_giaddr, 67);

		// send the packet (finally)..
		$error = socket_sendto($this->socket, $this->myPacket, 
			strlen($this->myPacket), 0, $this->my_server, 67);

		if ($error === FALSE) {
			print("Send failed for address");
			print_r("ERROR: ". $error ." while trying to send.");
			return(false);
		} else {
			#echo "Sent ". $error ." bytes\n";
			return(true);
		}
	}

	/**
	 * Receive a lease query response packet
	 * @returns array with lease info or false if failure
	 */
	public function receive() {
		if($this->socket == null) {
			$this->socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
			socket_set_option($this->fp, SOL_SOCKET, SO_REUSEADDR, 1);
			socket_bind($this->socket, $this->my_giaddr, 67);
		}

		$pkt = false;
		$port = 67;

		if (false !== ($pkt = socket_recvfrom($this->socket, $buf, 8192, 0, $this->my_server, $port))) {
			$this->log('leaseQuery.php: '. "Rec: ". $pkt . "\nbytes:: ". $buf);
		} else {
			$this->log('leaseQuery.php: '. "ERR: ". socket_strerror(socket_last_error($this->socket)));
			return(false);
		}	

		// close the listener socket
		try {
			socket_close($this->socket);
		} catch(Exception $t) {}

		// parse the packet and save off the data in our array
		$this->parse($buf);

		if($this->parse($buf) !== false) {
			return($this->lease);
		} else {
			return(false);
		}
	}

	/**
	 * Parse an incoming packet and put it's contents into an array
	 * @$_pkt = packet payload to parse
	 */
	private function parse($_pkt) {
		// unpack the binary octets from the packet payload into something we can work with
		$_format  = "H2op/H2htype/H2hlen/H2hops/H8xid/H4secs/H4flags/H8ciaddr/";
		$_format .= "H8yiaddr/H8siaddr/H8giaddr/H32chaddr/H128sname/H256file/H8magic/H*options";
		$this->lease = unpack($_format, $_pkt);	

		// check the packet's magic number and return out without doing anything if bad
		if(!$this->lease['magic'] == '63825363') {
			$this->log("BAD MAGIC: ". $this->lease['magic']);
			return(false);
		}

		// grab the options field from the payload and save it for later
		$optionData = $this->lease['options'];
		$pos = 0;

		$this->lease['cid'] = '';	// option 82 circuit id
		$this->lease['rid'] = '';	// option 82 remote id

		// loop through all the options sent to us and parse things out
		// (this is ugly and should be cleaned up/optimized some later..<blush>)
        while(strlen($optionData) > $pos) {
			// get the code number for the current option
			$code = base_convert(substr($optionData, $pos, 2), 16, 10);
			$pos += 2;

			// get the option field length for the current option
			$len = base_convert(substr($optionData, $pos, 2), 16, 10);
			$pos += 2;

			// get the bytes that make up the current option info
			$curoptdata = substr($optionData, $pos, $len*2);
			$pos += $len*2;

			// attempt to look up the data type, etc. for the current option code/type
            if (isset($this->options[$code])) {
			    $optinfo = $this->options[$code];
            }

			// if we found the code in the list..parse things out
			if($optinfo !== null) {
				$translatedData = null;

				// check the data type and determine how to parse it
				switch($optinfo['type']) {
    				case 'int':
						$translatedData = base_convert($curoptdata, 16, 10);
						break;
    				case 'string':
						// if we are dealing with option 82, loop through it's sub options
						// as appropriate
						if($code == 82) {
							$_pos = 0;
							$o82 = substr($curoptdata, $_pos, $len*2);

							while(strlen($o82) > $_pos) {
								$_code = base_convert(substr($o82, $_pos, 2), 16, 10);
								$_pos += 2;
								$_len = base_convert(substr($o82, $_pos, 2), 16, 10);
								$_pos += 2;
								$curo82 = substr($o82, $_pos, $_len*2);
								$_pos += $_len*2;
								
								// why in the heck does sub-option 2 not convert the same as
								// sub-option 1 (cid)? It's in the same format and
								// should convert the same. FIX THIS!!!!!
								($_code == 1) ? $field = "cid" : $field = "rid";
								$this->lease[$field] = $this->hex2str($curo82);
							}
						} else {
							$translatedData = $this->hex2str($curoptdata);
						}
						break;

    				case 'ip':
						$translatedData = $this->hex2ip($curoptdata);
						break;

    				case 'messageType':
						$translatedData = $this->messageTypes[$this->hex2int($curoptdata)];
						break;

    				default:
						$translatedData = $curoptdata;
				}

				$this->lease[$optinfo['name']] = $translatedData;
    		} else {
				$this->lease[$code] = $curoptdata;
			}
		}

		// Now clean up a few of the values a bit further.
		// ** Note that I've put most of these into try/catch blocks but have not added
		// ** any real error handling to most. Just let it keep going without breaking for now.
		try {
			$this->lease['chaddr'] = $this->str2mac(substr($this->lease['chaddr'], 0, 12));
		} catch(Exception $e0) {}

		try {
            # PHP's exception handling is fairly dumb.  It warns about this
            # even though it's in a try {} block
            if (isset($this->lease['client_id'])) {
			    $this->lease['client_id'] = substr($this->lease['client_id'], 2);
            }
		} catch(Exception $e1) {}

		try {
			$this->lease['ciaddr'] = $this->hex2ip($this->lease['ciaddr']);
		} catch(Exception $e3) {}

		try {
			$this->lease['yiaddr'] = $this->hex2ip($this->lease['yiaddr']);
		} catch(Exception $e4) {}

		try {
			$this->lease['siaddr'] = $this->hex2ip($this->lease['siaddr']);
		} catch(Exception $e5) {}

		try {
			$this->lease['giaddr'] = $this->hex2ip($this->lease['giaddr']);
		} catch(Exception $e6) {}

		// set the start/end/renew/rebind/total times to a human readable date/time
		// before altering their values below
		$this->setTimes(
			$this->lease['lease_time'], 
			$this->lease['renewal_time'], 
			$this->lease['rebinding_time'], 
			$this->lease['client-last-transaction-time']
		);

		try {
			$this->lease['lease_time'] = $this->toDateStr($this->lease['lease_time']);
		} catch(Exception $e7) {}

		try {
			$this->lease['renewal_time'] = $this->toDateStr($this->lease['renewal_time']);
		} catch(Exception $e8) {}

		try {
			$this->lease['rebinding_time'] = $this->toDateStr($this->lease['rebinding_time']);
		} catch(Exception $e8) {}

		try {
			$this->lease['client-last-transaction-time'] = $this->toDateStr($this->lease['client-last-transaction-time']);
		} catch(Exception $e9) {}
	}

	/**
	 * Convert the lease start/end/renewal/rebinding/cltt seconds to real dates/times in mysql format
	 * Also set the total number of seconds the lease was given for
	 * @$_lt = lease time in seconds (no relation to the epoch)
	 * @$_rt = renewal time in seconds (no relation to the epoch)
	 * @$_bt = rebinding time in seconds (no relation to the epoch)
	 * @$_ct = client last transmission time (no relation to the epoch)
	 * @returns nothing, merely attempts to add the appropriate fields to the lease array which
	 *          already contains the rest of the current lease info
	 */
	private function setTimes(&$_lt, &$_rt, &$_bt, &$_ct) {
		try {
			$_now = time();
			$startSecs = ($_now - $_ct);
			$totalSecs = ($_ct + $_lt);

			$this->lease['curTime'] = date("Y-m-d H:i:s");
			$this->lease['clttTime']  = date("Y-m-d H:i:s", $startSecs);
			$this->lease['startTime'] = date("Y-m-d H:i:s", $startSecs);
			$this->lease['renew']   = date("Y-m-d H:i:s", ($_now + $_rt));
			$this->lease['rebind']  = date("Y-m-d H:i:s", ($_now + $_bt));
			$this->lease['endTime'] = date("Y-m-d H:i:s", ($startSecs + $totalSecs));
			$this->lease['leaseTime'] = $totalSecs;
		} catch(Exception $t) {}
	}

	/**
	 * Convert a string to mac address w/ :'s inserted
	 * @$s = string to convert
	 * @returns converted string or original string if error
	 */
	private function str2mac($s) {
		try {
			$oct1 = $s{0} . $s{1};
			$oct2 = $s{2} . $s{3};
			$oct3 = $s{4} . $s{5};
			$oct4 = $s{6} . $s{7};
			$oct5 = $s{8} . $s{9};
			$oct6 = $s{10} . $s{11};
			return($oct1 .":". $oct2 .":". $oct3 .":". $oct4 .":". $oct5 .":". $oct6);
		} catch(Exception $r) {
			return($s);
		}
	}

	/**
	 * Convert a value to hex
	 * @$s = value to convert
	 * @returns converted hex value or -1 upon failure
	 */
	private function str2hex($s) {
		$hex = '';
	
		try {
			for ($i = 0 ; $i < strlen($s); $i++) {
				$hex .= dechex(ord($s[$i]));
			}
		} catch(Exception $x) {
			return(-1);
		}

		return($hex);
	}

	/**
	 * Convert a hex value to string
	 * @$hex = hex octet(s) to convert
	 * @returns converted string or false upon failure
	 */
    private function hex2str($hex) {
        $str = '';

        for ($i = 0 ; $i < strlen($hex) - 1 ; $i += 2) {
            $str .= chr(hexdec($hex[$i] . $hex[$i + 1]));
        }

        return($str);
    }

	// convert an ip address to hex values
	/*
	 * Convert an IP address to hex octets
	 * @$ip = IP address to convert
	 * @returns converted IP or -1 if failure
	 */
	private function ip2hex($ip) {
		$t = explode(".", $ip);

		try {
			$hex = $this->int2hex($t[0]) . $this->int2hex($t[1]) . $this->int2hex($t[2]) . $this->int2hex($t[3]);
			return($hex);
		} catch(Exception $y) {
			return(-1);
		}
	}

	/**
	 * Convert a hex value back to an ip address
	 * @$hex = value to convert
	 * @returns string containing ip address or -1 upon failure
	 */
	private function hex2ip($hex) {
		$retVal = -1;

		try {
			$retVal = 
				$this->hex2int($hex[0] . $hex[1]) .".".
				$this->hex2int($hex[2] . $hex[3]) .".".
				$this->hex2int($hex[4] . $hex[5]) .".".
				$this->hex2int($hex[6] . $hex[7]);
		} catch(Exception $r) {
			$retVal = -1;
		}

		return($retVal);
	}

	/*
	 * Convert an int value to a 0 padded hex value
	 * @$int = int to pad
	 * @returns padded value or -1 if failure
	 */
	private function int2hex($int) {
		try {
			$hex = base_convert($int, 10, 16);

			switch(strlen($hex)) {
				case 1: 
				case 3: 
				case 7: $hex = '0' . $hex; break;
				case 5: $hex = '000' . $hex; break;
			}

			return $hex;
		} catch(Exception $z) {
			return(-1);
		}
	}

	/**
	 * Convert a hex value back to an int value
	 * @$hex = value to convert
	 * @returns converted int value or -1 if failure
	 */
    private function hex2int($hex) {
		$retVal = -1;

		try {
        	$retVal = base_convert($hex, 16, 10);
		} catch(Exception $g) {
			$retVal = -1;
		}

		return($retVal);
    }

	/**
	 * Convert an int to number of days/hours/mins/secs
	 * Has no relation to the epoch, just the number of days/hours/mins/secs
	 * @$t = number to convert
	 * @returns string containing days, hours, mins, secs padded w/ 0's if applicable
	 */
	private function toDateStr($t) {
		$hours	= $this->lpad(intVal($t / 3600), 2);
		$days 	= $this->lpad(intVal($hours / 24), 2);
		$mins	= $this->lpad(intVal(($t / 60) - ($hours * 60)), 2);
		$secs	= $this->lpad(intVal($t % 60), 2);

		return($days ."d ". $hours ."h ". $mins ."m ". $secs ."s");
	}

	/**
 	 * Pad a field to a given number of 0's
 	 * @$s = string to add padding to (defaults to right side pad)
 	 * @$cnt = number of 0's to pad with
 	 * @returns padded string
 	 */
	private function pad($s, $cnt) {
		return(str_pad($s, $cnt, '0'));
	}

	/**
 	 * Pad a field to a given number of 0's
 	 * @$s = string to add padding to (defaults to left side pad)
 	 * @$cnt = number of 0's to pad with
 	 * @returns padded string
 	 */
	private function lpad($s, $cnt) {
		return(str_pad($s, $cnt, '0', STR_PAD_LEFT));
	}

	/**
	 * debug function...
	 */
	private function log($s) {
		$fp = fopen('/var/log/dhcp.log', 'a+');
		fputs($fp, $s ."\n");
		fclose($fp);
	}
}

?>
