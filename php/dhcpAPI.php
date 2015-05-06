<?php

/**
 * Some handy constants for inclusion..
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
 * @author Pat Winn (pat@patwinn.com)
 * @date 06/17/2010
 * @version 1.0
 *
 * If this file looks funky to you, try setting tab stops=4.
 */


// lease states:
define('L_FREE',			'0x01');	// free lease
define('L_ACTIVE',			'0x02');	// active lease
define('L_EXPIRED',			'0x03');	// expired lease
define('L_RELEASED',		'0x04');	// released lease
define('L_ABANDONED',		'0x05');	// abandoned lease
define('L_RESET',			'0x06');	// reset lease
define('L_BACKUP',			'0x07');	// backup lease
define('L_RESERVED',		'0x08');	// reserved 
define('L_BOOTP',			'0x09');	// bootp

// failover states:
define('F_PARTNER_DOWN',	'0x01');	// partner is down
define('F_NORMAL',			'0x02');	// normal 
define('F_COM_INT',			'0x03');	// communications interrupted
define('F_RES_INT',			'0x04');	// resolution interrupted
define('F_CONFLICT',		'0x05');	// potential conflict
define('F_RECOVER',			'0x06');	// recover
define('F_RECOVER_DONE',	'0x07');	// recovery done
define('F_SHUTDOWN',		'0x08');	// shutdown
define('F_PAUSED',			'0x09');	// paused
define('F_STARTUP',			'0x10');	// startup
define('F_RECOVER_WAIT',	'0x11');	// recover wait

// DHCP packet types
define('D_DISCOVER',		'0x01');	// dhcp discover packet (rfc 2132)
define('D_OFFER',			'0x02');	// dhcp offer packet (rfc 2132)
define('D_REQUEST',			'0x03');	// dhcp request packet (rfc 2132)
define('D_DECLINE',			'0x04');	// dhcp decline packet (rfc 2132)
define('D_ACK',				'0x05');	// dhcp ack packet (rfc 2132)
define('D_NACK',			'0x06');	// dhcp nack packet (rfc 2132)
define('D_RELEASE',			'0x07');	// dhcp release packet (rfc 2132)
define('D_INFORM',			'0x08');	// dhcp information packet (rfc 2132)
define('D_LEASEQUERY',		'0a');		// dhcp lease query packet (rfc 4388)
define('D_LEASEUNASSIGNED',	'0b');		// dhcp lease unassigned packet (rfc 4388)
define('D_LEASEUNKNOWN',   	'0c');		// dhcp lease unassigned packet (rfc 4388)
define('D_LEASEACTIVE',		'0d');		// dhcp lease active packet (rfc 4388)
define('D_BOOTREQUEST',		'01');		// dhcp boot message type
define('D_BOOTREPLY',		'02');		// dhcp boot message type
define('D_ETHERNET',		'01');		// dhcp hardware type - ethernet (other are not needed and thus undefined)
define('D_MAGIC',		'63825363');	// magic number for use in dhcp packets (this is the hex 4 octet value)

?>
