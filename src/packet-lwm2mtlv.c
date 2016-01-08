
/* packet-lwm2mtlv.c
 * Routines for LWM2M TLV dissection
 * References:
 *     OMA LWM2M Specification
 *
 * Copyright 2015, Christoph Burger-Scheidlin
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>

static int proto_lwm2mtlv = -1;

static void
dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

void
proto_register_foo(void)
{
	proto_lwm2mtlv = proto_register_protocol (
        "LWM2M TLV",
        "lwm2mTLV",
        "lwm2mTLV"
        );
}

void
proto_reg_handoff_foo(void)
{
    static dissector_handle_t lwm2mtlv_handle;

    lwm2mtlv_handle = create_dissector_handle(dissect_foo, proto_lwm2mtlv);
    dissector_add_uint("udp.port", 8080, lwm2mtlv_handle);
}

static void
dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FOO");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);
}

