/* packet-lvds.c
 * Routines for LVDS664 protocol packet disassembly
 * By Nick Zhang <zhangzyhack@126.com> <nickzhang@gatech.edu>
 * Copyright Nick Zhang
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
#include <epan/prefs.h>

#define LVDS_PORT 1301

void proto_register_lvds(void);
void proto_reg_handoff_lvds(void);

static int proto_lvds = -1;

static int hf_lvds_unique_word = -1;
static int hf_lvds_payload_size = -1;
static int hf_lvds_packet_id = -1;
static int hf_lvds_payload = -1;
static int hf_lvds_checkword = -1;

static gint ett_lvds = -1;


static guint
get_lvds_payload_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint16 len;
    len = tvb_get_letohs(tvb, offset);
    return len;
}

static int
dissect_lvds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    gint offset=0;
    guint16 payload_len=0;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LVDS");
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti=proto_tree_add_item(tree, proto_lvds, tvb, 0, -1, ENC_NA);
    proto_tree *lvds_tree = proto_item_add_subtree(ti, ett_lvds);
    //pickup the first byte
    proto_tree_add_item(lvds_tree, hf_lvds_unique_word, tvb, 0, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    payload_len = get_lvds_payload_len(pinfo, tvb, offset, data);
    proto_tree_add_item(lvds_tree, hf_lvds_payload_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(lvds_tree, hf_lvds_packet_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(lvds_tree, hf_lvds_payload, tvb, offset, payload_len, ENC_LITTLE_ENDIAN);
    offset += payload_len;
    proto_tree_add_item(lvds_tree, hf_lvds_checkword, tvb, offset, 2, ENC_LITTLE_ENDIAN);

    return tvb_captured_length(tvb);
}


void
proto_register_lvds(void)
{
    //An example
    static hf_register_info hf[] = {
        { &hf_lvds_unique_word,
            { "LVDS Unique Word", "lvds.uniqueword",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_lvds_payload_size,
            { "LVDS Payload Size", "lvds.payloadsize",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_lvds_packet_id,
            { "LVDS Packet ID", "lvds.packetid",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_lvds_payload,
            { "LVDS Payload", "lvds.payload",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_lvds_checkword,
            { "LVDS Checkword", "lvds.checkword",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_lvds
    };

    proto_lvds = proto_register_protocol (
            "LVDS Protocol",
            "LVDS",
            "lvds"
            );

    proto_register_field_array(proto_lvds, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_lvds(void)
{
    static dissector_handle_t lvds_handle;

    lvds_handle = create_dissector_handle(dissect_lvds, proto_lvds);
    dissector_add_uint("udp.port", LVDS_PORT, lvds_handle);
}

