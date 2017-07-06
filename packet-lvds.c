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

static const value_string packet_id_lookup[] = {

    {	0x1001	,  "A429 Block S1	"},
    {	0x1002	,  "A429 Block S2	"},
    {	0x1003	,  "A429 Block S3	"},
    {	0x1004	,  "A429 Block S4	"},
    {	0x1005	,  "A429 Block S5	"},
    {	0x1006	,  "A429 Block S6	"},
    {	0x1007	,  "A429 Block S7	"},
    {	0x1008	,  "A429 Block S8	"},
    {	0x1009	,  "A429 Block S9	"},
    {	0x100a	,  "A429 Block S10	"},
    {	0x100b	,  "A429 Block S11	"},
    {	0x100c	,  "A429 Block S12	"},
    {	0x100d	,  "A429 Block S13	"},
    {	0x2001	,  "A429 Block T1	"},
    {	0x2002	,  "A429 Block T2	"},
    {	0x2003	,  "A429 Block T3	"},
    {	0x4001	,  "A429 Block G1	"},
    {	0x4002	,  "A429 Block G2	"},
    {	0x1080	,  "WXR Display Mode	"},
    {	0x1081	,  "TAWS Display Mode	"},
    {	0x1082	,  "TAWS VSD Packet Header	"},
    {	0x1082	,  "TAWS Flight Path Definition	"},
    {	0x1082	,  "TAWS Flight Segment Definition	"},
    {	0x2080	,  "TCAS TIF Block	"},
    {	0x2081	,  "ADS-B TSF Block	"},
    {	0x2082	,  "Ownship Data Block Note 1	"},
    {	0X2085	,  "ITP Target Data Block Note 1	"},
    {	0X2087	,  "ITP Flight Level Data Block Note 1	"},
    {	0x3080	,  "WXR Map Block	"},
    {	0x4080	,  "TAWS Horizontal Map Block	"},
    {	0x4081	,  "TAWS Vertical Map Block	"},
    {	0x1090	,  "DCA Control and Status	"},
    {	0x2090	,  "TCAS Aural Alert Cue	"},
    {	0x3090	,  "WXR Aural Alert Cue	"},
    {	0x4090	,  "TAWS Aural Alert Cue	"},
    {	0x10a0	,  "Functional Test Control 	"},
    {	0x20a0	,  "TFC Functional Test Response	"},
    {	0x30a0	,  "WXR Functional Test Response	"},
    {	0x40a0	,  "TAWS Functional Test Response	"},
    {	0x20b0	,  "TFC Fault Report	"},
    {	0x30b0	,  "WXR Fault Report	"},
    {	0x40b0	,  "TAWS Fault Report	"},
    {	0x10c0	,  "SysIO SW Data File Query	"},
    {	0x20c0	,  "TFC SW Data File List Report	"},
    {	0x30c0	,  "WXR SW Data File List Report	"},
    {	0x40c0	,  "TAWS SW Data File List Report	"},
    {	0x50c0	,  "WRAU SW Data File List Report	"},
    {	0x10c1	,  "SysIO Part Number Query	"},
    {	0x20c1	,  "TFC Part Number Report	"},
    {	0x30c1	,  "WXR Part Number Report	"},
    {	0x40c1	,  "TAWS Part Number Report	"},
    {	0x50c1	,  "WRAU Part Number Report	"},
    {	0x50c2	,  "RTM Serial Number Report	"},
    {	0x10d0	,  "SysIO Dataload RCR	"},
    {	0x20d0	,  "TFC Dataload RCR	"},
    {	0x30d0	,  "WXR Dataload RCR	"},
    {	0x40d0	,  "TAWS Dataload RCR	"},
    {	0x50d0	,  "WRAU Dataload RCR	"},
    {	0x10e0	,  "TFC Configuration Data	"},
    {	0x20e0	,  "Configuration Data Request	"},
    {	0x10f0	,  "SysIO Sync Request	"},
    {	0x20f0	,  "TFC Sync Request	"},
    {	0x20f1	,  "TFC Sync Response	"},
    {	0x30f0	,  "WxR Sync Request	"},
    {	0x30f1	,  "WxR Sync Response	"},
    {	0x40f0	,  "TAWS Sync Request	"},
    {	0x40f1	,  "TAWS Sync Response	"},
    {	0x1100	,  "SysIO Shop NVRAM Request	"},
    {	0x2100	,  "TFC Shop NVRAM Response	"},
    {	0x3100	,  "WxR Shop NVRAM Response	"},
    {	0x3101	,  "WxR RTM Shop Mode NVRAM Response	"},
    {	0x3102	,  "WxR Ant Cntl NVRAM Response	"},
    {	0x2110	,  "ADS-B Block	"},
    {	0x1115	,  "SysIO Traffic Applications Data Block 	"}
    
};


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
    guint16 packet_id=tvb_get_letohs(tvb, 4);


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LVDS");
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type %s",
             val_to_str(packet_id, packet_id_lookup, "Unknown (0x%02x)"));

    proto_item *ti=proto_tree_add_item(tree, proto_lvds, tvb, 0, -1, ENC_NA);
    proto_item_append_text(ti, ", Type %s",
        val_to_str(packet_id, packet_id_lookup, "Unknown (0x%02x)"));
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

