/* packet-coaps.c
* Routines for Constrained Application Protocol Secure dissection
* Copyright 2013, Lars Schmertmann <smalllars@t-online.de>
*
* $Id: README.developer,v 1.86 2013/09/05 16:00:00 guy Exp $
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
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include "config.h"

#include <epan/packet.h>

#define COAPS_PORT 5684

static int proto_coaps = -1;
static dissector_handle_t coap_handle;
static gint ett_coaps = -1;

static int hf_coaps_recordtype = -1;
static int hf_coaps_version = -1;
static int hf_coaps_epoch = -1;
static int hf_coaps_sequenceno = -1;
static int hf_coaps_length = -1;

static int hf_coaps_a_recordtype = -1;
static int hf_coaps_a_version_major = -1;
static int hf_coaps_a_version_minor = -1;
static int hf_coaps_a_epoch = -1;
static int hf_coaps_a_sequenceno = -1;
static int hf_coaps_a_length = -1;

static int hf_coaps_alert_level = -1;
static int hf_coaps_alert_description = -1;

static int hf_coaps_appdata = -1;

static const value_string recordtypenames[] = {
    { 0, "8-Bit-Field" },
    { 1, "Alert" },
    { 2, "Handshake" },
    { 3, "Application Data" }
};

static const value_string recordatypenames[] = {
    { 20, "Change Cipher Spec" },
    { 21, "Alert" },
    { 22, "Handshake" },
    { 23, "Application Data" }
};

static const value_string recordversionnames[] = {
    { 0, "DTLS 1.0" },
    { 1, "16-Bit-Field" },
    { 2, "DTLS 1.2" },
    { 3, "Future Use" }
};

static const value_string recordepochnames[] = {
    { 0, "0" },
    { 1, "1" },
    { 2, "2" },
    { 3, "3" },
    { 4, "4" },
    { 5, "8-Bit-Field" },
    { 6, "16-Bit-Field" },
    { 7, "Implicit" }
};

static const value_string recordsequencenonames[] = {
    { 0, "No Value" },
    { 1, "8-Bit-Field" },
    { 2, "16-Bit-Field" },
    { 3, "24-Bit-Field" },
    { 4, "32-Bit-Field" },
    { 5, "40-Bit-Field" },
    { 6, "48-Bit-Field" },
    { 7, "Last Num + 1" }
};

static const value_string recordlengthnames[] = {
    { 0, "0" },
    { 1, "8-Bit-Field" },
    { 2, "16-Bit-Field" },
    { 3, "Last Record in Datagram" }
};

static const value_string alertlevelnames[] = {
    { 1, "Warning" },
    { 2, "Fatal" }
};

static const value_string alertdescriptionnames[] = {
    {   0, "Close Notify" },
    {  10, "Unexpected Message" },
    {  20, "Bad Record MAC" },
    {  21, "Decryption Failed (RESERVED)" },
    {  22, "Record Overflow" },
    {  23, "Decompression Failure" },
    {  40, "Handshake Failure" },
    {  41, "No Certificate (RESERVED)" },
    {  42, "Bad Certificate" },
    {  43, "Unsupported Certificate" },
    {  44, "Certificate Revoked" },
    {  45, "Certificate Expired" },
    {  46, "Certificate Unknown" },
    {  47, "Illegal Parameter" },
    {  48, "Unknown CA" },
    {  49, "Access Denied" },
    {  50, "Decode Error" },
    {  51, "Decrypt Error" },
    {  60, "Export Restriction (RESERVED)" },
    {  70, "Protocol Version" },
    {  71, "Insufficient Security" },
    {  80, "Internal Error" },
    {  90, "User Canceled" },
    { 100, "No Renegotiation" },
    { 110, "Unsupported Extension" }
};

void proto_register_coaps(void) {
    static hf_register_info hf[] = {
        { &hf_coaps_recordtype,
            { "Record Type", "coaps.record.type",
            FT_UINT16, BASE_DEC,
            VALS(recordtypenames), 0x6000,
            NULL, HFILL }
        },
        { &hf_coaps_version,
            { "Record Version", "coaps.record.version",
            FT_UINT16, BASE_DEC,
            VALS(recordversionnames), 0x1800,
            NULL, HFILL }
        },
        { &hf_coaps_epoch,
            { "Record Epoch", "coaps.record.epoch",
            FT_UINT16, BASE_DEC,
            VALS(recordepochnames), 0x0700,
            NULL, HFILL }
        },
        { &hf_coaps_sequenceno,
            { "Record Sequencno", "coaps.record.sequenceno",
            FT_UINT16, BASE_DEC,
            VALS(recordsequencenonames), 0x001C,
            NULL, HFILL }
        },
        { &hf_coaps_length,
            { "Record Length", "coaps.record.length",
            FT_UINT16, BASE_DEC,
            VALS(recordlengthnames), 0x0003,
            NULL, HFILL }
        },
        { &hf_coaps_a_recordtype,
            { "Record Type", "coaps.record.a.type",
            FT_UINT8, BASE_DEC,
            VALS(recordatypenames), 0x00,
            NULL, HFILL }
        },
        { &hf_coaps_a_version_major,
            { "Record Version Major", "coaps.record.a.version.major",
            FT_UINT8, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_coaps_a_version_minor,
            { "Record Version Minor", "coaps.record.a.version.minor",
            FT_UINT8, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_coaps_a_epoch,
            { "Record Epoch", "coaps.record.a.epoch",
            FT_UINT16, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_coaps_a_sequenceno,
            { "Record Sequencno", "coaps.record.a.sequenceno",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_coaps_a_length,
            { "Record Length", "coaps.record.a.length",
            FT_UINT16, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_coaps_alert_level,
            { "Alert Level", "coaps.alert.level",
            FT_UINT8, BASE_DEC,
            VALS(alertlevelnames), 0x00,
            NULL, HFILL }
        },
        { &hf_coaps_alert_description,
            { "Alert Description", "coaps.alert.description",
            FT_UINT8, BASE_DEC,
            VALS(alertdescriptionnames), 0x00,
            NULL, HFILL }
        },
        { &hf_coaps_appdata,
            { "Encrypted Application Data", "coaps.record.appdata",
            FT_BYTES, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_coaps
    };

    proto_coaps = proto_register_protocol (
        "Constrained Application Protocol Secure",  // name
        "CoAPs",                                    // short name
        "coaps"                                     // abbrev
    );

    proto_register_field_array(proto_coaps, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

static void dissect_coaps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    gint8 type = tvb_get_bits8(tvb, 1, 2);
    if (type == 0) {
        type = tvb_get_guint8(tvb, 2);
    } else {
        type += 20;
    }

    if (tree) {
        proto_item *ti = NULL;
        proto_tree *coaps_tree = NULL;
        tvbuff_t *coap_tvb = NULL;
        gint offset = 0;

        gint8 hlen_rt = (tvb_get_bits8(tvb, 1, 2) == 0 ? 1 : 0);
        gint8 hlen_ve = (tvb_get_bits8(tvb, 3, 2) == 1 ? 2 : 0);
        gint8 hlen_ep = tvb_get_bits8(tvb, 5, 3);
        gint8 hlen_sq = tvb_get_bits8(tvb, 11, 3);
        gint8 hlen_le = tvb_get_bits8(tvb, 14, 2);

        gint16 epoch = hlen_ep;
        if (hlen_ep == 5 || hlen_ep == 6) {
            hlen_ep -= 4;
        } else {
            hlen_ep = 0;
        }
        if (hlen_sq == 7) hlen_sq = 0;
        if (hlen_le == 3) hlen_le = 0;

        ti = proto_tree_add_item(tree, proto_coaps, tvb, 0, 2 + hlen_rt + hlen_ve + hlen_ep + hlen_sq + hlen_le, ENC_NA);
        proto_item_append_text(ti, ", Type: %s", val_to_str(type, recordatypenames, "Unknown (0x%02x)"));
        coaps_tree = proto_item_add_subtree(ti, ett_coaps);
        proto_tree_add_item(coaps_tree, hf_coaps_recordtype, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(coaps_tree, hf_coaps_version, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(coaps_tree, hf_coaps_epoch, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(coaps_tree, hf_coaps_sequenceno, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(coaps_tree, hf_coaps_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        if (hlen_rt) { // Record Type
            proto_tree_add_item(coaps_tree, hf_coaps_a_recordtype, tvb, offset, hlen_rt, ENC_BIG_ENDIAN);
            offset += hlen_rt;
        }
        if (hlen_ve) {  // Version
            proto_tree_add_item(coaps_tree, hf_coaps_a_version_major, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(coaps_tree, hf_coaps_a_version_minor, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;;
        }
        if (hlen_ep) { // Epoch
            proto_tree_add_item(coaps_tree, hf_coaps_a_epoch, tvb, offset, hlen_ep, ENC_BIG_ENDIAN);
            offset += hlen_ep;
        }
        if (hlen_sq) { // Sequenceno
            proto_tree_add_item(coaps_tree, hf_coaps_a_sequenceno, tvb, offset, hlen_sq, ENC_BIG_ENDIAN);
            offset += hlen_sq;
        }
        if (hlen_le) { // Length
            proto_tree_add_item(coaps_tree, hf_coaps_a_length, tvb, offset, hlen_le, ENC_BIG_ENDIAN);
            offset += hlen_le;
        }

        if (epoch == 0 && type == 22) { // Handshake Data without Encryption
            coap_tvb = tvb_new_subset(tvb, offset, tvb_length(tvb) - offset, tvb_reported_length(tvb) - offset);
            call_dissector(coap_handle, coap_tvb, pinfo, coaps_tree);
        } else if (epoch == 0 && type == 21) { // Alert without Encryption
            proto_tree_add_item(coaps_tree, hf_coaps_alert_level, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(coaps_tree, hf_coaps_alert_description, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        } else {
            proto_tree_add_item(coaps_tree, hf_coaps_appdata, tvb, offset, tvb_length(tvb) - offset, ENC_NA);
        }
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CoAPs");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(type, recordatypenames, "Unknown (0x%02x)"));
}

void proto_reg_handoff_coaps(void) {
    static dissector_handle_t coaps_handle;
    coaps_handle = create_dissector_handle(dissect_coaps, proto_coaps);
    dissector_add_uint("udp.port", COAPS_PORT, coaps_handle);

    coap_handle = find_dissector("coap");
}
