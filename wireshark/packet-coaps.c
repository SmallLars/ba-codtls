#include "config.h"

#include <epan/packet.h>

#define COAPS_PORT 5684

static int proto_coaps = -1;            // speichert den index des eigenen protokolls
static dissector_handle_t coap_handle;  // coap handle für den aufruf des coap dissectors bei epoch 0

static gint ett_coaps = -1;             // speichert den zustand des unterbaums mit den headerdetails (auf/zu)


static int hf_coaps_recordtype = -1;
static int hf_coaps_version = -1;
static int hf_coaps_epoch = -1;
static int hf_coaps_sequenceno = -1;
static int hf_coaps_length = -1;

static const value_string recordtypenames[] = {
    { 0, "8-Bit-Field" },
    { 1, "Alert" },
    { 2, "Handshake" },
    { 3, "Application Data" }
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
    gint offset = 0;

    if (tree) {
        proto_item *ti = NULL;
        proto_tree *coaps_tree = NULL;
        tvbuff_t *coap_tvb = NULL;

        ti = proto_tree_add_item(tree, proto_coaps, tvb, 0, 3, ENC_NA);
        coaps_tree = proto_item_add_subtree(ti, ett_coaps);
        proto_tree_add_item(coaps_tree, hf_coaps_recordtype, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(coaps_tree, hf_coaps_version, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(coaps_tree, hf_coaps_epoch, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(coaps_tree, hf_coaps_sequenceno, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(coaps_tree, hf_coaps_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        coap_tvb = tvb_new_subset(tvb, 3, tvb_length(tvb) - 3, tvb_reported_length(tvb) - 3);
        call_dissector(coap_handle, coap_tvb, pinfo, coaps_tree);
    }

    // Informationen in der Tabelle am Ende setzten,
    // da diese bei der CoAP-Auswertung überschrieben werden
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CoAPs");
    col_clear(pinfo->cinfo, COL_INFO); // Info-Spalte löschen
}

void proto_reg_handoff_coaps(void) {
    static dissector_handle_t coaps_handle;
    coaps_handle = create_dissector_handle(dissect_coaps, proto_coaps);
    dissector_add_uint("udp.port", COAPS_PORT, coaps_handle);

    coap_handle = find_dissector("coap");
}
