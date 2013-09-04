#include "config.h"

#include <epan/packet.h>

#define COAPS_PORT 5684

static int proto_coaps = -1;

static dissector_handle_t coap_handle;

static int hf_coaps_pdu_type = -1;

static gint ett_coaps = -1;

void proto_register_coaps(void) {
    static hf_register_info hf[] = {
        { &hf_coaps_pdu_type,
            { "CoAPs PDU Type", "coaps.type",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
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
    if (tree) {
        proto_item *ti = NULL;
        proto_tree *coaps_tree = NULL;
        tvbuff_t *coap_tvb = NULL;

        ti = proto_tree_add_item(tree, proto_coaps, tvb, 0, 3, ENC_NA);
        coaps_tree = proto_item_add_subtree(ti, ett_coaps);
        proto_tree_add_item(coaps_tree, hf_coaps_pdu_type, tvb, 0, 1, ENC_BIG_ENDIAN);

        coap_tvb = tvb_new_subset(tvb, 3, tvb_length(tvb) - 3, tvb_reported_length(tvb) - 3);
        call_dissector(coap_handle, coap_tvb, pinfo, coaps_tree);

        // Informationen in der Tabelle am Ende setzten,
        // da diese bei der CoAP-Auswertung überschrieben werden
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "CoAPs");
        col_clear(pinfo->cinfo, COL_INFO); // Info-Spalte löschen
    }
}

void proto_reg_handoff_coaps(void) {
    static dissector_handle_t coaps_handle;
    coaps_handle = create_dissector_handle(dissect_coaps, proto_coaps);
    dissector_add_uint("udp.port", COAPS_PORT, coaps_handle);

    coap_handle = find_dissector("coap");
}
