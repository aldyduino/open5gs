#include <limits.h>

#include "asn1c/util/message.h"

#include "s1ap-build.h"

ogs_pkbuf_t *s1ap_build_downlink_ue_associated_lppa_transport(
        enb_ue_t *enb_ue, uint8_t routing_id,
        const uint8_t *payload, size_t payload_len)
{
    ogs_s1ap_message_t pdu;
    S1AP_InitiatingMessage_t *initiating_message = NULL;
    S1AP_DownlinkUEAssociatedLPPaTransport_t *transport = NULL;
    S1AP_DownlinkUEAssociatedLPPaTransport_IEs_t *ie = NULL;

    ogs_assert(enb_ue);
    if (!payload || !payload_len || payload_len > INT_MAX ||
        enb_ue->enb_ue_s1ap_id == INVALID_UE_S1AP_ID ||
        enb_ue->mme_ue_s1ap_id == INVALID_UE_S1AP_ID) {
        ogs_error("Invalid downlink LPPA transport parameters");
        return NULL;
    }

    memset(&pdu, 0, sizeof(pdu));
    pdu.present = S1AP_S1AP_PDU_PR_initiatingMessage;
    pdu.choice.initiatingMessage = CALLOC(1, sizeof(*initiating_message));
    initiating_message = pdu.choice.initiatingMessage;
    ogs_assert(initiating_message);
    initiating_message->procedureCode =
        S1AP_ProcedureCode_id_downlinkUEAssociatedLPPaTransport;
    initiating_message->criticality = S1AP_Criticality_ignore;
    initiating_message->value.present =
        S1AP_InitiatingMessage__value_PR_DownlinkUEAssociatedLPPaTransport;
    initiating_message->value.choice.DownlinkUEAssociatedLPPaTransport =
        CALLOC(1, sizeof(*transport));
    transport =
        initiating_message->value.choice.DownlinkUEAssociatedLPPaTransport;
    ogs_assert(transport);
    transport->protocolIEs = ogs_asn_calloc_protocol_ies(
            &asn_DEF_S1AP_DownlinkUEAssociatedLPPaTransport);
    ogs_assert(transport->protocolIEs);

    ie = CALLOC(1, sizeof(*ie));
    ogs_assert(ie);
    ASN_SEQUENCE_ADD(transport->protocolIEs, ie);
    ie->id = S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present =
        S1AP_DownlinkUEAssociatedLPPaTransport_IEs__value_PR_MME_UE_S1AP_ID;
    ie->value.choice.MME_UE_S1AP_ID = CALLOC(1,
            sizeof(*ie->value.choice.MME_UE_S1AP_ID));
    ogs_assert(ie->value.choice.MME_UE_S1AP_ID);
    *ie->value.choice.MME_UE_S1AP_ID = enb_ue->mme_ue_s1ap_id;

    ie = CALLOC(1, sizeof(*ie));
    ogs_assert(ie);
    ASN_SEQUENCE_ADD(transport->protocolIEs, ie);
    ie->id = S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present =
        S1AP_DownlinkUEAssociatedLPPaTransport_IEs__value_PR_ENB_UE_S1AP_ID;
    ie->value.choice.ENB_UE_S1AP_ID = CALLOC(1,
            sizeof(*ie->value.choice.ENB_UE_S1AP_ID));
    ogs_assert(ie->value.choice.ENB_UE_S1AP_ID);
    *ie->value.choice.ENB_UE_S1AP_ID = enb_ue->enb_ue_s1ap_id;

    ie = CALLOC(1, sizeof(*ie));
    ogs_assert(ie);
    ASN_SEQUENCE_ADD(transport->protocolIEs, ie);
    ie->id = S1AP_ProtocolIE_ID_id_Routing_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present =
        S1AP_DownlinkUEAssociatedLPPaTransport_IEs__value_PR_Routing_ID;
    ie->value.choice.Routing_ID = CALLOC(1,
            sizeof(*ie->value.choice.Routing_ID));
    ogs_assert(ie->value.choice.Routing_ID);
    *ie->value.choice.Routing_ID = routing_id;

    ie = CALLOC(1, sizeof(*ie));
    ogs_assert(ie);
    ASN_SEQUENCE_ADD(transport->protocolIEs, ie);
    ie->id = S1AP_ProtocolIE_ID_id_LPPa_PDU;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present =
        S1AP_DownlinkUEAssociatedLPPaTransport_IEs__value_PR_LPPa_PDU;
    ie->value.choice.LPPa_PDU = CALLOC(1,
            sizeof(*ie->value.choice.LPPa_PDU));
    ogs_assert(ie->value.choice.LPPa_PDU);
    ogs_assert(OCTET_STRING_fromBuf(ie->value.choice.LPPa_PDU,
                (const char *)payload, (int)payload_len) == 0);

    return ogs_s1ap_encode(&pdu);
}