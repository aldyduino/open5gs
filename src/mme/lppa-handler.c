#include "mme-context.h"
#include "s1ap-handler.h"
#include "lcsap-build.h"
#include "lcsap-path.h"

void s1ap_handle_uplink_ue_associated_lppa_transport(
        mme_enb_t *enb, ogs_s1ap_message_t *message)
{
    S1AP_InitiatingMessage_t *initiating_message = NULL;
    S1AP_UplinkUEAssociatedLPPaTransport_t *transport = NULL;
    S1AP_UplinkUEAssociatedLPPaTransport_IEs_t *ie = NULL;
    S1AP_MME_UE_S1AP_ID_t *mme_ue_s1ap_id = NULL;
    S1AP_ENB_UE_S1AP_ID_t *enb_ue_s1ap_id = NULL;
    S1AP_Routing_ID_t *routing_id = NULL;
    S1AP_LPPa_PDU_t *lppa_pdu = NULL;
    enb_ue_t *enb_ue = NULL;
    ogs_pkbuf_t *pkbuf = NULL;
    uint8_t correlation_id[4];
    int i;

    ogs_assert(enb);
    ogs_assert(message);

    initiating_message = message->choice.initiatingMessage;
    ogs_assert(initiating_message);
    transport =
        initiating_message->value.choice.UplinkUEAssociatedLPPaTransport;
    ogs_assert(transport);

    for (i = 0; i < OGS_ASN_LIST_COUNT(transport->protocolIEs); i++) {
        ie = OGS_ASN_LIST_GET(transport->protocolIEs, i);
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            mme_ue_s1ap_id = ie->value.choice.MME_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            enb_ue_s1ap_id = ie->value.choice.ENB_UE_S1AP_ID;
            break;
        case S1AP_ProtocolIE_ID_id_Routing_ID:
            routing_id = ie->value.choice.Routing_ID;
            break;
        case S1AP_ProtocolIE_ID_id_LPPa_PDU:
            lppa_pdu = ie->value.choice.LPPa_PDU;
            break;
        default:
            break;
        }
    }

    if (!mme_ue_s1ap_id || !enb_ue_s1ap_id || !routing_id || !lppa_pdu ||
        !lppa_pdu->size || *routing_id < 0 || *routing_id > UINT8_MAX) {
        ogs_error("Invalid UplinkUEAssociatedLPPaTransport IEs");
        return;
    }

    enb_ue = enb_ue_find_by_mme_ue_s1ap_id(*mme_ue_s1ap_id);
    if (!enb_ue || enb_ue->enb_id != enb->id ||
        enb_ue->enb_ue_s1ap_id != *enb_ue_s1ap_id ||
        !mme_ue_find_by_id(enb_ue->mme_ue_id)) {
        ogs_warn("LPPA message does not match the serving S1 UE context");
        return;
    }

    enb_ue->lppa_routing_id_presence = true;
    enb_ue->lppa_routing_id = (uint8_t)*routing_id;

    correlation_id[0] = (*mme_ue_s1ap_id >> 24) & 0xff;
    correlation_id[1] = (*mme_ue_s1ap_id >> 16) & 0xff;
    correlation_id[2] = (*mme_ue_s1ap_id >> 8) & 0xff;
    correlation_id[3] = *mme_ue_s1ap_id & 0xff;
    pkbuf = lcsap_build_connection_oriented_information(
            LCSAP_Payload_Type_lPPa, correlation_id,
            lppa_pdu->buf, lppa_pdu->size);
    if (!pkbuf) {
        ogs_error("Failed to build LCS-AP LPPA transfer");
        return;
    }

    lcsap_send_to_esmlc(pkbuf);
}