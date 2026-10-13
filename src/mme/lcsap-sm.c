#include "ogs-sctp.h"

#include "asn1c/util/message.h"
#include "LCSAP_asn_constant.h"
#include "LCSAP_Connection-Oriented-Information.h"
#include "LCSAP_InitiatingMessage.h"
#include "LCSAP_LCS-AP-PDU.h"
#include "LCSAP_Payload-Type.h"
#include "LCSAP_ProtocolIE-Container.h"
#include "LCSAP_ProtocolIE-Field.h"
#include "LCSAP_SuccessfulOutcome.h"
#include "LCSAP_UnsuccessfulOutcome.h"

#include "mme-context.h"
#include "mme-event.h"
#include "mme-sm.h"
#include "mme-timer.h"

#include "emm-build.h"
#include "nas-path.h"
#include "s1ap-build.h"
#include "s1ap-path.h"
#include "lcsap-path.h"

static void lcsap_handle_connection_oriented_information(
        LCSAP_Connection_Oriented_Information_t *information)
{
    LCSAP_ProtocolIE_Container_81P3_t *container = NULL;
    LCSAP_Correlation_ID_t *correlation = NULL;
    LCSAP_Payload_Type_t *payload_type = NULL;
    LCSAP_APDU_t *apdu = NULL;
    int i;

    if (!information || !information->protocolIEs)
        return;

    container = (LCSAP_ProtocolIE_Container_81P3_t *)
        information->protocolIEs;
    for (i = 0; i < OGS_ASN_LIST_COUNT(&container->list); i++) {
        LCSAP_Connection_Oriented_Information_IEs_t *ie =
            OGS_ASN_LIST_GET(&container->list, i);
        switch (ie->id) {
        case LCSAP_id_Correlation_ID:
            correlation = ie->value.choice.Correlation_ID;
            break;
        case LCSAP_id_Payload_Type:
            payload_type = ie->value.choice.Payload_Type;
            break;
        case LCSAP_id_APDU:
            apdu = ie->value.choice.APDU;
            break;
        default:
            break;
        }
    }

    if (!payload_type || !correlation || correlation->size != 4 ||
        !apdu || !apdu->size) {
        ogs_warn("Discard LCS-AP information without a valid payload");
        return;
    }

    {
        uint32_t mme_ue_s1ap_id =
            ((uint32_t)correlation->buf[0] << 24) |
            ((uint32_t)correlation->buf[1] << 16) |
            ((uint32_t)correlation->buf[2] << 8) |
            (uint32_t)correlation->buf[3];
        enb_ue_t *enb_ue = enb_ue_find_by_mme_ue_s1ap_id(mme_ue_s1ap_id);

        if (*payload_type == LCSAP_Payload_Type_lPP) {
            if (enb_ue) {
                mme_ue_t *mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
                ogs_pkbuf_t *nasbuf = NULL;

                if (!mme_ue || mme_ue->enb_ue_id != enb_ue->id) {
                    ogs_warn("LPP Correlation-ID points to a stale S1 context");
                    return;
                }

                nasbuf = emm_build_downlink_generic_nas_transport(
                        mme_ue, apdu->buf, apdu->size);
                if (nasbuf)
                    nas_eps_send_to_enb(mme_ue, nasbuf);
                else
                    ogs_error("Failed to build downlink LPP NAS message");
            } else {
                ogs_warn("LPP Correlation-ID has no active S1 context");
            }
        } else if (*payload_type == LCSAP_Payload_Type_lPPa) {
            if (enb_ue) {
                mme_ue_t *mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
                ogs_pkbuf_t *s1apbuf = NULL;

                if (!mme_ue || mme_ue->enb_ue_id != enb_ue->id ||
                    !enb_ue->lppa_routing_id_presence) {
                    ogs_warn("LPPA Correlation-ID has no active S1 routing");
                    return;
                }

                s1apbuf = s1ap_build_downlink_ue_associated_lppa_transport(
                        enb_ue, enb_ue->lppa_routing_id,
                        apdu->buf, apdu->size);
                if (s1apbuf)
                    s1ap_send_to_enb_ue(enb_ue, s1apbuf);
                else
                    ogs_error("Failed to build downlink LPPA S1AP message");
            } else {
                ogs_warn("LPPA Correlation-ID has no active S1 context");
            }
        } else {
            ogs_warn("Unsupported LCS-AP payload type[%ld]", *payload_type);
        }
    }
}

void lcsap_state_initial(ogs_fsm_t *s, mme_event_t *e)
{
    mme_esmlc_t *esmlc = NULL;

    ogs_assert(s);
    ogs_assert(e);

    esmlc = e->esmlc;
    ogs_assert(esmlc);

    esmlc->t_conn = ogs_timer_add(ogs_app()->timer_mgr,
            mme_timer_lcsap_cli_conn_to_srv, esmlc);
    if (!esmlc->t_conn) {
        ogs_error("ogs_timer_add() failed");
        return;
    }

    OGS_FSM_TRAN(s, &lcsap_state_will_connect);
}

void lcsap_state_final(ogs_fsm_t *s, mme_event_t *e)
{
    mme_esmlc_t *esmlc = NULL;

    ogs_assert(s);
    ogs_assert(e);

    esmlc = e->esmlc;
    ogs_assert(esmlc);

    ogs_timer_delete(esmlc->t_conn);
    mme_esmlc_close(esmlc);
}

void lcsap_state_will_connect(ogs_fsm_t *s, mme_event_t *e)
{
    mme_esmlc_t *esmlc = NULL;

    ogs_assert(s);
    ogs_assert(e);

    esmlc = e->esmlc;
    ogs_assert(esmlc);
    ogs_assert(esmlc->t_conn);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        ogs_timer_start(esmlc->t_conn,
                mme_timer_cfg(MME_TIMER_LCSAP_CLI_CONN_TO_SRV)->duration);
        lcsap_client(esmlc);
        break;
    case OGS_FSM_EXIT_SIG:
        ogs_timer_stop(esmlc->t_conn);
        break;
    case MME_EVENT_LCSAP_TIMER:
        if (e->timer_id == MME_TIMER_LCSAP_CLI_CONN_TO_SRV) {
            mme_esmlc_close(esmlc);
            ogs_timer_start(esmlc->t_conn,
                    mme_timer_cfg(MME_TIMER_LCSAP_CLI_CONN_TO_SRV)->duration);
            lcsap_client(esmlc);
        }
        break;
    case MME_EVENT_LCSAP_LO_SCTP_COMM_UP:
        OGS_FSM_TRAN(s, &lcsap_state_connected);
        break;
    case MME_EVENT_LCSAP_LO_CONNREFUSED:
        mme_esmlc_close(esmlc);
        break;
    default:
        ogs_error("Unexpected LCS-AP event %s", mme_event_get_name(e));
        break;
    }
}

void lcsap_state_connected(ogs_fsm_t *s, mme_event_t *e)
{
    mme_esmlc_t *esmlc = NULL;

    ogs_assert(s);
    ogs_assert(e);

    esmlc = e->esmlc;
    ogs_assert(esmlc);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
    case OGS_FSM_EXIT_SIG:
        break;
    case MME_EVENT_LCSAP_LO_CONNREFUSED:
        mme_esmlc_close(esmlc);
        OGS_FSM_TRAN(s, &lcsap_state_will_connect);
        break;
    case MME_EVENT_LCSAP_MESSAGE: {
        int rv;
        ogs_pkbuf_t *pkbuf = e->pkbuf;
        LCSAP_LCS_AP_PDU_t message;

        ogs_assert(pkbuf);
        memset(&message, 0, sizeof(message));
        rv = ogs_asn_decode(&asn_DEF_LCSAP_LCS_AP_PDU,
                &message, sizeof(message), pkbuf);
        if (rv == OGS_OK) {
            long procedure_code = -1;

            if (message.present == LCSAP_LCS_AP_PDU_PR_initiatingMessage &&
                message.choice.initiatingMessage)
                procedure_code =
                    message.choice.initiatingMessage->procedureCode;
            else if (message.present ==
                    LCSAP_LCS_AP_PDU_PR_successfulOutcome &&
                    message.choice.successfulOutcome)
                procedure_code =
                    message.choice.successfulOutcome->procedureCode;
            else if (message.present ==
                    LCSAP_LCS_AP_PDU_PR_unsuccessfulOutcome &&
                    message.choice.unsuccessfulOutcome)
                procedure_code =
                    message.choice.unsuccessfulOutcome->procedureCode;

            ogs_debug("Received LCS-AP procedure [%ld]", procedure_code);
            if (message.present == LCSAP_LCS_AP_PDU_PR_initiatingMessage &&
                message.choice.initiatingMessage &&
                message.choice.initiatingMessage->procedureCode ==
                    LCSAP_id_Connection_Oriented_Information_Transfer &&
                message.choice.initiatingMessage->value.present ==
                    LCSAP_InitiatingMessage__value_PR_Connection_Oriented_Information) {
                lcsap_handle_connection_oriented_information(
                    message.choice.initiatingMessage->value.choice.
                        Connection_Oriented_Information);
            }
        } else {
            ogs_warn("Cannot decode LCS-AP message");
        }
        ogs_asn_free(&asn_DEF_LCSAP_LCS_AP_PDU, &message);
        break;
    }
    default:
        ogs_error("Unexpected LCS-AP event %s", mme_event_get_name(e));
        break;
    }
}