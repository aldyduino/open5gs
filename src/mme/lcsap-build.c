#include <limits.h>

#include "LCSAP_asn_constant.h"
#include "LCSAP_APDU.h"
#include "LCSAP_Connection-Oriented-Information.h"
#include "LCSAP_Criticality.h"
#include "LCSAP_E-CGI.h"
#include "LCSAP_InitiatingMessage.h"
#include "LCSAP_LCS-AP-PDU.h"
#include "LCSAP_Location-Request.h"
#include "LCSAP_Location-Type.h"
#include "LCSAP_LCS-Client-Type.h"
#include "LCSAP_IMSI.h"
#include "LCSAP_IMEI.h"
#include "LCSAP_Include-Velocity.h"
#include "LCSAP_UE-Positioning-Capability.h"
#include "LCSAP_Correlation-ID.h"
#include "LCSAP_LCS-Priority.h"
#include "LCSAP_LCS-QoS.h"
#include "LCSAP_LCS-Service-Type-ID.h"
#include "LCSAP_Payload-Type.h"
#include "LCSAP_ProtocolIE-Container.h"
#include "LCSAP_ProtocolIE-Field.h"
#include "LCSAP_ProtocolExtensionContainer.h"
#include "LCSAP_ProtocolExtensionField.h"

#include "asn1c/util/message.h"

#include "lcsap-build.h"

ogs_pkbuf_t *lcsap_build_location_request(uint32_t correlation_id,
        LCSAP_Location_Type_t location_type, const uint8_t *imsi,
        size_t imsi_len, const uint8_t plmn_id[3], uint32_t cell_id,
        long client_type, const lcsap_location_request_options_t *options)
{
    ogs_pkbuf_t *pkbuf = NULL;
    LCSAP_LCS_AP_PDU_t *pdu = NULL;
    LCSAP_InitiatingMessage_t *initiating_message = NULL;
    LCSAP_Location_Request_t *request = NULL;
    LCSAP_ProtocolIE_Container_81P0_t *container = NULL;
    LCSAP_Location_Request_IEs_t *ie = NULL;
    LCSAP_E_CGI_t *e_cgi = NULL;
    LCSAP_UE_Positioning_Capability_t *positioning_capability = NULL;
    LCSAP_LCS_QoS_t *lcs_qos = NULL;
    LCSAP_ProtocolExtensionContainer_107P21_t *extension_container = NULL;
    LCSAP_Location_Request_Extensions_t *extension = NULL;
    uint8_t correlation[4];
    uint8_t cell_identity[4];
    uint8_t imsi_tbcd[(OGS_MAX_IMSI_BCD_LEN + 1) / 2];
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN + 1];
    size_t i;
    int imsi_tbcd_len;

    if (!imsi || !imsi_len || imsi_len > OGS_MAX_IMSI_BCD_LEN ||
        !plmn_id || cell_id > 0x0fffffff ||
        client_type < LCSAP_LCS_Client_Type_emergency_Services ||
        client_type > LCSAP_LCS_Client_Type_pLMN_Operator_Target_MS_Service_Support) {
        ogs_error("Invalid LCS-AP Location Service Request parameters");
        return NULL;
    }
    if (options &&
        ((options->lcs_priority_present && options->lcs_priority > 1) ||
         (options->horizontal_accuracy_present &&
          (options->horizontal_accuracy < 0 ||
           options->horizontal_accuracy > 127)) ||
         (options->vertical_requested_present &&
          (options->vertical_requested < 0 ||
           options->vertical_requested > 1)) ||
         (options->vertical_accuracy_present &&
          (options->vertical_accuracy < 0 ||
           options->vertical_accuracy > 127)) ||
         (options->response_time_present &&
          (options->response_time < 0 || options->response_time > 1)) ||
         (options->include_velocity_present &&
          (options->include_velocity < LCSAP_Include_Velocity_requested ||
           options->include_velocity >
                LCSAP_Include_Velocity_not_Requested)) ||
         (options->lcs_service_type_id_present &&
          (options->lcs_service_type_id < 0 ||
           options->lcs_service_type_id > 127)))) {
        ogs_error("Invalid optional LCS-AP Location Service Request parameter");
        return NULL;
    }
    for (i = 0; i < imsi_len; i++) {
        if (imsi[i] < '0' || imsi[i] > '9') {
            ogs_error("Invalid IMSI in LCS-AP Location Service Request");
            return NULL;
        }
    }
    memcpy(imsi_bcd, imsi, imsi_len);
    imsi_bcd[imsi_len] = '\0';

    imsi_tbcd_len = sizeof(imsi_tbcd);
    if (!ogs_bcd_to_buffer(imsi_bcd, imsi_tbcd, &imsi_tbcd_len))
        return NULL;

    correlation[0] = (uint8_t)(correlation_id >> 24);
    correlation[1] = (uint8_t)(correlation_id >> 16);
    correlation[2] = (uint8_t)(correlation_id >> 8);
    correlation[3] = (uint8_t)correlation_id;

    pdu = ogs_calloc(1, sizeof(*pdu));
    if (!pdu)
        return NULL;

    pdu->present = LCSAP_LCS_AP_PDU_PR_initiatingMessage;
    pdu->choice.initiatingMessage = ogs_calloc(1, sizeof(*initiating_message));
    if (!pdu->choice.initiatingMessage)
        goto cleanup;
    initiating_message = pdu->choice.initiatingMessage;
    initiating_message->procedureCode = LCSAP_id_Location_Service_Request;
    initiating_message->criticality = LCSAP_Criticality_reject;
    initiating_message->value.present =
        LCSAP_InitiatingMessage__value_PR_Location_Request;
    initiating_message->value.choice.Location_Request =
        ogs_calloc(1, sizeof(*request));
    if (!initiating_message->value.choice.Location_Request)
        goto cleanup;
    request = initiating_message->value.choice.Location_Request;

    container = ogs_calloc(1, sizeof(*container));
    if (!container)
        goto cleanup;
    request->protocolIEs = (struct LCSAP_ProtocolIE_Container *)container;

    ie = ogs_calloc(1, sizeof(*ie));
    if (!ie)
        goto cleanup;
    if (ASN_SEQUENCE_ADD(&container->list, ie) != 0) {
        ogs_free(ie);
        ie = NULL;
        goto cleanup;
    }
    ie->id = LCSAP_id_Correlation_ID;
    ie->criticality = LCSAP_Criticality_reject;
    ie->value.present = LCSAP_Location_Request_IEs__value_PR_Correlation_ID;
    ie->value.choice.Correlation_ID = ogs_calloc(1,
            sizeof(*ie->value.choice.Correlation_ID));
    if (!ie->value.choice.Correlation_ID ||
        OCTET_STRING_fromBuf(ie->value.choice.Correlation_ID,
            (const char *)correlation, sizeof(correlation)) != 0)
        goto cleanup;

    ie = ogs_calloc(1, sizeof(*ie));
    if (!ie)
        goto cleanup;
    if (ASN_SEQUENCE_ADD(&container->list, ie) != 0) {
        ogs_free(ie);
        ie = NULL;
        goto cleanup;
    }
    ie->id = LCSAP_id_Location_Type;
    ie->criticality = LCSAP_Criticality_reject;
    ie->value.present = LCSAP_Location_Request_IEs__value_PR_Location_Type;
    ie->value.choice.Location_Type = ogs_calloc(1,
            sizeof(*ie->value.choice.Location_Type));
    if (!ie->value.choice.Location_Type)
        goto cleanup;
    *ie->value.choice.Location_Type = location_type;

    ie = ogs_calloc(1, sizeof(*ie));
    if (!ie)
        goto cleanup;
    if (ASN_SEQUENCE_ADD(&container->list, ie) != 0) {
        ogs_free(ie);
        ie = NULL;
        goto cleanup;
    }
    ie->id = LCSAP_id_E_UTRAN_Cell_Identifier;
    ie->criticality = LCSAP_Criticality_ignore;
    ie->value.present = LCSAP_Location_Request_IEs__value_PR_E_CGI;
    ie->value.choice.E_CGI = ogs_calloc(1, sizeof(*e_cgi));
    if (!ie->value.choice.E_CGI)
        goto cleanup;
    e_cgi = ie->value.choice.E_CGI;
    if (OCTET_STRING_fromBuf(&e_cgi->pLMNidentity,
                (const char *)plmn_id, 3) != 0)
        goto cleanup;
    cell_identity[0] = (uint8_t)(cell_id >> 20);
    cell_identity[1] = (uint8_t)(cell_id >> 12);
    cell_identity[2] = (uint8_t)(cell_id >> 4);
    cell_identity[3] = (uint8_t)((cell_id & 0x0f) << 4);
    e_cgi->cell_ID.buf = ogs_malloc(sizeof(cell_identity));
    if (!e_cgi->cell_ID.buf)
        goto cleanup;
    memcpy(e_cgi->cell_ID.buf, cell_identity, sizeof(cell_identity));
    e_cgi->cell_ID.size = sizeof(cell_identity);
    e_cgi->cell_ID.bits_unused = 4;

    ie = ogs_calloc(1, sizeof(*ie));
    if (!ie)
        goto cleanup;
    if (ASN_SEQUENCE_ADD(&container->list, ie) != 0) {
        ogs_free(ie);
        ie = NULL;
        goto cleanup;
    }
    ie->id = LCSAP_id_LCS_Client_Type;
    ie->criticality = LCSAP_Criticality_reject;
    ie->value.present = LCSAP_Location_Request_IEs__value_PR_LCS_Client_Type;
    ie->value.choice.LCS_Client_Type = ogs_calloc(1,
            sizeof(*ie->value.choice.LCS_Client_Type));
    if (!ie->value.choice.LCS_Client_Type)
        goto cleanup;
    *ie->value.choice.LCS_Client_Type = client_type;

    ie = ogs_calloc(1, sizeof(*ie));
    if (!ie)
        goto cleanup;
    if (ASN_SEQUENCE_ADD(&container->list, ie) != 0) {
        ogs_free(ie);
        ie = NULL;
        goto cleanup;
    }
    ie->id = LCSAP_id_IMSI;
    ie->criticality = LCSAP_Criticality_ignore;
    ie->value.present = LCSAP_Location_Request_IEs__value_PR_IMSI;
    ie->value.choice.IMSI = ogs_calloc(1, sizeof(*ie->value.choice.IMSI));
    if (!ie->value.choice.IMSI ||
        OCTET_STRING_fromBuf(ie->value.choice.IMSI,
            (const char *)imsi_tbcd, imsi_tbcd_len) != 0)
        goto cleanup;

    ie = ogs_calloc(1, sizeof(*ie));
    if (!ie)
        goto cleanup;
    if (ASN_SEQUENCE_ADD(&container->list, ie) != 0) {
        ogs_free(ie);
        ie = NULL;
        goto cleanup;
    }
    ie->id = LCSAP_id_UE_Positioning_Capability;
    ie->criticality = LCSAP_Criticality_reject;
    ie->value.present =
        LCSAP_Location_Request_IEs__value_PR_UE_Positioning_Capability;
    ie->value.choice.UE_Positioning_Capability =
        ogs_calloc(1, sizeof(*ie->value.choice.UE_Positioning_Capability));
    if (!ie->value.choice.UE_Positioning_Capability)
        goto cleanup;
    positioning_capability = ie->value.choice.UE_Positioning_Capability;
    positioning_capability->lPP = 1;

    if (options && options->imei_present) {
        ie = ogs_calloc(1, sizeof(*ie));
        if (!ie)
            goto cleanup;
        if (ASN_SEQUENCE_ADD(&container->list, ie) != 0) {
            ogs_free(ie);
            ie = NULL;
            goto cleanup;
        }
        ie->id = LCSAP_id_IMEI;
        ie->criticality = LCSAP_Criticality_ignore;
        ie->value.present = LCSAP_Location_Request_IEs__value_PR_IMEI;
        ie->value.choice.IMEI = ogs_calloc(1, sizeof(*ie->value.choice.IMEI));
        if (!ie->value.choice.IMEI ||
            OCTET_STRING_fromBuf(ie->value.choice.IMEI,
                (const char *)options->imei, sizeof(options->imei)) != 0)
            goto cleanup;
    }

    if (options && options->include_velocity_present) {
        ie = ogs_calloc(1, sizeof(*ie));
        if (!ie)
            goto cleanup;
        if (ASN_SEQUENCE_ADD(&container->list, ie) != 0) {
            ogs_free(ie);
            ie = NULL;
            goto cleanup;
        }
        ie->id = LCSAP_id_Include_Velocity;
        ie->criticality = LCSAP_Criticality_reject;
        ie->value.present = LCSAP_Location_Request_IEs__value_PR_Include_Velocity;
        ie->value.choice.Include_Velocity =
            ogs_calloc(1, sizeof(*ie->value.choice.Include_Velocity));
        if (!ie->value.choice.Include_Velocity)
            goto cleanup;
        *ie->value.choice.Include_Velocity = options->include_velocity;
    }

    if (options && options->lcs_priority_present) {
        ie = ogs_calloc(1, sizeof(*ie));
        if (!ie)
            goto cleanup;
        if (ASN_SEQUENCE_ADD(&container->list, ie) != 0) {
            ogs_free(ie);
            ie = NULL;
            goto cleanup;
        }
        ie->id = LCSAP_id_LCS_Priority;
        ie->criticality = LCSAP_Criticality_reject;
        ie->value.present = LCSAP_Location_Request_IEs__value_PR_LCS_Priority;
        ie->value.choice.LCS_Priority =
            ogs_calloc(1, sizeof(*ie->value.choice.LCS_Priority));
        if (!ie->value.choice.LCS_Priority ||
            OCTET_STRING_fromBuf(ie->value.choice.LCS_Priority,
                (const char *)&options->lcs_priority, 1) != 0)
            goto cleanup;
    }

    if (options && options->lcs_qos_present) {
        ie = ogs_calloc(1, sizeof(*ie));
        if (!ie)
            goto cleanup;
        if (ASN_SEQUENCE_ADD(&container->list, ie) != 0) {
            ogs_free(ie);
            ie = NULL;
            goto cleanup;
        }
        ie->id = LCSAP_id_LCS_QOS;
        ie->criticality = LCSAP_Criticality_reject;
        ie->value.present = LCSAP_Location_Request_IEs__value_PR_LCS_QoS;
        ie->value.choice.LCS_QoS = ogs_calloc(1,
                sizeof(*ie->value.choice.LCS_QoS));
        if (!ie->value.choice.LCS_QoS)
            goto cleanup;
        lcs_qos = ie->value.choice.LCS_QoS;
        if (options->horizontal_accuracy_present) {
            lcs_qos->horizontal_Accuracy = ogs_calloc(1,
                    sizeof(*lcs_qos->horizontal_Accuracy));
            if (!lcs_qos->horizontal_Accuracy)
                goto cleanup;
            *lcs_qos->horizontal_Accuracy = options->horizontal_accuracy;
        }
        if (options->vertical_requested_present) {
            lcs_qos->vertical_Requested = ogs_calloc(1,
                    sizeof(*lcs_qos->vertical_Requested));
            if (!lcs_qos->vertical_Requested)
                goto cleanup;
            *lcs_qos->vertical_Requested = options->vertical_requested;
        }
        if (options->vertical_accuracy_present) {
            lcs_qos->vertical_Accuracy = ogs_calloc(1,
                    sizeof(*lcs_qos->vertical_Accuracy));
            if (!lcs_qos->vertical_Accuracy)
                goto cleanup;
            *lcs_qos->vertical_Accuracy = options->vertical_accuracy;
        }
        if (options->response_time_present) {
            lcs_qos->response_Time = ogs_calloc(1,
                    sizeof(*lcs_qos->response_Time));
            if (!lcs_qos->response_Time)
                goto cleanup;
            *lcs_qos->response_Time = options->response_time;
        }
    }

    if (options && options->lcs_service_type_id_present) {
        extension_container = ogs_calloc(1, sizeof(*extension_container));
        if (!extension_container)
            goto cleanup;
        request->protocolExtensions =
            (struct LCSAP_ProtocolExtensionContainer *)extension_container;
        extension = ogs_calloc(1, sizeof(*extension));
        if (!extension)
            goto cleanup;
        if (ASN_SEQUENCE_ADD(&extension_container->list, extension) != 0) {
            ogs_free(extension);
            extension = NULL;
            goto cleanup;
        }
        extension->id = LCSAP_id_LCS_Service_Type_ID;
        extension->criticality = LCSAP_Criticality_ignore;
        extension->extensionValue.present =
            LCSAP_Location_Request_Extensions__extensionValue_PR_LCS_Service_Type_ID;
        extension->extensionValue.choice.LCS_Service_Type_ID =
            ogs_calloc(1, sizeof(*extension->extensionValue.choice.LCS_Service_Type_ID));
        if (!extension->extensionValue.choice.LCS_Service_Type_ID)
            goto cleanup;
        *extension->extensionValue.choice.LCS_Service_Type_ID =
            options->lcs_service_type_id;
    }

    pkbuf = ogs_asn_encode(&asn_DEF_LCSAP_LCS_AP_PDU, pdu);
    ogs_free(pdu);
    pdu = NULL;
    if (!pkbuf)
        ogs_error("ogs_asn_encode(LCS-AP Location Service Request) failed");

cleanup:
    if (pdu) {
        ogs_asn_free(&asn_DEF_LCSAP_LCS_AP_PDU, pdu);
        ogs_free(pdu);
    }
    return pkbuf;
}


ogs_pkbuf_t *lcsap_build_connection_oriented_information(
        LCSAP_Payload_Type_t payload_type,
    const uint8_t correlation_id[4],
        const uint8_t *payload, size_t payload_len)
{
    ogs_pkbuf_t *pkbuf = NULL;
    LCSAP_LCS_AP_PDU_t *pdu = NULL;
    LCSAP_InitiatingMessage_t *initiating_message = NULL;
    LCSAP_Connection_Oriented_Information_t *information = NULL;
    LCSAP_ProtocolIE_Container_81P3_t *container = NULL;
    LCSAP_Connection_Oriented_Information_IEs_t *ie = NULL;

    if (!correlation_id || !payload || !payload_len ||
        payload_len > INT_MAX ||
        (payload_type != LCSAP_Payload_Type_lPP &&
         payload_type != LCSAP_Payload_Type_lPPa)) {
        ogs_error("Invalid LCS-AP payload");
        return NULL;
    }

    pdu = ogs_calloc(1, sizeof(*pdu));
    if (!pdu)
        return NULL;

    pdu->present = LCSAP_LCS_AP_PDU_PR_initiatingMessage;
    pdu->choice.initiatingMessage = ogs_calloc(1, sizeof(*initiating_message));
    if (!pdu->choice.initiatingMessage)
        goto cleanup;
    initiating_message = pdu->choice.initiatingMessage;
    initiating_message->procedureCode =
        LCSAP_id_Connection_Oriented_Information_Transfer;
    initiating_message->criticality = LCSAP_Criticality_reject;
    initiating_message->value.present =
        LCSAP_InitiatingMessage__value_PR_Connection_Oriented_Information;
    initiating_message->value.choice.Connection_Oriented_Information =
        ogs_calloc(1, sizeof(*information));
    if (!initiating_message->value.choice.Connection_Oriented_Information)
        goto cleanup;
    information =
        initiating_message->value.choice.Connection_Oriented_Information;

    container = ogs_calloc(1, sizeof(*container));
    if (!container)
        goto cleanup;
    information->protocolIEs =
        (struct LCSAP_ProtocolIE_Container *)container;

    ie = ogs_calloc(1, sizeof(*ie));
    if (!ie)
        goto cleanup;
    if (ASN_SEQUENCE_ADD(&container->list, ie) != 0) {
        ogs_free(ie);
        ie = NULL;
        goto cleanup;
    }
    ie->id = LCSAP_id_Correlation_ID;
    ie->criticality = LCSAP_Criticality_reject;
    ie->value.present =
        LCSAP_Connection_Oriented_Information_IEs__value_PR_Correlation_ID;
    ie->value.choice.Correlation_ID = ogs_calloc(1,
            sizeof(*ie->value.choice.Correlation_ID));
    if (!ie->value.choice.Correlation_ID)
        goto cleanup;
    if (OCTET_STRING_fromBuf(ie->value.choice.Correlation_ID,
                (const char *)correlation_id, 4) != 0)
        goto cleanup;

    ie = ogs_calloc(1, sizeof(*ie));
    if (!ie)
        goto cleanup;
    if (ASN_SEQUENCE_ADD(&container->list, ie) != 0) {
        ogs_free(ie);
        ie = NULL;
        goto cleanup;
    }
    ie->id = LCSAP_id_Payload_Type;
    ie->criticality = LCSAP_Criticality_reject;
    ie->value.present =
        LCSAP_Connection_Oriented_Information_IEs__value_PR_Payload_Type;
    ie->value.choice.Payload_Type = ogs_calloc(1,
            sizeof(*ie->value.choice.Payload_Type));
    if (!ie->value.choice.Payload_Type)
        goto cleanup;
    *ie->value.choice.Payload_Type = payload_type;

    ie = ogs_calloc(1, sizeof(*ie));
    if (!ie)
        goto cleanup;
    if (ASN_SEQUENCE_ADD(&container->list, ie) != 0) {
        ogs_free(ie);
        ie = NULL;
        goto cleanup;
    }
    ie->id = LCSAP_id_APDU;
    ie->criticality = LCSAP_Criticality_reject;
    ie->value.present =
        LCSAP_Connection_Oriented_Information_IEs__value_PR_APDU;
    ie->value.choice.APDU = ogs_calloc(1, sizeof(*ie->value.choice.APDU));
    if (!ie->value.choice.APDU)
        goto cleanup;
    if (OCTET_STRING_fromBuf(ie->value.choice.APDU,
                (const char *)payload, (int)payload_len) != 0)
        goto cleanup;

    pkbuf = ogs_asn_encode(&asn_DEF_LCSAP_LCS_AP_PDU, pdu);
    ogs_free(pdu);
    pdu = NULL;
    if (!pkbuf)
        ogs_error("ogs_asn_encode(LCS-AP-PDU) failed");

cleanup:
    if (pdu) {
        ogs_asn_free(&asn_DEF_LCSAP_LCS_AP_PDU, pdu);
        ogs_free(pdu);
    }
    return pkbuf;
}