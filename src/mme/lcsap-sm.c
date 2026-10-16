#include "ogs-sctp.h"

#include "asn1c/util/message.h"
#include "LCSAP_asn_constant.h"
#include "LCSAP_Connection-Oriented-Information.h"
#include "LCSAP_Geographical-Area.h"
#include "LCSAP_Geographical-Coordinates.h"
#include "LCSAP_Ellipsoid-Point-With-Uncertainty-Ellipse.h"
#include "LCSAP_Uncertainty-Ellipse.h"
#include "LCSAP_InitiatingMessage.h"
#include "LCSAP_LCS-AP-PDU.h"
#include "LCSAP_Location-Request.h"
#include "LCSAP_Location-Response.h"
#include "LCSAP_Point.h"
#include "LCSAP_Payload-Type.h"
#include "LCSAP_ProtocolIE-Container.h"
#include "LCSAP_ProtocolIE-Field.h"
#include "LCSAP_SuccessfulOutcome.h"
#include "LCSAP_UnsuccessfulOutcome.h"
#include "LCSAP_asn_constant.h"

#include "mme-context.h"
#include "mme-event.h"
#include "mme-sm.h"
#include "mme-timer.h"

#include "emm-build.h"
#include "nas-path.h"
#include "s1ap-build.h"
#include "s1ap-path.h"
#include "lcsap-path.h"
#include "lcsap-build.h"

typedef struct lcsap_slg_pending_s {
    ogs_lnode_t lnode;
    uint32_t correlation_id;
    struct msg *diameter_request;
    ogs_timer_t *timer;
} lcsap_slg_pending_t;

static ogs_list_t slg_pending_list;

static lcsap_slg_pending_t *lcsap_slg_pending_find(uint32_t correlation_id)
{
    lcsap_slg_pending_t *pending = NULL;

    ogs_list_for_each(&slg_pending_list, pending) {
        if (pending->correlation_id == correlation_id)
            return pending;
    }


    return NULL;
}

static int lcsap_slg_answer(lcsap_slg_pending_t *pending,
        uint32_t result_code, const uint8_t *geographic_information,
        size_t geographic_information_len)
{
    struct msg *answer = NULL;
    struct avp *avp = NULL;
    union avp_value value;
    int rv;

    ogs_assert(pending);
    ogs_assert(pending->diameter_request);

    answer = pending->diameter_request;
    rv = fd_msg_new_answer_from_req(fd_g_config->cnf_dict, &answer, 0);
    if (rv != 0) {
        ogs_error("fd_msg_new_answer_from_req() failed for Provide-Location [%d]",
                rv);
        return OGS_ERROR;
    }
    pending->diameter_request = NULL;

    rv = fd_msg_add_origin(answer, 0);
    ogs_assert(rv == 0);
    rv = fd_msg_rescode_set(answer,
            (char *)(result_code == ER_DIAMETER_SUCCESS ?
                "DIAMETER_SUCCESS" : "DIAMETER_UNABLE_TO_COMPLY"),
            NULL, NULL, 1);
    ogs_assert(rv == 0);
    rv = ogs_diam_message_vendor_specific_appid_set(
            answer, OGS_DIAM_SLG_APPLICATION_ID);
    ogs_assert(rv == 0);

    if (result_code == ER_DIAMETER_SUCCESS &&
        geographic_information && geographic_information_len) {
        rv = fd_msg_avp_new(ogs_diam_slg_location_estimate, 0, &avp);
        ogs_assert(rv == 0);
        memset(&value, 0, sizeof(value));
        value.os.data = (uint8_t *)geographic_information;
        value.os.len = geographic_information_len;
        rv = fd_msg_avp_setvalue(avp, &value);
        ogs_assert(rv == 0);
        rv = fd_msg_avp_add(answer, MSG_BRW_LAST_CHILD, avp);
        ogs_assert(rv == 0);

        rv = fd_msg_avp_new(ogs_diam_slg_age_of_location_estimate, 0, &avp);
        ogs_assert(rv == 0);
        memset(&value, 0, sizeof(value));
        value.u32 = 0;
        rv = fd_msg_avp_setvalue(avp, &value);
        ogs_assert(rv == 0);
        rv = fd_msg_avp_add(answer, MSG_BRW_LAST_CHILD, avp);
        ogs_assert(rv == 0);
    }

    rv = fd_msg_avp_new(ogs_diam_auth_session_state, 0, &avp);
    ogs_assert(rv == 0);
    memset(&value, 0, sizeof(value));
    value.i32 = OGS_DIAM_AUTH_SESSION_NO_STATE_MAINTAINED;
    rv = fd_msg_avp_setvalue(avp, &value);
    ogs_assert(rv == 0);
    rv = fd_msg_avp_add(answer, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(rv == 0);

    rv = fd_msg_send(&answer, NULL, NULL);
    if (rv != 0) {
        ogs_error("fd_msg_send() failed for SLg answer [%d]", rv);
        return OGS_ERROR;
    }
    return OGS_OK;
}

static void lcsap_slg_pending_remove(lcsap_slg_pending_t *pending)
{
    ogs_assert(pending);
    ogs_list_remove(&slg_pending_list, pending);
    ogs_timer_delete(pending->timer);
    if (pending->diameter_request)
        fd_msg_free(pending->diameter_request);
    ogs_free(pending);
}

static void lcsap_slg_timeout(void *data)
{
    lcsap_slg_pending_t *pending = data;

    ogs_assert(pending);
    ogs_warn("SLg Provide-Location timed out [Correlation-ID:%u]",
            pending->correlation_id);
    if (lcsap_slg_answer(pending, ER_DIAMETER_UNABLE_TO_COMPLY, NULL, 0) != OGS_OK)
        ogs_error("Failed to send SLg timeout answer");
    lcsap_slg_pending_remove(pending);
}

void lcsap_slg_init(void)
{
    ogs_list_init(&slg_pending_list);
}

void lcsap_slg_final(void)
{
    lcsap_slg_pending_t *pending = NULL, *next = NULL;

    ogs_list_for_each_safe(&slg_pending_list, next, pending)
        lcsap_slg_pending_remove(pending);
}

static int lcsap_slg_geographical_area(
        LCSAP_Geographical_Area_t *area, uint8_t info[11], size_t *info_len)
{
    LCSAP_Geographical_Coordinates_t *coordinates = NULL;
    int32_t longitude;
    uint32_t latitude;

    if (!area || !info_len)
        return OGS_ERROR;

    if (area->present == LCSAP_Geographical_Area_PR_point &&
        area->choice.point) {
        coordinates = area->choice.point->geographical_Coordinates;
    } else if (area->present ==
            LCSAP_Geographical_Area_PR_ellipsoidPoint_With_Uncertainty_Ellipse &&
            area->choice.ellipsoidPoint_With_Uncertainty_Ellipse &&
            area->choice.ellipsoidPoint_With_Uncertainty_Ellipse->
                uncertainty_Ellipse) {
        LCSAP_Ellipsoid_Point_With_Uncertainty_Ellipse_t *ellipse =
            area->choice.ellipsoidPoint_With_Uncertainty_Ellipse;
        coordinates = ellipse->geographical_Coordinates;
        if (ellipse->uncertainty_Ellipse->uncertainty_SemiMajor < 0 ||
            ellipse->uncertainty_Ellipse->uncertainty_SemiMajor > 127 ||
            ellipse->uncertainty_Ellipse->uncertainty_SemiMinor < 0 ||
            ellipse->uncertainty_Ellipse->uncertainty_SemiMinor > 127 ||
            ellipse->uncertainty_Ellipse->orientation_Major_Axis < 0 ||
            ellipse->uncertainty_Ellipse->orientation_Major_Axis > 89 ||
            ellipse->confidence < 0 || ellipse->confidence > 100)
            return OGS_ERROR;
    } else {
        return OGS_ERROR;
    }
    if (!coordinates)
        return OGS_ERROR;

    if (coordinates->latitudeSign != LCSAP_LatitudeSign_north &&
        coordinates->latitudeSign != LCSAP_LatitudeSign_south)
        return OGS_ERROR;
    if (coordinates->degreesLatitude < 0 ||
        coordinates->degreesLatitude > 8388607 ||
        coordinates->degreesLongitude < -8388608 ||
        coordinates->degreesLongitude > 8388607)
        return OGS_ERROR;

    latitude = (uint32_t)coordinates->degreesLatitude;
    longitude = (int32_t)coordinates->degreesLongitude;

    info[0] = area->present == LCSAP_Geographical_Area_PR_point ?
        0x80 : 0x81;
    info[1] = (coordinates->latitudeSign ==
            LCSAP_LatitudeSign_south ? 0x80 : 0) |
        (uint8_t)((latitude >> 16) & 0x7f);
    info[2] = (uint8_t)(latitude >> 8);
    info[3] = (uint8_t)latitude;
    info[4] = (uint8_t)(longitude >> 16);
    info[5] = (uint8_t)(longitude >> 8);
    info[6] = (uint8_t)longitude;
    if (area->present ==
            LCSAP_Geographical_Area_PR_ellipsoidPoint_With_Uncertainty_Ellipse) {
        LCSAP_Ellipsoid_Point_With_Uncertainty_Ellipse_t *ellipse =
            area->choice.ellipsoidPoint_With_Uncertainty_Ellipse;
        info[7] = (uint8_t)ellipse->uncertainty_Ellipse->uncertainty_SemiMajor;
        info[8] = (uint8_t)ellipse->uncertainty_Ellipse->uncertainty_SemiMinor;
        info[9] = (uint8_t)(ellipse->uncertainty_Ellipse->
                orientation_Major_Axis * 2);
        info[10] = (uint8_t)ellipse->confidence;
        *info_len = 11;
    } else {
        *info_len = 7;
    }
    return OGS_OK;
}

static void lcsap_slg_location_response(LCSAP_Location_Response_t *response,
        bool successful)
{
    LCSAP_ProtocolIE_Container_81P1_t *container = NULL;
    LCSAP_Geographical_Area_t *area = NULL;
    LCSAP_Correlation_ID_t *correlation = NULL;
    uint8_t information[11];
    size_t information_len = 0;
    uint32_t correlation_id;
    int i;
    lcsap_slg_pending_t *pending = NULL;

    if (!response || !response->protocolIEs)
        return;
    container = (LCSAP_ProtocolIE_Container_81P1_t *)
        response->protocolIEs;
    for (i = 0; i < OGS_ASN_LIST_COUNT(&container->list); i++) {
        LCSAP_Location_Response_IEs_t *ie =
            OGS_ASN_LIST_GET(&container->list, i);
        if (!ie)
            continue;
        if (ie->id == LCSAP_id_Correlation_ID &&
            ie->value.present ==
                LCSAP_Location_Response_IEs__value_PR_Correlation_ID)
            correlation = ie->value.choice.Correlation_ID;
        else if (ie->id == LCSAP_id_Location_Estimate &&
            ie->value.present ==
                LCSAP_Location_Response_IEs__value_PR_Geographical_Area)
            area = ie->value.choice.Geographical_Area;
    }

    if (!correlation || correlation->size != 4 || !correlation->buf) {
        ogs_warn("Discard LCS-AP Location Response without Correlation-ID");
        return;
    }
    correlation_id = ((uint32_t)correlation->buf[0] << 24) |
        ((uint32_t)correlation->buf[1] << 16) |
        ((uint32_t)correlation->buf[2] << 8) |
        (uint32_t)correlation->buf[3];
    pending = lcsap_slg_pending_find(correlation_id);
    if (!pending) {
        ogs_warn("LCS-AP Location Response has unknown Correlation-ID[%u]",
                correlation_id);
        return;
    }

    if (!successful || lcsap_slg_geographical_area(area, information,
                &information_len) != OGS_OK) {
        if (lcsap_slg_answer(pending, ER_DIAMETER_UNABLE_TO_COMPLY, NULL, 0) !=
                OGS_OK)
            ogs_error("Failed to send SLg location failure answer");
    } else if (lcsap_slg_answer(pending, ER_DIAMETER_SUCCESS,
                information, information_len) != OGS_OK) {
        ogs_error("Failed to send SLg location answer");
    }
    lcsap_slg_pending_remove(pending);
}

static int lcsap_slg_optional_grouped_integer(struct avp *group,
        struct dict_object *dict, long *value, bool *present)
{
    struct avp *avp = NULL;
    struct avp_hdr *hdr = NULL;
    int rv;

    rv = fd_avp_search_avp(group, dict, &avp);
    if (rv == ENOENT) {
        *present = false;
        return OGS_OK;
    }
    if (rv != 0 || !avp || fd_msg_avp_hdr(avp, &hdr) != 0 ||
        !hdr->avp_value)
        return OGS_ERROR;

    *value = hdr->avp_value->i32;
    *present = true;
    return OGS_OK;
}

void lcsap_handle_slg_request(struct msg *request)
{
    struct avp *avp = NULL;
    struct avp *qos_avp = NULL;
    struct avp_hdr *hdr = NULL;
    char imsi[OGS_MAX_IMSI_BCD_LEN + 1];
    size_t imsi_len;
    long location_type = LCSAP_Location_Type_geographic_Information;
    long client_type = LCSAP_LCS_Client_Type_value_Added_Services;
    long lcs_priority;
    long lcs_service_type_id;
    long velocity_requested;
    lcsap_location_request_options_t options = { 0 };
    ogs_nas_plmn_id_t nas_plmn_id;
    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;
    lcsap_slg_pending_t *pending = NULL;
    ogs_pkbuf_t *pkbuf = NULL;
    uint32_t correlation_id;
    int rv;

    ogs_assert(request);
    memset(imsi, 0, sizeof(imsi));

    rv = fd_msg_search_avp(request, ogs_diam_slg_user_name, &avp);
    if (rv != 0 || !avp || fd_msg_avp_hdr(avp, &hdr) != 0 ||
        !hdr->avp_value || !hdr->avp_value->os.data ||
        hdr->avp_value->os.len < 5 ||
        hdr->avp_value->os.len > OGS_MAX_IMSI_BCD_LEN) {
        ogs_warn("Reject SLg request without a valid User-Name");
        goto reject;
    }
    imsi_len = hdr->avp_value->os.len;
    memcpy(imsi, hdr->avp_value->os.data, imsi_len);
    imsi[imsi_len] = '\0';
    for (size_t i = 0; i < imsi_len; i++) {
        if (imsi[i] < '0' || imsi[i] > '9') {
            ogs_warn("Reject SLg request with non-numeric User-Name");
            goto reject;
        }
    }

    rv = fd_msg_search_avp(request, ogs_diam_slg_imei, &avp);
    if (rv != 0)
        goto reject;
    if (avp) {
        if (fd_msg_avp_hdr(avp, &hdr) != 0 || !hdr->avp_value ||
            !hdr->avp_value->os.data ||
            hdr->avp_value->os.len != sizeof(options.imei))
            goto reject;
        options.imei_present = true;
        memcpy(options.imei, hdr->avp_value->os.data, sizeof(options.imei));
    }

    rv = fd_msg_search_avp(request, ogs_diam_slg_slg_location_type, &avp);
    if (rv != 0 || !avp || fd_msg_avp_hdr(avp, &hdr) != 0) {
        ogs_warn("Reject Provide-Location-Request without SLg-Location-Type");
        goto reject;
    }
    if (!hdr->avp_value) {
        ogs_warn("Cannot read SLg-Location-Type value");
        goto reject;
    }
    location_type = hdr->avp_value->i32;
    if (location_type < 0 || location_type > 1) {
        ogs_warn("Reject unsupported SLg-Location-Type[%ld]", location_type);
        goto reject;
    }

    rv = fd_msg_search_avp(request, ogs_diam_slg_client_type, &avp);
    if (rv != 0)
        goto reject;
    if (avp) {
        if (fd_msg_avp_hdr(avp, &hdr) != 0)
            goto reject;
        if (!hdr->avp_value)
            goto reject;
        client_type = hdr->avp_value->i32;
    }
    if (client_type < LCSAP_LCS_Client_Type_emergency_Services ||
        client_type > LCSAP_LCS_Client_Type_pLMN_Operator_Target_MS_Service_Support)
        goto reject;

    rv = fd_msg_search_avp(request, ogs_diam_slg_lcs_priority, &avp);
    if (rv != 0)
        goto reject;
    if (avp) {
        if (fd_msg_avp_hdr(avp, &hdr) != 0 || !hdr->avp_value)
            goto reject;
        lcs_priority = hdr->avp_value->i32;
        if (lcs_priority < 0 || lcs_priority > 1)
            goto reject;
        options.lcs_priority_present = true;
        options.lcs_priority = (uint8_t)lcs_priority;
    }

    rv = fd_msg_search_avp(request, ogs_diam_slg_lcs_qos, &qos_avp);
    if (rv != 0)
        goto reject;
    if (qos_avp) {
        if (lcsap_slg_optional_grouped_integer(qos_avp,
                    ogs_diam_slg_horizontal_accuracy,
                    &options.horizontal_accuracy,
                    &options.horizontal_accuracy_present) != OGS_OK ||
            lcsap_slg_optional_grouped_integer(qos_avp,
                    ogs_diam_slg_vertical_requested,
                    &options.vertical_requested,
                    &options.vertical_requested_present) != OGS_OK ||
            lcsap_slg_optional_grouped_integer(qos_avp,
                    ogs_diam_slg_vertical_accuracy,
                    &options.vertical_accuracy,
                    &options.vertical_accuracy_present) != OGS_OK ||
            lcsap_slg_optional_grouped_integer(qos_avp,
                    ogs_diam_slg_response_time,
                    &options.response_time,
                    &options.response_time_present) != OGS_OK)
            goto reject;
        options.lcs_qos_present =
            options.horizontal_accuracy_present ||
            options.vertical_requested_present ||
            options.vertical_accuracy_present ||
            options.response_time_present;
    }

    rv = fd_msg_search_avp(request,
            ogs_diam_slg_velocity_requested, &avp);
    if (rv != 0)
        goto reject;
    if (avp) {
        if (fd_msg_avp_hdr(avp, &hdr) != 0 || !hdr->avp_value)
            goto reject;
        velocity_requested = hdr->avp_value->i32;
        if (velocity_requested < 0 || velocity_requested > 1)
            goto reject;
        options.include_velocity_present = true;
        options.include_velocity =
            velocity_requested == 1 ?
                LCSAP_Include_Velocity_requested :
                LCSAP_Include_Velocity_not_Requested;
    }

    rv = fd_msg_search_avp(request,
            ogs_diam_slg_lcs_service_type_id, &avp);
    if (rv != 0)
        goto reject;
    if (avp) {
        if (fd_msg_avp_hdr(avp, &hdr) != 0 || !hdr->avp_value)
            goto reject;
        lcs_service_type_id = hdr->avp_value->i32;
        if (lcs_service_type_id < 0 || lcs_service_type_id > 127)
            goto reject;
        options.lcs_service_type_id_present = true;
        options.lcs_service_type_id = lcs_service_type_id;
    }

    mme_ue = mme_ue_find_by_imsi_bcd(imsi);
    if (!mme_ue || !ECM_CONNECTED(mme_ue)) {
        ogs_warn("SLg request for inactive or unknown IMSI[%s]", imsi);
        goto reject;
    }
    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    if (!enb_ue || enb_ue->mme_ue_s1ap_id == INVALID_UE_S1AP_ID ||
        enb_ue->enb_ue_s1ap_id == INVALID_UE_S1AP_ID) {
        ogs_warn("SLg request for IMSI[%s] has no valid S1 context", imsi);
        goto reject;
    }
    correlation_id = enb_ue->mme_ue_s1ap_id;
    if (lcsap_slg_pending_find(correlation_id)) {
        ogs_warn("SLg request already pending for IMSI[%s]", imsi);
        goto reject;
    }

    pending = ogs_calloc(1, sizeof(*pending));
    ogs_assert(pending);
    pending->correlation_id = correlation_id;
    pending->diameter_request = request;
    pending->timer = ogs_timer_add(ogs_app()->timer_mgr,
            lcsap_slg_timeout, pending);
    if (!pending->timer) {
        ogs_error("ogs_timer_add() failed for SLg transaction");
        ogs_free(pending);
        goto reject;
    }
    ogs_list_add(&slg_pending_list, pending);

    ogs_nas_from_plmn_id(&nas_plmn_id, &mme_ue->e_cgi.plmn_id);
    pkbuf = lcsap_build_location_request(correlation_id,
            location_type == 0 ?
                LCSAP_Location_Type_geographic_Information :
                LCSAP_Location_Type_last_known_location,
            (const uint8_t *)imsi, imsi_len,
            (const uint8_t *)&nas_plmn_id, mme_ue->e_cgi.cell_id,
            client_type, &options);
    if (!pkbuf || lcsap_send_to_esmlc(pkbuf) != OGS_OK) {
        if (pending->diameter_request)
            (void)lcsap_slg_answer(pending, ER_DIAMETER_UNABLE_TO_COMPLY,
                    NULL, 0);
        lcsap_slg_pending_remove(pending);
        return;
    }
    ogs_timer_start(pending->timer, ogs_time_from_sec(30));
    return;

reject:
    if (lcsap_slg_answer(&(lcsap_slg_pending_t) {
                .diameter_request = request
            }, ER_DIAMETER_UNABLE_TO_COMPLY, NULL, 0) != OGS_OK)
        ogs_error("Failed to send SLg rejection answer");
}

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
        if (!ie)
            continue;
        switch (ie->id) {
        case LCSAP_id_Correlation_ID:
            if (ie->value.present ==
                    LCSAP_Connection_Oriented_Information_IEs__value_PR_Correlation_ID)
                correlation = ie->value.choice.Correlation_ID;
            break;
        case LCSAP_id_Payload_Type:
            if (ie->value.present ==
                    LCSAP_Connection_Oriented_Information_IEs__value_PR_Payload_Type)
                payload_type = ie->value.choice.Payload_Type;
            break;
        case LCSAP_id_APDU:
            if (ie->value.present ==
                    LCSAP_Connection_Oriented_Information_IEs__value_PR_APDU)
                apdu = ie->value.choice.APDU;
            break;
        default:
            break;
        }
    }

    if (!payload_type || !correlation || correlation->size != 4 ||
        !correlation->buf || !apdu || !apdu->size || !apdu->buf) {
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
                if (nasbuf) {
                    int rv = nas_eps_send_to_enb(mme_ue, nasbuf);
                    if (rv != OGS_OK)
                        ogs_error("Failed forwarding LPP to UE "
                                "[Correlation-ID:%u, MME-UE-S1AP-ID:%u, "
                                "rv:%d]", mme_ue_s1ap_id,
                                enb_ue->mme_ue_s1ap_id, rv);
                    else
                        ogs_debug("Forwarded LPP to UE "
                                "[Correlation-ID:%u]", mme_ue_s1ap_id);
                } else {
                    ogs_error("Failed to build downlink LPP NAS message");
                }
            } else {
                ogs_warn("LPP Correlation-ID[%u] has no active S1 context",
                        mme_ue_s1ap_id);
            }
        } else if (*payload_type == LCSAP_Payload_Type_lPPa) {
            if (enb_ue) {
                mme_ue_t *mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
                ogs_pkbuf_t *s1apbuf = NULL;

                if (!mme_ue || mme_ue->enb_ue_id != enb_ue->id ||
                    !enb_ue->lppa_routing_id_presence) {
                    ogs_warn("LPPA Correlation-ID[%u] has no active S1 "
                            "routing [MME-UE-S1AP-ID:%u, routing-id:%u, "
                            "present:%d]", mme_ue_s1ap_id,
                            enb_ue->mme_ue_s1ap_id,
                            enb_ue->lppa_routing_id,
                            enb_ue->lppa_routing_id_presence);
                    return;
                }

                s1apbuf = s1ap_build_downlink_ue_associated_lppa_transport(
                        enb_ue, enb_ue->lppa_routing_id,
                        apdu->buf, apdu->size);
                if (s1apbuf) {
                    int rv = s1ap_send_to_enb_ue(enb_ue, s1apbuf);
                    if (rv != OGS_OK)
                        ogs_error("Failed forwarding LPPA to eNB "
                                "[Correlation-ID:%u, MME-UE-S1AP-ID:%u, "
                                "eNB-UE-S1AP-ID:%u, routing-id:%u, rv:%d]",
                                mme_ue_s1ap_id, enb_ue->mme_ue_s1ap_id,
                                enb_ue->enb_ue_s1ap_id,
                                enb_ue->lppa_routing_id, rv);
                    else
                        ogs_debug("Forwarded LPPA to eNB "
                                "[Correlation-ID:%u, routing-id:%u]",
                                mme_ue_s1ap_id, enb_ue->lppa_routing_id);
                } else {
                    ogs_error("Failed to build downlink LPPA S1AP message");
                }
            } else {
                ogs_warn("LPPA Correlation-ID[%u] has no active S1 context",
                        mme_ue_s1ap_id);
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
    case MME_EVENT_LCSAP_MESSAGE:
        lcsap_process_message(e->pkbuf);
        break;
    default:
        ogs_error("Unexpected LCS-AP event %s", mme_event_get_name(e));
        break;
    }
}

void lcsap_process_message(ogs_pkbuf_t *pkbuf)
{
    LCSAP_LCS_AP_PDU_t message;
    int rv;

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
        if (message.present == LCSAP_LCS_AP_PDU_PR_successfulOutcome &&
            message.choice.successfulOutcome &&
            message.choice.successfulOutcome->procedureCode ==
                LCSAP_id_Location_Service_Request &&
            message.choice.successfulOutcome->value.present ==
                LCSAP_SuccessfulOutcome__value_PR_Location_Response) {
            lcsap_slg_location_response(
                message.choice.successfulOutcome->value.choice.
                        Location_Response, true);
        } else if (message.present ==
                LCSAP_LCS_AP_PDU_PR_unsuccessfulOutcome &&
                message.choice.unsuccessfulOutcome &&
                message.choice.unsuccessfulOutcome->procedureCode ==
                        LCSAP_id_Location_Service_Request &&
                message.choice.unsuccessfulOutcome->value.present ==
                        LCSAP_UnsuccessfulOutcome__value_PR_Location_Response) {
            lcsap_slg_location_response(
                message.choice.unsuccessfulOutcome->value.choice.
                        Location_Response, false);
        }
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
}