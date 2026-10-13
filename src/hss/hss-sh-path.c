/*
 * Copyright (C) 2026 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "ogs-crypt.h"

#include "hss-context.h"
#include "hss-sh-path.h"

#include <stdarg.h>

static struct disp_hdl *hdl_sh_udr = NULL;

typedef struct hss_sh_pending_s {
    struct msg *udr;
    char imsi[OGS_MAX_IMSI_BCD_LEN+1];
    bool location_requested;
    bool state_requested;
    bool scscf_requested;
    int32_t auth_session_state;
} hss_sh_pending_t;

static void hss_sh_get_auth_session_state(hss_sh_pending_t *pending)
{
    int ret;
    struct avp *avp = NULL;
    struct avp_hdr *hdr = NULL;

    ret = fd_msg_search_avp(pending->udr, ogs_diam_auth_session_state,
            &avp);
    if (ret == 0 && avp && fd_msg_avp_hdr(avp, &hdr) == 0 &&
            hdr && hdr->avp_value)
        pending->auth_session_state = hdr->avp_value->i32;
}

static int hss_sh_add_auth_session_state(struct msg *ans, int32_t state)
{
    int ret;
    struct avp *avp = NULL;
    union avp_value val;

    ret = fd_msg_avp_new(ogs_diam_auth_session_state, 0, &avp);
    if (ret != 0)
        return ret;
    val.i32 = state;
    ret = fd_msg_avp_setvalue(avp, &val);
    if (ret == 0)
        ret = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp);
    return ret;
}

static void hss_sh_send_uda(hss_sh_pending_t *pending,
        uint32_t result_code, const char *xml);

static void hss_sh_fail_request(struct msg **msg)
{
    hss_sh_pending_t *pending;

    ogs_assert(msg);
    ogs_assert(*msg);
    pending = ogs_calloc(1, sizeof(*pending));
    ogs_assert(pending);
    pending->udr = *msg;
    hss_sh_get_auth_session_state(pending);
    hss_sh_send_uda(pending, ER_DIAMETER_UNABLE_TO_COMPLY, NULL);
    *msg = NULL;
}

static void hss_sh_send_uda(hss_sh_pending_t *pending,
        uint32_t result_code, const char *xml)
{
    int ret;
    struct msg *ans = pending->udr;
    struct avp *avp = NULL;
    union avp_value val;

    ret = fd_msg_new_answer_from_req(fd_g_config->cnf_dict, &ans, 0);
    if (ret != 0) {
        ogs_error("Failed to create User-Data-Answer");
        if (pending->udr)
            (void)fd_msg_free(pending->udr);
        pending->udr = NULL;
        ogs_free(pending);
        return;
    }
    pending->udr = ans;

    ret = ogs_diam_message_vendor_specific_appid_set(
            ans, OGS_DIAM_SH_APPLICATION_ID);
    if (ret != 0) {
        ogs_error("Failed to set Sh Vendor-Specific-Application-Id");
        goto done;
    }
    ret = fd_msg_add_origin(ans, 0);
    if (ret != 0)
        goto done;

    if (xml) {
        ret = fd_msg_avp_new(ogs_diam_sh_user_data, 0, &avp);
        if (ret != 0)
            goto done;
        val.os.data = (uint8_t *)xml;
        val.os.len = strlen(xml);
        ret = fd_msg_avp_setvalue(avp, &val);
        if (ret == 0)
            ret = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp);
        if (ret != 0)
            goto done;
    }

    ret = fd_msg_rescode_set(ans,
            result_code == ER_DIAMETER_SUCCESS ?
                (char *)"DIAMETER_SUCCESS" :
                (char *)"DIAMETER_UNABLE_TO_COMPLY",
            NULL, NULL, 1);
    if (ret != 0)
        goto done;

    ret = hss_sh_add_auth_session_state(ans, pending->auth_session_state);
    if (ret != 0)
        goto done;

    ret = fd_msg_send(&pending->udr, NULL, NULL);
    if (ret != 0) {
        ogs_error("Failed to send User-Data-Answer");
    } else
        pending->udr = NULL;

done:
    if (pending->udr)
        (void)fd_msg_free(pending->udr);
    ogs_free(pending);
}

static void hss_sh_psi_reply(struct msg **msg, hss_sh_pending_t *pending,
        uint32_t result_code, const char *xml)
{
    if (msg && *msg) {
        (void)fd_msg_free(*msg);
        *msg = NULL;
    }
    hss_sh_send_uda(pending, result_code, xml);
}

static int hss_sh_xml_escape(char *output, size_t output_len,
        const char *input)
{
    const char *replacement;
    size_t used = 0;

    while (*input) {
        switch (*input) {
        case '&':
            replacement = "&amp;";
            break;
        case '<':
            replacement = "&lt;";
            break;
        case '>':
            replacement = "&gt;";
            break;
        case '"':
            replacement = "&quot;";
            break;
        case '\'':
            replacement = "&apos;";
            break;
        default:
            replacement = NULL;
            break;
        }
        if (replacement) {
            size_t len = strlen(replacement);
            if (used + len >= output_len)
                return OGS_ERROR;
            memcpy(output + used, replacement, len);
            used += len;
        } else {
            if (used + 1 >= output_len)
                return OGS_ERROR;
            output[used++] = *input;
        }
        input++;
    }
    output[used] = '\0';
    return OGS_OK;
}

static int hss_sh_xml_append(char *xml, size_t xml_len, size_t *offset,
        const char *format, ...)
{
    int written;
    va_list ap;

    if (*offset >= xml_len)
        return OGS_ERROR;
    va_start(ap, format);
    written = ogs_vsnprintf(xml + *offset, xml_len - *offset, format, ap);
    va_end(ap);
    if (written < 0 || (size_t)written >= xml_len - *offset)
        return OGS_ERROR;
    *offset += written;
    return OGS_OK;
}

static void hss_sh_psi_cb(void *data, struct msg **msg)
{
    hss_sh_pending_t *pending = data;
    int ret;
    struct avp *avp = NULL, *child = NULL;
    struct avp_hdr *hdr = NULL;
    uint32_t result_code = 0, state = 0, age = 0, rat_type = 0;
    uint8_t ecgi[7], tai[5];
    char ecgi_b64[16], tai_b64[16], xml[1024], scscf[512];
    char *scscf_name = NULL;
    size_t xml_len = 0;

    ogs_assert(pending);
    if (!msg || !*msg) {
        ogs_error("Provide-Subscriber-Info returned no answer");
        hss_sh_send_uda(pending, ER_DIAMETER_UNABLE_TO_COMPLY, NULL);
        return;
    }

    ret = fd_msg_search_avp(*msg, ogs_diam_result_code, &avp);
    if (ret == 0 && avp && fd_msg_avp_hdr(avp, &hdr) == 0 &&
            hdr && hdr->avp_value) {
        result_code = hdr->avp_value->u32;
    } else {
        struct avp *experimental = NULL;
        ret = fd_msg_search_avp(*msg, ogs_diam_experimental_result,
                &experimental);
        if (ret == 0 && experimental &&
                fd_avp_search_avp(experimental,
                    ogs_diam_experimental_result_code, &child) == 0 &&
                child && fd_msg_avp_hdr(child, &hdr) == 0 &&
                hdr && hdr->avp_value)
            result_code = hdr->avp_value->u32;
    }

    if (result_code != ER_DIAMETER_SUCCESS) {
        hss_sh_psi_reply(msg, pending, ER_DIAMETER_UNABLE_TO_COMPLY, NULL);
        return;
    }

    if (pending->state_requested) {
        ret = fd_msg_search_avp(*msg, ogs_diam_s6a_eps_user_state, &avp);
        if (ret == 0 && avp &&
                fd_avp_search_avp(avp, ogs_diam_s6a_mme_user_state,
                    &child) == 0 && child &&
                fd_avp_search_avp(child, ogs_diam_s6a_user_state,
                    &avp) == 0 && avp &&
                fd_msg_avp_hdr(avp, &hdr) == 0 && hdr && hdr->avp_value)
            state = hdr->avp_value->u32;
        else
            goto unavailable;
    }

    if (pending->location_requested) {
        ret = fd_msg_search_avp(*msg,
                ogs_diam_s6a_eps_location_information, &avp);
        if (ret == 0 && avp &&
                fd_avp_search_avp(avp,
                    ogs_diam_s6a_mme_location_information, &child) == 0 &&
                child) {
            struct avp *field = NULL;
            if (fd_avp_search_avp(child,
                        ogs_diam_s6a_e_utran_cell_global_identity,
                        &field) == 0 && field &&
                    fd_msg_avp_hdr(field, &hdr) == 0 && hdr &&
                    hdr->avp_value &&
                    hdr->avp_value->os.len == sizeof(ecgi))
                memcpy(ecgi, hdr->avp_value->os.data, sizeof(ecgi));
            else
                goto unavailable;

            if (fd_avp_search_avp(child,
                        ogs_diam_s6a_tracking_area_identity, &field) == 0 &&
                    field && fd_msg_avp_hdr(field, &hdr) == 0 && hdr &&
                    hdr->avp_value &&
                    hdr->avp_value->os.len == sizeof(tai))
                memcpy(tai, hdr->avp_value->os.data, sizeof(tai));
            else
                goto unavailable;

            if (fd_avp_search_avp(child,
                        ogs_diam_s6a_age_of_location_information,
                        &field) == 0 && field &&
                    fd_msg_avp_hdr(field, &hdr) == 0 && hdr &&
                    hdr->avp_value)
                age = hdr->avp_value->u32;
        } else {
            goto unavailable;
        }
    }

    ret = fd_msg_search_avp(*msg, ogs_diam_rat_type, &avp);
    if (ret == 0 && avp && fd_msg_avp_hdr(avp, &hdr) == 0 &&
            hdr && hdr->avp_value)
        rat_type = hdr->avp_value->u32;
    else
        rat_type = OGS_DIAM_S6A_RAT_TYPE_EUTRAN;

    if (pending->scscf_requested) {
        scscf_name = hss_cx_get_server_name_by_imsi(pending->imsi);
        if (scscf_name &&
                hss_sh_xml_escape(scscf, sizeof(scscf), scscf_name) != OGS_OK)
            goto unavailable;
    }

    if (hss_sh_xml_append(xml, sizeof(xml), &xml_len,
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                "<Sh-Data><Extension>") != OGS_OK)
        goto unavailable;
    if (pending->state_requested &&
            hss_sh_xml_append(xml, sizeof(xml), &xml_len,
                "<EPSUserState>%u</EPSUserState>", state) != OGS_OK)
        goto unavailable;
    if (pending->location_requested) {
        if (ogs_base64_encode_from_buffer(ecgi_b64, sizeof(ecgi_b64),
                    ecgi, sizeof(ecgi)) < 0 ||
            ogs_base64_encode_from_buffer(tai_b64, sizeof(tai_b64),
                    tai, sizeof(tai)) < 0)
            goto unavailable;
        if (hss_sh_xml_append(xml, sizeof(xml), &xml_len,
                "<EPSLocationInformation><E-UTRANCellGlobalId>%s"
                "</E-UTRANCellGlobalId><TrackingAreaId>%s</TrackingAreaId>"
                "<CurrentLocationRetrieved>1</CurrentLocationRetrieved>"
                "<AgeOfLocationInformation>%u</AgeOfLocationInformation>"
                "</EPSLocationInformation><EPSLocationInformation-Extension2>"
                "<RATtype>%u</RATtype></EPSLocationInformation-Extension2>",
                ecgi_b64, tai_b64, age, rat_type) != OGS_OK)
            goto unavailable;
    }
    if (scscf_name && hss_sh_xml_append(xml, sizeof(xml), &xml_len,
                "<S-CSCFName>%s</S-CSCFName>", scscf) != OGS_OK)
        goto unavailable;
    if (hss_sh_xml_append(xml, sizeof(xml), &xml_len,
                "</Extension></Sh-Data>") != OGS_OK)
        goto unavailable;
    hss_sh_psi_reply(msg, pending, ER_DIAMETER_SUCCESS, xml);
    return;

unavailable:
    hss_sh_psi_reply(msg, pending, ER_DIAMETER_UNABLE_TO_COMPLY, NULL);
}

static int hss_ogs_diam_sh_udr_cb(struct msg **msg, struct avp *avp,
        struct session *session, void *opaque, enum disp_action *act)
{
    int ret, rv;
    struct msg *qry = NULL, *req = NULL;
    struct avp *user_identity = NULL, *imsi_avp = NULL;
    struct avp *cursor = NULL;
    struct avp_hdr *hdr = NULL;
    struct avp *out = NULL;
    struct dict_object *model = NULL;
    union avp_value val;
    ogs_subscription_data_t subscription_data;
    hss_sh_pending_t *pending = NULL;
    bool location_requested = false, state_requested = false;
    bool scscf_requested = false;
    char imsi[OGS_MAX_IMSI_BCD_LEN+1] = { 0 };

    (void)avp;
    (void)session;
    (void)opaque;
    (void)act;

    if (!msg || !*msg)
        return EINVAL;

    qry = *msg;
    ret = fd_msg_search_avp(qry, ogs_diam_sh_user_identity, &user_identity);
    if (ret != 0 || !user_identity ||
            fd_msg_search_avp(user_identity, ogs_diam_sh_imsi, &imsi_avp) != 0 ||
            !imsi_avp || fd_msg_avp_hdr(imsi_avp, &hdr) != 0 || !hdr ||
            !hdr->avp_value || !hdr->avp_value->os.data ||
            hdr->avp_value->os.len == 0 ||
            hdr->avp_value->os.len > OGS_MAX_IMSI_BCD_LEN) {
        ogs_error("Invalid or unsupported Sh User-Identity");
        hss_sh_fail_request(msg);
        return 0;
    }
    memcpy(imsi, hdr->avp_value->os.data, hdr->avp_value->os.len);
    imsi[hdr->avp_value->os.len] = '\0';
    if (!ogs_imsi_bcd_is_valid(imsi)) {
        ogs_error("Invalid IMSI in Sh User-Identity");
        hss_sh_fail_request(msg);
        return 0;
    }

    ret = fd_msg_browse(qry, MSG_BRW_FIRST_CHILD, &cursor, NULL);
    while (ret == 0 && cursor) {
        if (fd_msg_model(cursor, &model) == 0 &&
                model == ogs_diam_sh_data_reference &&
                fd_msg_avp_hdr(cursor, &hdr) == 0 && hdr &&
                hdr->avp_value) {
            switch (hdr->avp_value->u32) {
            case 12:
                scscf_requested = true;
                break;
            case 14:
                location_requested = true;
                break;
            case 15:
                state_requested = true;
                break;
            default:
                break;
            }
        }
        ret = fd_msg_browse(cursor, MSG_BRW_NEXT, &cursor, NULL);
    }
    if (!location_requested && !state_requested && !scscf_requested) {
        ogs_error("Unsupported Sh Data-Reference values");
        hss_sh_fail_request(msg);
        return 0;
    }

    if (scscf_requested && !location_requested && !state_requested) {
        char *scscf_name = hss_cx_get_server_name_by_imsi(imsi);
        char scscf[512], xml[768];
        size_t xml_len = 0;

        if (!scscf_name ||
                hss_sh_xml_escape(scscf, sizeof(scscf), scscf_name) != OGS_OK ||
                hss_sh_xml_append(xml, sizeof(xml), &xml_len,
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    "<Sh-Data><Extension><S-CSCFName>%s</S-CSCFName>"
                    "</Extension></Sh-Data>", scscf) != OGS_OK) {
            hss_sh_fail_request(msg);
            return 0;
        }
        pending = ogs_calloc(1, sizeof(*pending));
        ogs_assert(pending);
        pending->udr = qry;
        hss_sh_get_auth_session_state(pending);
        hss_sh_send_uda(pending, ER_DIAMETER_SUCCESS, xml);
        *msg = NULL;
        return 0;
    }

    memset(&subscription_data, 0, sizeof(subscription_data));
    rv = hss_db_subscription_data(imsi, &subscription_data);
    if (rv != OGS_OK || !subscription_data.mme_host ||
            !subscription_data.mme_realm) {
        ogs_error("No serving MME available for IMSI[%s]", imsi);
        ogs_subscription_data_free(&subscription_data);
        hss_sh_fail_request(msg);
        return 0;
    }

    pending = ogs_calloc(1, sizeof(*pending));
    ogs_assert(pending);
    pending->udr = qry;
    hss_sh_get_auth_session_state(pending);
    ogs_cpystrn(pending->imsi, imsi, sizeof(pending->imsi));
    pending->location_requested = location_requested;
    pending->state_requested = state_requested;
    pending->scscf_requested = scscf_requested;

    ret = fd_msg_new(ogs_diam_s6a_cmd_psi, MSGFL_ALLOC_ETEID, &req);
    if (ret != 0)
        goto error;
    ret = fd_msg_new_session(req, (os0_t)"app_s6a", CONSTSTRLEN("app_s6a"));
    if (ret != 0)
        goto error;
    ret = fd_msg_avp_new(ogs_diam_auth_session_state, 0, &out);
    if (ret != 0)
        goto error;
    val.i32 = OGS_DIAM_AUTH_SESSION_NO_STATE_MAINTAINED;
    ret = fd_msg_avp_setvalue(out, &val);
    if (ret == 0)
        ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, out);
    if (ret != 0)
        goto error;
    ret = fd_msg_add_origin(req, 0);
    if (ret != 0)
        goto error;

    ret = fd_msg_avp_new(ogs_diam_destination_host, 0, &out);
    if (ret != 0)
        goto error;
    val.os.data = (uint8_t *)subscription_data.mme_host;
    val.os.len = strlen(subscription_data.mme_host);
    ret = fd_msg_avp_setvalue(out, &val);
    if (ret == 0)
        ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, out);
    if (ret != 0)
        goto error;

    ret = fd_msg_avp_new(ogs_diam_destination_realm, 0, &out);
    if (ret != 0)
        goto error;
    val.os.data = (uint8_t *)subscription_data.mme_realm;
    val.os.len = strlen(subscription_data.mme_realm);
    ret = fd_msg_avp_setvalue(out, &val);
    if (ret == 0)
        ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, out);
    if (ret != 0)
        goto error;

    ret = fd_msg_avp_new(ogs_diam_user_name, 0, &out);
    if (ret != 0)
        goto error;
    val.os.data = (uint8_t *)pending->imsi;
    val.os.len = strlen(pending->imsi);
    ret = fd_msg_avp_setvalue(out, &val);
    if (ret == 0)
        ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, out);
    if (ret != 0)
        goto error;

    ret = fd_msg_avp_new(ogs_diam_s6a_requested_user_data, 0, &out);
    if (ret != 0)
        goto error;
    val.u32 = (location_requested ? 1 : 0) |
        (state_requested ? 2 : 0);
    ret = fd_msg_avp_setvalue(out, &val);
    if (ret == 0)
        ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, out);
    if (ret != 0)
        goto error;

    ret = fd_msg_avp_new(ogs_diam_s6a_current_location, 0, &out);
    if (ret != 0)
        goto error;
    val.u32 = 1;
    ret = fd_msg_avp_setvalue(out, &val);
    if (ret == 0)
        ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, out);
    if (ret != 0)
        goto error;

    ret = ogs_diam_message_vendor_specific_appid_set(
            req, OGS_DIAM_S6A_APPLICATION_ID);
    if (ret != 0)
        goto error;

    ret = fd_msg_send(&req, hss_sh_psi_cb, pending);
    if (ret != 0)
        goto error;

    ogs_subscription_data_free(&subscription_data);
    *msg = NULL;
    return 0;

error:
    ogs_error("Failed to request subscriber information from MME");
    if (req)
        (void)fd_msg_free(req);
    ogs_subscription_data_free(&subscription_data);
    hss_sh_send_uda(pending, ER_DIAMETER_UNABLE_TO_COMPLY, NULL);
    *msg = NULL;
    return 0;
}

int hss_sh_init(void)
{
    int ret;
    struct disp_when data;

    ret = ogs_diam_sh_init();
    ogs_assert(ret == 0);

    memset(&data, 0, sizeof(data));
    data.app = ogs_diam_sh_application;
    data.command = ogs_diam_sh_cmd_udr;
    ret = fd_disp_register(hss_ogs_diam_sh_udr_cb, DISP_HOW_CC, &data,
            NULL, &hdl_sh_udr);
    ogs_assert(ret == 0);
    ret = fd_disp_app_support(ogs_diam_sh_application, ogs_diam_vendor, 1, 0);
    ogs_assert(ret == 0);
    return OGS_OK;
}

void hss_sh_final(void)
{
    if (hdl_sh_udr)
        (void)fd_disp_unregister(&hdl_sh_udr, NULL);
}
