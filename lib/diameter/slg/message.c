/*
 * Copyright (C) 2026 by LetMeConnect
 *
 * This file is part of Open5GS.
 *
 * Open5GS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "ogs-diameter-slg.h"

#define CHECK_dict_search(_type, _criteria, _what, _result) \
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, (_type), (_criteria), \
                (_what), (_result), ENOENT))

struct dict_object *ogs_diam_slg_application = NULL;
struct dict_object *ogs_diam_slg_cmd_psl = NULL;
struct dict_object *ogs_diam_slg_cmd_psl_answer = NULL;
struct dict_object *ogs_diam_slg_user_name = NULL;
struct dict_object *ogs_diam_slg_location_type = NULL;
struct dict_object *ogs_diam_slg_slg_location_type = NULL;
struct dict_object *ogs_diam_slg_client_type = NULL;
struct dict_object *ogs_diam_slg_location_estimate = NULL;
struct dict_object *ogs_diam_slg_age_of_location_estimate = NULL;

int ogs_diam_slg_init(void)
{
    struct dict_object *vendor = NULL;
    struct dict_application_data app_data = {
        OGS_DIAM_SLG_APPLICATION_ID, "SLg"
    };
    struct dict_cmd_data cmd_data = {
        OGS_DIAM_SLG_CMD_CODE_PROVIDE_SUBSCRIBER_LOCATION,
        "Provide-Subscriber-Location-Request",
        CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE | CMD_FLAG_ERROR,
        CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE
    };
    struct dict_cmd_data answer_data = {
        OGS_DIAM_SLG_CMD_CODE_PROVIDE_SUBSCRIBER_LOCATION,
        "Provide-Subscriber-Location-Answer",
        CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE | CMD_FLAG_ERROR,
        CMD_FLAG_PROXIABLE
    };
    struct dict_avp_request avp_request;

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_VENDOR,
                VENDOR_BY_NAME, "3GPP", &vendor, ENOENT));
    CHECK_FCT(fd_dict_new(fd_g_config->cnf_dict, DICT_APPLICATION,
                &app_data, vendor, &ogs_diam_slg_application));
    CHECK_FCT(fd_dict_new(fd_g_config->cnf_dict, DICT_COMMAND,
                &cmd_data, ogs_diam_slg_application, &ogs_diam_slg_cmd_psl));
    CHECK_FCT(fd_dict_new(fd_g_config->cnf_dict, DICT_COMMAND,
                &answer_data, ogs_diam_slg_application,
                &ogs_diam_slg_cmd_psl_answer));

    CHECK_dict_search(DICT_AVP, AVP_BY_NAME, "User-Name",
            &ogs_diam_slg_user_name);
    avp_request.avp_vendor = 10415;
    avp_request.avp_name = "Location-Type";
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_AND_VENDOR, &avp_request,
            &ogs_diam_slg_location_type);
    avp_request.avp_name = "SLg-Location-Type";
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_AND_VENDOR, &avp_request,
            &ogs_diam_slg_slg_location_type);
    avp_request.avp_name = "LCS-Client-Type";
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_AND_VENDOR, &avp_request,
            &ogs_diam_slg_client_type);
    avp_request.avp_name = "Location-Estimate";
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_AND_VENDOR, &avp_request,
            &ogs_diam_slg_location_estimate);
    avp_request.avp_name = "Age-Of-Location-Estimate";
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_AND_VENDOR, &avp_request,
            &ogs_diam_slg_age_of_location_estimate);

    return OGS_OK;
}
