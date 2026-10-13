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

#include "ogs-diameter-sh.h"

#define CHECK_dict_search(_type, _criteria, _what, _result) \
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, (_type), (_criteria), \
                (_what), (_result), ENOENT))

struct dict_object *ogs_diam_sh_application = NULL;
struct dict_object *ogs_diam_sh_cmd_udr = NULL;
struct dict_object *ogs_diam_sh_cmd_uda = NULL;
struct dict_object *ogs_diam_sh_user_identity = NULL;
struct dict_object *ogs_diam_sh_imsi = NULL;
struct dict_object *ogs_diam_sh_user_data = NULL;
struct dict_object *ogs_diam_sh_data_reference = NULL;
struct dict_object *ogs_diam_sh_requested_domain = NULL;
struct dict_object *ogs_diam_sh_current_location = NULL;
struct dict_object *ogs_diam_sh_udr_flags = NULL;
struct dict_object *ogs_diam_sh_requested_nodes = NULL;

extern int ogs_dict_sh_entry(char *conffile);

int ogs_diam_sh_init(void)
{
    application_id_t id = OGS_DIAM_SH_APPLICATION_ID;

    ogs_assert(ogs_dict_sh_entry(NULL) == 0);

    CHECK_dict_search(DICT_APPLICATION, APPLICATION_BY_ID,
            (void *)&id, &ogs_diam_sh_application);
    CHECK_dict_search(DICT_COMMAND, CMD_BY_NAME, "3GPP/User-Data-Request",
            &ogs_diam_sh_cmd_udr);
    CHECK_dict_search(DICT_COMMAND, CMD_BY_NAME, "3GPP/User-Data-Answer",
            &ogs_diam_sh_cmd_uda);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "User-Identity",
            &ogs_diam_sh_user_identity);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "IMSI",
            &ogs_diam_sh_imsi);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Sh-User-Data",
            &ogs_diam_sh_user_data);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Data-Reference",
            &ogs_diam_sh_data_reference);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Requested-Domain",
            &ogs_diam_sh_requested_domain);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Current-Location",
            &ogs_diam_sh_current_location);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "UDR-Flags",
            &ogs_diam_sh_udr_flags);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS, "Requested-Nodes",
            &ogs_diam_sh_requested_nodes);

    return 0;
}
