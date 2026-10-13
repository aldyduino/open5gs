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

#include <freeDiameter/extension.h>

#define CHECK_dict_new(_type, _data, _parent, _ref) \
    CHECK_FCT(fd_dict_new(fd_g_config->cnf_dict, (_type), (_data), \
                (_parent), (_ref)))
#define CHECK_dict_search(_type, _criteria, _what, _result) \
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, (_type), (_criteria), \
                (_what), (_result), ENOENT))

struct local_rule {
    uint32_t vendor;
    const char *name;
    enum rule_position position;
    int min;
    int max;
};

#define PARSE_RULES(_rules, _parent) \
    do { \
        size_t i; \
        for (i = 0; i < sizeof(_rules) / sizeof((_rules)[0]); i++) { \
            struct dict_avp_request request = { \
                .avp_vendor = (_rules)[i].vendor, \
                .avp_name = (char *)(_rules)[i].name \
            }; \
            struct dict_rule_data rule = { NULL, (_rules)[i].position, 0, \
                (_rules)[i].min, (_rules)[i].max }; \
            CHECK_dict_search(DICT_AVP, AVP_BY_NAME_AND_VENDOR, \
                    &request, &rule.rule_avp); \
            CHECK_dict_new(DICT_RULE, &rule, (_parent), NULL); \
        } \
    } while (0)

static int sh_add_avp(uint32_t code, const char *name,
        enum dict_avp_basetype type, struct dict_object **avp)
{
    int ret;
    struct dict_object *existing = NULL;
    struct dict_avp_request request = {
        .avp_vendor = 10415,
        .avp_name = (char *)name
    };
    struct dict_avp_data existing_data;
    struct dict_avp_data data = {
        code, 10415, (char *)name,
        AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, AVP_FLAG_VENDOR, type
    };

    ret = fd_dict_search(fd_g_config->cnf_dict, DICT_AVP,
            AVP_BY_NAME_AND_VENDOR, &request, &existing, ENOENT);
    if (ret == 0) {
        ret = fd_dict_getval(existing, &existing_data);
        if (ret != 0)
            return ret;
        if (existing_data.avp_code != code ||
                existing_data.avp_vendor != 10415 ||
                existing_data.avp_basetype != type)
            return EINVAL;
        if (avp)
            *avp = existing;
        return 0;
    }
    if (ret != ENOENT)
        return ret;
    return fd_dict_new(fd_g_config->cnf_dict, DICT_AVP, &data, NULL, avp);
}

int ogs_dict_sh_entry(char *conffile)
{
    struct dict_object *vendor = NULL, *app = NULL, *avp = NULL;
    struct dict_application_data app_data = {
        16777217, "Sh"
    };

    (void)conffile;
    CHECK_dict_search(DICT_VENDOR, VENDOR_BY_NAME, "3GPP", &vendor);
    CHECK_dict_new(DICT_APPLICATION, &app_data, vendor, &app);

    CHECK_FCT(sh_add_avp(1, "IMSI", AVP_TYPE_OCTETSTRING, NULL));
    CHECK_FCT(sh_add_avp(700, "User-Identity", AVP_TYPE_GROUPED, &avp));
    {
        struct local_rule rules[] = {
            { 10415, "IMSI", RULE_OPTIONAL, -1, 1 },
            { 10415, "MSISDN", RULE_OPTIONAL, -1, 1 },
            { 10415, "Public-Identity", RULE_OPTIONAL, -1, 1 },
        };
        PARSE_RULES(rules, avp);
    }
    CHECK_FCT(sh_add_avp(702, "Sh-User-Data", AVP_TYPE_OCTETSTRING, NULL));
    CHECK_FCT(sh_add_avp(703, "Data-Reference", AVP_TYPE_UNSIGNED32, NULL));
    CHECK_FCT(sh_add_avp(706, "Requested-Domain", AVP_TYPE_UNSIGNED32, NULL));
    CHECK_FCT(sh_add_avp(707, "Current-Location", AVP_TYPE_UNSIGNED32, NULL));
    CHECK_FCT(sh_add_avp(719, "UDR-Flags", AVP_TYPE_UNSIGNED32, NULL));
    CHECK_FCT(sh_add_avp(722, "Requested-Nodes", AVP_TYPE_UNSIGNED32, NULL));

    {
        struct dict_cmd_data data = {
            306, "3GPP/User-Data-Request",
            CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE | CMD_FLAG_ERROR,
            CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE
        };
        struct local_rule rules[] = {
            { 0, "Session-Id", RULE_FIXED_HEAD, -1, 1 },
            { 0, "Vendor-Specific-Application-Id", RULE_REQUIRED, -1, 1 },
            { 0, "Auth-Session-State", RULE_REQUIRED, -1, 1 },
            { 0, "Origin-Host", RULE_REQUIRED, -1, 1 },
            { 0, "Origin-Realm", RULE_REQUIRED, -1, 1 },
            { 0, "Destination-Host", RULE_OPTIONAL, -1, 1 },
            { 0, "Destination-Realm", RULE_REQUIRED, -1, 1 },
            { 10415, "User-Identity", RULE_REQUIRED, -1, 1 },
            { 10415, "Data-Reference", RULE_REQUIRED, -1, -1 },
            { 10415, "Requested-Domain", RULE_OPTIONAL, -1, 1 },
            { 10415, "Current-Location", RULE_OPTIONAL, -1, 1 },
            { 10415, "UDR-Flags", RULE_OPTIONAL, -1, 1 },
            { 10415, "Requested-Nodes", RULE_OPTIONAL, -1, 1 },
            { 0, "Proxy-Info", RULE_OPTIONAL, -1, -1 },
            { 0, "Route-Record", RULE_OPTIONAL, -1, -1 },
        };
        CHECK_dict_new(DICT_COMMAND, &data, app, &avp);
        PARSE_RULES(rules, avp);
    }
    {
        struct dict_cmd_data data = {
            306, "3GPP/User-Data-Answer",
            CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE | CMD_FLAG_ERROR,
            CMD_FLAG_PROXIABLE
        };
        struct local_rule rules[] = {
            { 0, "Session-Id", RULE_FIXED_HEAD, -1, 1 },
            { 0, "Vendor-Specific-Application-Id", RULE_REQUIRED, -1, 1 },
            { 0, "Result-Code", RULE_OPTIONAL, -1, 1 },
            { 0, "Experimental-Result", RULE_OPTIONAL, -1, 1 },
            { 0, "Auth-Session-State", RULE_REQUIRED, -1, 1 },
            { 0, "Origin-Host", RULE_REQUIRED, -1, 1 },
            { 0, "Origin-Realm", RULE_REQUIRED, -1, 1 },
            { 10415, "Sh-User-Data", RULE_OPTIONAL, -1, 1 },
            { 0, "Failed-AVP", RULE_OPTIONAL, -1, -1 },
            { 0, "Proxy-Info", RULE_OPTIONAL, -1, -1 },
            { 0, "Route-Record", RULE_OPTIONAL, -1, -1 },
        };
        CHECK_dict_new(DICT_COMMAND, &data, app, &avp);
        PARSE_RULES(rules, avp);
    }

    return 0;
}
