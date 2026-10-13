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

#if !defined(OGS_DIAMETER_INSIDE) && !defined(OGS_DIAMETER_COMPILATION)
#error "This header cannot be included directly."
#endif

#ifndef OGS_DIAMETER_SH_MESSAGE_H
#define OGS_DIAMETER_SH_MESSAGE_H

#define OGS_DIAM_SH_APPLICATION_ID 16777217

extern struct dict_object *ogs_diam_sh_application;
extern struct dict_object *ogs_diam_sh_cmd_udr;
extern struct dict_object *ogs_diam_sh_cmd_uda;
extern struct dict_object *ogs_diam_sh_user_identity;
extern struct dict_object *ogs_diam_sh_imsi;
extern struct dict_object *ogs_diam_sh_user_data;
extern struct dict_object *ogs_diam_sh_data_reference;
extern struct dict_object *ogs_diam_sh_requested_domain;
extern struct dict_object *ogs_diam_sh_current_location;
extern struct dict_object *ogs_diam_sh_udr_flags;
extern struct dict_object *ogs_diam_sh_requested_nodes;

int ogs_diam_sh_init(void);

#endif /* OGS_DIAMETER_SH_MESSAGE_H */
