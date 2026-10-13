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

#if !defined(OGS_DIAMETER_INSIDE) && !defined(OGS_DIAMETER_COMPILATION)
#error "This header cannot be included directly."
#endif

#ifndef OGS_DIAM_SLG_MESSAGE_H
#define OGS_DIAM_SLG_MESSAGE_H

#ifdef __cplusplus
extern "C" {
#endif

#define OGS_DIAM_SLG_APPLICATION_ID 16777255
#define OGS_DIAM_SLG_CMD_CODE_PROVIDE_SUBSCRIBER_LOCATION 8388620
#define OGS_DIAM_SLG_AVP_CODE_SLG_LOCATION_TYPE 2500
#define OGS_DIAM_SLG_AVP_CODE_AGE_OF_LOCATION_ESTIMATE 2514

extern struct dict_object *ogs_diam_slg_application;
extern struct dict_object *ogs_diam_slg_cmd_psl;
extern struct dict_object *ogs_diam_slg_cmd_psl_answer;
extern struct dict_object *ogs_diam_slg_user_name;
extern struct dict_object *ogs_diam_slg_location_type;
extern struct dict_object *ogs_diam_slg_slg_location_type;
extern struct dict_object *ogs_diam_slg_client_type;
extern struct dict_object *ogs_diam_slg_location_estimate;
extern struct dict_object *ogs_diam_slg_age_of_location_estimate;

int ogs_diam_slg_init(void);

#ifdef __cplusplus
}
#endif

#endif /* OGS_DIAM_SLG_MESSAGE_H */
