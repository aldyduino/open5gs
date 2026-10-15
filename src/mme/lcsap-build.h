#ifndef LCSAP_BUILD_H
#define LCSAP_BUILD_H

#include "ogs-core.h"

#include "LCSAP_Payload-Type.h"
#include "LCSAP_Location-Type.h"

typedef struct lcsap_location_request_options_s {
    bool imei_present;
    uint8_t imei[8];
    bool lcs_priority_present;
    uint8_t lcs_priority;
    bool lcs_qos_present;
    bool horizontal_accuracy_present;
    long horizontal_accuracy;
    bool vertical_requested_present;
    long vertical_requested;
    bool vertical_accuracy_present;
    long vertical_accuracy;
    bool response_time_present;
    long response_time;
    bool include_velocity_present;
    long include_velocity;
    bool lcs_service_type_id_present;
    long lcs_service_type_id;
} lcsap_location_request_options_t;

#ifdef __cplusplus
extern "C" {
#endif

ogs_pkbuf_t *lcsap_build_connection_oriented_information(
        LCSAP_Payload_Type_t payload_type,
        const uint8_t correlation_id[4],
        const uint8_t *payload, size_t payload_len);
ogs_pkbuf_t *lcsap_build_location_request(uint32_t correlation_id,
        LCSAP_Location_Type_t location_type, const uint8_t *imsi,
        size_t imsi_len, const uint8_t plmn_id[3], uint32_t cell_id,
        long client_type, const lcsap_location_request_options_t *options);

#ifdef __cplusplus
}
#endif

#endif /* LCSAP_BUILD_H */