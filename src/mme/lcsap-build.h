#ifndef LCSAP_BUILD_H
#define LCSAP_BUILD_H

#include "ogs-core.h"

#include "LCSAP_Payload-Type.h"
#include "LCSAP_Location-Type.h"

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
        long client_type);

#ifdef __cplusplus
}
#endif

#endif /* LCSAP_BUILD_H */