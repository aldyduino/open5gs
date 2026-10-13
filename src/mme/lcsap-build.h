#ifndef LCSAP_BUILD_H
#define LCSAP_BUILD_H

#include "ogs-core.h"

#include "LCSAP_Payload-Type.h"

#ifdef __cplusplus
extern "C" {
#endif

ogs_pkbuf_t *lcsap_build_connection_oriented_information(
        LCSAP_Payload_Type_t payload_type,
        const uint8_t correlation_id[4],
        const uint8_t *payload, size_t payload_len);

#ifdef __cplusplus
}
#endif

#endif /* LCSAP_BUILD_H */