#ifndef LCSAP_PATH_H
#define LCSAP_PATH_H

#include "mme-context.h"
#include "mme-event.h"

#ifdef __cplusplus
extern "C" {
#endif

int lcsap_open(void);
void lcsap_close(void);
void lcsap_slg_init(void);
void lcsap_slg_final(void);

ogs_sock_t *lcsap_client(mme_esmlc_t *esmlc);
void lcsap_event_push(mme_event_t *e);
int lcsap_send(mme_esmlc_t *esmlc, ogs_pkbuf_t *pkbuf);
int lcsap_send_to_esmlc(ogs_pkbuf_t *pkbuf);

#ifdef __cplusplus
}
#endif

#endif /* LCSAP_PATH_H */