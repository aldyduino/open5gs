#include "ogs-sctp.h"

#include "mme-event.h"
#include "mme-sm.h"

#include "lcsap-path.h"

int lcsap_open(void)
{
    mme_esmlc_t *esmlc = NULL;
    int rv;

    lcsap_slg_init();

    ogs_list_for_each(&mme_self()->esmlc_list, esmlc) {
        mme_event_t e;

        memset(&e, 0, sizeof(e));
        e.esmlc = esmlc;
        ogs_fsm_init(&esmlc->sm, lcsap_state_initial,
                lcsap_state_final, &e);
    }

    rv = lcsap_server_open();
    if (rv != OGS_OK) {
        lcsap_server_close();
        return rv;
    }

    return OGS_OK;
}

void lcsap_close(void)
{
    mme_esmlc_t *esmlc = NULL;

    lcsap_server_close();

    ogs_list_for_each(&mme_self()->esmlc_list, esmlc) {
        mme_event_t e;

        memset(&e, 0, sizeof(e));
        e.esmlc = esmlc;
        ogs_fsm_fini(&esmlc->sm, &e);
    }

    lcsap_slg_final();
}

int lcsap_send(mme_esmlc_t *esmlc, ogs_pkbuf_t *pkbuf)
{
    int sent;

    ogs_assert(esmlc);
    ogs_assert(pkbuf);

    if (!esmlc->sock) {
        ogs_error("LCS-AP E-SMLC is not connected");
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }

    sent = ogs_sctp_sendmsg(esmlc->sock, pkbuf->data, pkbuf->len,
            NULL, OGS_SCTP_LCSAP_PPID, 0);
    if (sent < 0 || sent != pkbuf->len) {
        ogs_error("LCS-AP SCTP send failed (%d:%s)", errno, strerror(errno));
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }

    ogs_pkbuf_free(pkbuf);
    return OGS_OK;
}

int lcsap_send_to_esmlc(ogs_pkbuf_t *pkbuf)
{
    mme_esmlc_t *esmlc = NULL;

    ogs_assert(pkbuf);

    ogs_list_for_each(&mme_self()->esmlc_list, esmlc) {
        if (esmlc->sock)
            return lcsap_send(esmlc, pkbuf);
    }

    ogs_warn("No connected E-SMLC for LCS-AP message");
    ogs_pkbuf_free(pkbuf);
    return OGS_NOTFOUND;
}

void lcsap_event_push(mme_event_t *e)
{
    int rv;

    ogs_assert(e);

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        if (e->pkbuf)
            ogs_pkbuf_free(e->pkbuf);
        if (e->id == MME_EVENT_LCSAP_SERVER_ACCEPT && e->sock)
            ogs_sctp_destroy(e->sock);
        mme_event_free(e);
        return;
    }
#if HAVE_USRSCTP
    ogs_pollset_notify(ogs_app()->pollset);
#endif
}