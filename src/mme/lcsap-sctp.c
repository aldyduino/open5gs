#include "ogs-sctp.h"

#include "mme-event.h"

#include "lcsap-path.h"

#if HAVE_USRSCTP
static void usrsctp_recv_handler(struct socket *socket, void *data, int flags);
#else
static void lksctp_recv_handler(short when, ogs_socket_t fd, void *data);
#endif

static void recv_handler(ogs_sock_t *sock);

ogs_sock_t *lcsap_client(mme_esmlc_t *esmlc)
{
    ogs_sock_t *sock = NULL;

    ogs_assert(esmlc);

    sock = ogs_sctp_client(SOCK_STREAM, esmlc->sa_list,
            esmlc->local_sa_list, esmlc->option);
    if (!sock)
        return NULL;

    esmlc->sock = sock;
#if HAVE_USRSCTP
    usrsctp_set_non_blocking((struct socket *)sock, 1);
    usrsctp_set_upcall((struct socket *)sock, usrsctp_recv_handler, NULL);
#else
    esmlc->poll = ogs_pollset_add(ogs_app()->pollset,
            OGS_POLLIN, sock->fd, lksctp_recv_handler, sock);
    ogs_assert(esmlc->poll);
#endif

    ogs_info("LCS-AP client %s",
            ogs_sockaddr_to_string_static(esmlc->sa_list));
    return sock;
}

#if HAVE_USRSCTP
static void usrsctp_recv_handler(struct socket *socket, void *data, int flags)
{
    int events;

    while ((events = usrsctp_get_events(socket)) &&
           (events & SCTP_EVENT_READ))
        recv_handler((ogs_sock_t *)socket);
}
#else
static void lksctp_recv_handler(short when, ogs_socket_t fd, void *data)
{
    ogs_sock_t *sock = data;

    ogs_assert(fd != INVALID_SOCKET);
    ogs_assert(sock);
    recv_handler(sock);
}
#endif

static void push_sctp_event(mme_event_e id, ogs_sock_t *sock,
        ogs_pkbuf_t *pkbuf, uint16_t inbound, uint16_t outbound)
{
    mme_event_t *e = mme_event_new(id);

    e->sock = sock;
    e->pkbuf = pkbuf;
    e->max_num_of_istreams = inbound;
    e->max_num_of_ostreams = outbound;
    lcsap_event_push(e);
}

static void recv_handler(ogs_sock_t *sock)
{
    ogs_pkbuf_t *pkbuf = NULL;
    int size;
    ogs_sctp_info_t sinfo;
    int flags = 0;

    ogs_assert(sock);

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_assert(pkbuf);
    ogs_pkbuf_put(pkbuf, OGS_MAX_SDU_LEN);
    size = ogs_sctp_recvmsg(sock, pkbuf->data, pkbuf->len,
            NULL, &sinfo, &flags);
    if (size < 0 || size >= OGS_MAX_SDU_LEN) {
        ogs_error("ogs_sctp_recvmsg() failed (%d:%s)",
                errno, strerror(errno));
        ogs_pkbuf_free(pkbuf);
        return;
    }

    if (flags & MSG_NOTIFICATION) {
        union sctp_notification *notification =
            (union sctp_notification *)pkbuf->data;

        if (notification->sn_header.sn_type == SCTP_ASSOC_CHANGE) {
            if (notification->sn_assoc_change.sac_state == SCTP_COMM_UP) {
                push_sctp_event(MME_EVENT_LCSAP_LO_SCTP_COMM_UP,
                        sock, NULL,
                        notification->sn_assoc_change.sac_inbound_streams,
                        notification->sn_assoc_change.sac_outbound_streams);
            } else if (notification->sn_assoc_change.sac_state ==
                        SCTP_COMM_LOST ||
                    notification->sn_assoc_change.sac_state ==
                        SCTP_SHUTDOWN_COMP) {
                push_sctp_event(MME_EVENT_LCSAP_LO_CONNREFUSED,
                        sock, NULL, 0, 0);
            }
        } else if (notification->sn_header.sn_type == SCTP_SHUTDOWN_EVENT ||
                notification->sn_header.sn_type == SCTP_SEND_FAILED) {
            push_sctp_event(MME_EVENT_LCSAP_LO_CONNREFUSED,
                    sock, NULL, 0, 0);
        }
    } else if (flags & MSG_EOR) {
        ogs_pkbuf_trim(pkbuf, size);
        push_sctp_event(MME_EVENT_LCSAP_MESSAGE, sock, pkbuf, 0, 0);
        return;
    } else {
        ogs_error("Incomplete LCS-AP SCTP message (%d:%s)",
                errno, strerror(errno));
    }

    ogs_pkbuf_free(pkbuf);
}