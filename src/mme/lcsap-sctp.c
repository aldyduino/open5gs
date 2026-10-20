#include "ogs-sctp.h"

#include "mme-event.h"

#include "lcsap-path.h"

#if HAVE_USRSCTP
static void usrsctp_recv_handler(struct socket *socket, void *data, int flags);
static void usrsctp_server_recv_handler(
        struct socket *socket, void *data, int flags);
#else
static void lksctp_recv_handler(short when, ogs_socket_t fd, void *data);
static void lksctp_accept_handler(short when, ogs_socket_t fd, void *data);
static void lksctp_peer_handler(short when, ogs_socket_t fd, void *data);
#endif

static void recv_handler(ogs_sock_t *sock, bool server);

#if !HAVE_USRSCTP
typedef struct lcsap_peer_s {
    ogs_lnode_t lnode;
    ogs_sock_t *sock;
    ogs_poll_t *poll;
    bool close_pending;
} lcsap_peer_t;

static ogs_list_t peer_list;
#endif

ogs_sock_t *lcsap_client(mme_esmlc_t *esmlc)
{
    ogs_sock_t *sock = NULL;

    ogs_assert(esmlc);

    sock = ogs_sctp_client(SOCK_STREAM, esmlc->sa_list,
            esmlc->local_sa_list, esmlc->option, true);
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
        recv_handler((ogs_sock_t *)socket, false);
}
#else
static void lksctp_recv_handler(short when, ogs_socket_t fd, void *data)
{
    ogs_sock_t *sock = data;

    ogs_assert(fd != INVALID_SOCKET);
    ogs_assert(sock);
    recv_handler(sock, false);
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

static void push_server_close_event(ogs_sock_t *sock)
{
#if !HAVE_USRSCTP
    lcsap_peer_t *peer = NULL;
    bool found = false;

    ogs_list_for_each(&peer_list, peer) {
        if (peer->sock == sock) {
            if (peer->close_pending)
                return;
            peer->close_pending = true;
            found = true;
            break;
        }
    }
    if (!found)
        return;

    {
        mme_event_t *e = mme_event_new(MME_EVENT_LCSAP_SERVER_CLOSE);
        e->sock = sock;
        lcsap_event_push(e);
    }
#else
    ogs_assert(sock);
#endif
}

static void recv_handler(ogs_sock_t *sock, bool server)
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
    if (server && size == 0) {
        ogs_pkbuf_free(pkbuf);
        push_server_close_event(sock);
        return;
    }
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
            if (!server &&
                notification->sn_assoc_change.sac_state == SCTP_COMM_UP) {
                push_sctp_event(MME_EVENT_LCSAP_LO_SCTP_COMM_UP,
                        sock, NULL,
                        notification->sn_assoc_change.sac_inbound_streams,
                        notification->sn_assoc_change.sac_outbound_streams);
            } else if (!server &&
                    (notification->sn_assoc_change.sac_state ==
                        SCTP_COMM_LOST ||
                    notification->sn_assoc_change.sac_state ==
                        SCTP_SHUTDOWN_COMP)) {
                push_sctp_event(MME_EVENT_LCSAP_LO_CONNREFUSED,
                        sock, NULL, 0, 0);
#if !HAVE_USRSCTP
            } else if (server &&
                    (notification->sn_assoc_change.sac_state ==
                        SCTP_COMM_LOST ||
                    notification->sn_assoc_change.sac_state ==
                        SCTP_SHUTDOWN_COMP)) {
                push_server_close_event(sock);
#endif
            }
        } else if (notification->sn_header.sn_type == SCTP_SHUTDOWN_EVENT ||
                (!server &&
                 notification->sn_header.sn_type == SCTP_SEND_FAILED)) {
            if (!server)
                push_sctp_event(MME_EVENT_LCSAP_LO_CONNREFUSED,
                        sock, NULL, 0, 0);
#if !HAVE_USRSCTP
            else {
                push_server_close_event(sock);
            }
#endif
        }
    } else if (flags & MSG_EOR) {
        ogs_pkbuf_trim(pkbuf, size);
        push_sctp_event(server ? MME_EVENT_LCSAP_SERVER_MESSAGE :
                MME_EVENT_LCSAP_MESSAGE, sock, pkbuf, 0, 0);
        return;
    } else {
        ogs_error("Incomplete LCS-AP SCTP message (%d:%s)",
                errno, strerror(errno));
    }

    ogs_pkbuf_free(pkbuf);
}

static ogs_sock_t *server_socket(ogs_socknode_t *node)
{
    ogs_sock_t *sock = NULL;
#if !HAVE_USRSCTP
    ogs_poll_t *poll = NULL;
#endif

    ogs_assert(node);
#if HAVE_USRSCTP
    sock = ogs_sctp_server(SOCK_SEQPACKET, node->addr, node->option);
    if (sock) {
        usrsctp_set_non_blocking((struct socket *)sock, 1);
        usrsctp_set_upcall((struct socket *)sock,
                usrsctp_server_recv_handler, NULL);
    }
#else
    sock = ogs_sctp_server(SOCK_STREAM, node->addr, node->option);
    if (sock) {
        poll = ogs_pollset_add(ogs_app()->pollset,
                OGS_POLLIN, sock->fd, lksctp_accept_handler, sock);
        ogs_assert(poll);
        node->poll = poll;
    }
#endif

    if (sock) {
        node->sock = sock;
        node->cleanup = ogs_sctp_destroy;
        ogs_info("LCS-AP server %s",
                ogs_sockaddr_to_string_static(node->addr));
    }
    return sock;
}

int lcsap_server_open(void)
{
    ogs_socknode_t *node = NULL;

#if !HAVE_USRSCTP
    ogs_list_init(&peer_list);
#endif
    ogs_list_for_each(&mme_self()->lcsap_list, node)
        if (!server_socket(node))
            return OGS_ERROR;
    ogs_list_for_each(&mme_self()->lcsap_list6, node)
        if (!server_socket(node))
            return OGS_ERROR;
    return OGS_OK;
}

void lcsap_server_close(void)
{
#if !HAVE_USRSCTP
    lcsap_peer_t *peer = NULL, *next = NULL;
    ogs_list_for_each_safe(&peer_list, next, peer) {
        ogs_list_remove(&peer_list, peer);
        if (peer->poll)
            ogs_pollset_remove(peer->poll);
        if (peer->sock)
            ogs_sctp_destroy(peer->sock);
        ogs_free(peer);
    }
#endif
    ogs_socknode_remove_all(&mme_self()->lcsap_list);
    ogs_socknode_remove_all(&mme_self()->lcsap_list6);
}

int lcsap_server_add_peer(ogs_sock_t *sock)
{
#if HAVE_USRSCTP
    ogs_assert(sock);
    return OGS_OK;
#else
    lcsap_peer_t *peer = NULL;
    ogs_assert(sock);
    peer = ogs_calloc(1, sizeof(*peer));
    ogs_assert(peer);
    peer->sock = sock;
    peer->poll = ogs_pollset_add(ogs_app()->pollset,
            OGS_POLLIN, sock->fd, lksctp_peer_handler, sock);
    if (!peer->poll) {
        ogs_free(peer);
        return OGS_ERROR;
    }
    ogs_list_add(&peer_list, peer);
    ogs_info("LCS-AP accepted peer %s",
            ogs_sockaddr_to_string_static(&sock->remote_addr));
    return OGS_OK;
#endif
}

void lcsap_server_remove_peer(ogs_sock_t *sock)
{
#if !HAVE_USRSCTP
    lcsap_peer_t *peer = NULL;

    ogs_assert(sock);
    ogs_list_for_each(&peer_list, peer) {
        if (peer->sock == sock) {
            ogs_list_remove(&peer_list, peer);
            if (peer->poll)
                ogs_pollset_remove(peer->poll);
            ogs_sctp_destroy(peer->sock);
            ogs_free(peer);
            return;
        }
    }
#else
    ogs_assert(sock);
#endif
}

int lcsap_server_send(ogs_pkbuf_t *pkbuf)
{
    ogs_assert(pkbuf);
#if !HAVE_USRSCTP
    lcsap_peer_t *peer = NULL;

    ogs_list_for_each(&peer_list, peer) {
        int sent = ogs_sctp_sendmsg(peer->sock,
                pkbuf->data, pkbuf->len, NULL, OGS_SCTP_LCSAP_PPID, 0);
        if (sent == (int)pkbuf->len) {
            ogs_pkbuf_free(pkbuf);
            return OGS_OK;
        }
        ogs_error("LCS-AP SCTP server send failed (%d:%s)",
                errno, strerror(errno));
    }
#endif
    ogs_warn("No connected LCS-AP server peer");
    ogs_pkbuf_free(pkbuf);
    return OGS_NOTFOUND;
}

#if HAVE_USRSCTP
static void usrsctp_server_recv_handler(struct socket *socket,
        void *data, int flags)
{
    int events;

    while ((events = usrsctp_get_events(socket)) &&
           (events & SCTP_EVENT_READ))
        recv_handler((ogs_sock_t *)socket, true);
}
#else
static void lksctp_accept_handler(short when, ogs_socket_t fd, void *data)
{
    ogs_sock_t *listener = data;
    ogs_sock_t *sock = NULL;
    mme_event_t *e = NULL;

    ogs_assert(fd != INVALID_SOCKET);
    ogs_assert(listener);
    sock = ogs_sock_accept(listener);
    if (!sock) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "LCS-AP accept() failed");
        return;
    }
    e = mme_event_new(MME_EVENT_LCSAP_SERVER_ACCEPT);
    e->sock = sock;
    lcsap_event_push(e);
}

static void lksctp_peer_handler(short when, ogs_socket_t fd, void *data)
{
    ogs_sock_t *sock = data;
    ogs_assert(fd != INVALID_SOCKET);
    ogs_assert(sock);
    recv_handler(sock, true);
}
#endif