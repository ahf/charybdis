
#include "stdinc.h"
#include "client.h"
#include "match.h"
#include "hostmask.h"
#include "send.h"
#include "numeric.h"
#include "ircd.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "s_serv.h"
#include "hash.h"
#include "s_conf.h"
#include "reject.h"

#include <stdio.h>

#define ONION_SPOOF "%d.user.onion"

static const char onion_desc[] = "Adds support for the Onion HAProxy circuit id feature";

static void mr_onion(struct MsgBuf *msgbuf_p, struct Client *, struct Client *, int, const char **);

struct Message onion_msgtab = {
	"PROXY", 0, 0, 0, 0,
	{{mr_onion, 4}, mg_reg, mg_ignore, mg_ignore, mg_ignore, mg_reg}
};

mapi_clist_av1 onion_clist[] = { &onion_msgtab, NULL };

DECLARE_MODULE_AV2(onion, NULL, NULL, onion_clist, NULL, NULL, NULL, NULL, onion_desc);

static void
mr_onion(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct sockaddr_in6 ipv6_address;
	uint8_t *raw_ipv6_address = NULL;
	uint32_t gid = 0;

	/* If the client have already sent USER that means the client is
	 * trying to send PROXY *after*, which should be impossible. */
	if (source_p->flags & FLAGS_SENTUSER)
		return;

	/* Same check but check if we have a NICK already. */
	if (source_p->name[0] != '\0')
		return;

	/* The client have already sent the PROXY command, now they are doing
	 * it again? Ignore it and use the first one. */
	if (source_p->flags & FLAGS_SENTONIONPROXY)
		return;

	/* Mark this client. */
	source_p->flags |= FLAGS_SENTONIONPROXY;

	/* The V6 address, which encodes the 32-bit GID is parv[2]. */
	if (rb_inet_pton_sock(parv[2], (struct sockaddr *)&ipv6_address) <= 0)
		return;

	raw_ipv6_address = ipv6_address.sin6_addr.s6_addr;
	gid = (raw_ipv6_address[12] << 24) + (raw_ipv6_address[13] << 16) + (raw_ipv6_address[14] << 8) + raw_ipv6_address[15];
	snprintf(source_p->host, sizeof(source_p->host), ONION_SPOOF, gid);
}
