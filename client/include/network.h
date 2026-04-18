#include "util.h"
#include "wallet.h"
#include <sys/poll.h>
int peer_message(struct pollfd *pollfd, Wallet *wallet);
int connect_to_node(Peer peer, unsigned char *public_key);
