#include "util.h"
#include "wallet.h"
#include <sys/poll.h>
int peer_message(struct pollfd *pollfd, Wallet *wallet);
int connect_to_node(Peer *peer);
int send_balance_request(int fd, Wallet *wallet);
