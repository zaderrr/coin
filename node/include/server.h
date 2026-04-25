#include "block.h"
#include "node.h"
#include <stdint.h>

PeerManager *init_pm();
int request_current_height(PeerManager *pm);
int request_missing_blocks(node_ctx *ctx);
int broadcast_message(unsigned char *buff, int length, PeerManager *pm);
int broadcast_tx(node_ctx *ctx, unsigned char *payload, int length);
int init_network(node_ctx *ctx, uint16_t port);
int listen_for_message(node_ctx *ctx);
int accept_connections(node_ctx *ctx);
