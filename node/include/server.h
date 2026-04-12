#include "block.h"
#include "node.h"
#include <stdint.h>

PeerManager *init_pm();
int broadcast_tx(node_ctx *ctx, transaction *tx);
int init_network(node_ctx *ctx, uint16_t port);
int listen_for_message(node_ctx *ctx);
int accept_connections(node_ctx *ctx);
