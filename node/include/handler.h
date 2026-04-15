#include "node.h"
#include <stdint.h>
int handle_tx(unsigned char *payload, node_ctx *ctx);
int handle_block_proposal(unsigned char *buff, node_ctx *ctx, int length);
int handle_handshake(unsigned char *buff, struct pollfd client_fd,
                     state *current_state);
