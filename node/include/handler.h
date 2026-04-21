#include "message.h"
#include "node.h"
#include <stdint.h>
int handle_tx(unsigned char *payload, node_ctx *ctx);
int handle_block_proposal(unsigned char *buff, node_ctx *ctx, int length);
int handle_handshake(unsigned char *buff, struct pollfd client_fd,
                     state *current_state);

int handle_blocks_received(Message *message, node_ctx *ctx);
int handle_height_response(Message *message, node_ctx *ctx);
int handle_get_height(Message *message, node_ctx *ctx, int fd);
int handle_get_blocks(Message *message, node_ctx *ctx, int fd);
int handle_block_received(Message *message);
int handle_get_block(Message *message, node_ctx *ctx, int fd);
