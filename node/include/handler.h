#include "node.h"
#include <stdint.h>
int handle_tx(uint8_t *payload, node_ctx *ctx);

int handle_handshake(unsigned char *buff, struct pollfd client_fd,
                     state *current_state);
