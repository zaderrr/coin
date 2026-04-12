#include "node.h"
#include "block.h"
#include "ed25519.h"
#include "message.h"
#include "time.h"
#include <netinet/in.h>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_verify_64.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_CLIENTS 128

unsigned char *get_public_key(unsigned char *buff) {
  unsigned char *public_key;
  public_key = malloc(32);
  memcpy(public_key, buff, 32);
  return public_key;
}

unsigned char *handle_handshake(unsigned char *buff, struct pollfd client_fd,
                                state *current_state) {
  unsigned char *public_key = get_public_key(buff);
  unsigned char res[1024];
  // Write response + send
  write_header(INIT_BALANCE, sizeof(uint64_t), res);
  uint64_t balance = get_balance(public_key, current_state);
  balance = htonll(balance);
  // Write balance to response
  memcpy(res + 5, &balance, 8);
  send(client_fd.fd, res, 1024, 0);
  free(public_key);
  return 0;
}

struct pollfd start_server(uint16_t port) {
  int server_fd, new_socket;
  ssize_t valread;
  struct sockaddr_in address;
  int opt = 1;
  socklen_t addrlen = sizeof(address);
  struct pollfd *fds;
  fds = malloc(sizeof(struct pollfd) * MAX_CLIENTS + 1);
  int nfds = 0;

  // Creating socket file descriptor
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  // Forcefully attaching socket to the port 8080
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                 sizeof(opt))) {
    perror("setsockopt");
    exit(EXIT_FAILURE);
  }
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }
  if (listen(server_fd, 3) < 0) {
    perror("listen");
    exit(EXIT_FAILURE);
  }
  fds[0].fd = server_fd;
  fds[0].events = POLLIN;
  return fds[0];
}

int accept_connections(node_ctx *ctx) {
  struct pollfd *fds = ctx->peer_manager->fds;
  uint32_t *count = &ctx->peer_manager->peer_count;
  int ready = poll(fds, *count, 100);
  if (ready < 0) {
    perror("poll");
    return 1;
  }
  if (fds[0].revents & POLLIN) {
    int client_fd = accept(fds[0].fd, NULL, NULL);
    if (client_fd >= 0 && *count < MAX_CLIENTS + 1) {
      fds[*count].fd = client_fd;
      fds[*count].events = POLLIN;
      ctx->peer_manager->peers[*count] = (Peer){.peer_fd = client_fd};
      *count += 1;
      printf("new client: fd %d\n", client_fd);
    }
  }
  return 0;
}
// Read transaction from payload
transaction read_tx_from_buff(unsigned char *payload) {

  uint64_t amount_n = 0;
  uint64_t nonce_n = 0;

  // Acknowledged that this is very fragile
  transaction tx = {0};
  memcpy(&tx.type, payload, 1);
  memcpy(tx.from, payload + 1, 32);
  memcpy(tx.to, payload + 33, 32);
  memcpy(&amount_n, payload + 65, 8);
  memcpy(&nonce_n, payload + 73, 8);
  memcpy(tx.signature, payload + 81, 64);

  tx.amount = htonll(amount_n);
  tx.nonce = htonll(nonce_n);
  return tx;
}

int verify_transaction(unsigned char *payload, transaction *tx) {
  return ed25519_verify(tx->signature, payload, 81, tx->from);
}

int mempool_contains(mempool *pool, transaction *tx) {
  for (int i = 0; i < pool->tx_count; i++) {
    if (memcmp(pool->tx[i].signature, tx->signature, 64) == 0) {
      return 0;
    }
  }
  return 1;
}

int build_tx_message(transaction *tx, uint8_t *buff) {
  int offset = 0;
  unsigned char type_byte = (unsigned char)tx->type;
  tx->amount = htonll(tx->amount);
  tx->nonce = htonll(tx->nonce);
  memcpy(buff, &type_byte, 1);
  memcpy(buff + 1, tx->from, 32);
  memcpy(buff + 33, tx->to, 32);
  memcpy(buff + 65, &tx->amount, 8);
  memcpy(buff + 73, &tx->nonce, 8);
  memcpy(buff + 81, tx->signature, 64);
  return 0;
}

int broadcast_tx(node_ctx *ctx, transaction *tx) {
  // This is where we tell our friends about the new transaction
  // Type, From, To, Amount, Nonce, Signature
  size_t size = 1 + 32 + 32 + 8 + 8 + 64;
  uint8_t buff[size];
  build_tx_message(tx, buff);
  uint8_t msg[size + 5];
  write_header(TX_SUBMIT, size, msg);
  memcpy(msg + 5, buff, size);
  PeerManager *pm = ctx->peer_manager;
  for (int i = 0; i < pm->peer_count; i++) {
    if (i == 0)
      continue;
    send(pm->peers[i].peer_fd, msg, size + 5, 0);
  }
  return 0;
}

int validate_tx(transaction *tx, node_ctx *ctx) {
  account *account = get_account(ctx->current_state, tx->from);
  if (account == NULL) {
    printf("Account is null :( no balance\n");
    return 1;
  }
  // Check account can withdraw (validator)
  if (tx->type == TX_STAKE_WITHDRAW) {
    validator *validator = get_validator(ctx->current_state, tx->from);
    if (validator == NULL) {
      return 1;
    }

    if (can_wirthdraw_stake(account, validator, tx, ctx->current_state) == 1) {
      return 1;
    }

  } else if (tx->type == TX_TRANSFER) {
    // Validate transfer, balance + nonce
    if (validate_funds(account, ctx->current_state, tx) == 1) {
      return 1;
    }
  }
  return 0;
}

int handle_tx(unsigned char *payload, node_ctx *ctx) {
  transaction tx = read_tx_from_buff(payload);
  // TODO: Add validation for received data...
  if (verify_transaction(payload, &tx) != 1) {
    printf("Invalid signature.\n");
    return 1;
  }
  if (ctx->mempool->tx_count >= ctx->mempool->capacity) {
    printf("Mempool full\n");
    return 1;
  }
  // Check we don't already have this transaction
  if (mempool_contains(ctx->mempool, &tx) == 0) {
    printf("We already have this tx...\n");
    return 1;
  }
  if (validate_tx(&tx, ctx) == 1) {
    return 1;
  }
  int mempool_count = ctx->mempool->tx_count;
  ctx->mempool->tx[mempool_count] = tx;
  ctx->mempool->tx_count++;
  broadcast_tx(ctx, &tx);
  return 0;
}

int handle_decoded(Message *message, struct pollfd client_fd, node_ctx ctx) {
  switch (message->header->type) {
  case HANDSHAKE: {
    handle_handshake(message->payload, client_fd, ctx.current_state);
    break;
  }
  case TX_SUBMIT: {
    handle_tx(message->payload, &ctx);
    break;
  }
  case PING: {
    printf("Ping received");
  }
  default: {
    break;
  }
  }
  return 0;
}

int listen_for_message(node_ctx *ctx) {
  PeerManager *pm = ctx->peer_manager;
  uint32_t *count = &pm->peer_count;
  for (int i = 1; i < *count; i++) {
    if (!(pm->fds[i].revents & POLLIN))
      continue;
    unsigned char buf[4096];
    ssize_t n = recv(pm->fds[i].fd, buf, sizeof(buf), 0);
    if (n <= 0) {
      pm->peers[i] = pm->peers[*count - 1];
      close(pm->fds[i].fd);
      pm->fds[i] = pm->fds[*count - 1];
      *count -= 1;
      i--;

    } else {
      Message *message;
      decode_message(buf, &message);
      handle_decoded(message, pm->fds[i], *ctx);
      free(message->payload);
      free(message->header);
      free(message);
    }
  }
  return 0;
}

int read_friends(char *file_location, char *friends) {
  FILE *fptr;
  fptr = fopen(file_location, "r+");
  if (fptr == NULL) {
    printf("Couldn't open friend list");
    return 1;
  }
  char buff[128];
  fgets(buff, 128, fptr);
  printf("%s", buff);
  return 0;
}
int get_local_blocks() {
  FILE *fptr;
  fptr = fopen("blocks.bin", "r+");
  if (fptr == NULL) {
    printf("No local blocks");
    return 1;
  }
  char buff[128];
  fgets(buff, 128, fptr);
  printf("%s", buff);
  return 0;
}

unsigned char *build_tx_leaf(transaction *tx) {
  // From, To, Nonce, type
  size_t leaf_size = 32 + 32 + 8 + 1;

  unsigned char type_byte = (unsigned char)tx->type;
  unsigned char *leaf = malloc(leaf_size);
  memcpy(leaf, tx->from, 32);
  memcpy(leaf + 32, tx->to, 32);
  memcpy(leaf + 64, &tx->nonce, 8);
  memcpy(leaf + 72, &type_byte, 1);

  return leaf;
}

int build_root(unsigned char *root, mempool *mempool) {
  size_t leaf_size = 32 + 32 + 8 + 1;
  unsigned char **leafs = malloc(sizeof(unsigned char *) * mempool->tx_count);
  for (int i = 0; i < mempool->tx_count; i++) {
    leafs[i] = build_tx_leaf(&mempool->tx[i]);
  }
  compute_merkle_root(leafs, mempool->tx_count, root, leaf_size);
  for (int i = 0; i < mempool->tx_count; i++) {
    free(leafs[i]);
  }
  free(leafs);
  return 0;
}

int build_root_hash(unsigned char *item, unsigned char *out_buf, int count) {
  unsigned char **leaves = malloc(sizeof(char *) * count);

  for (int i = 0; i < count; i++) {
    leaves[i] = state_to_leaf(&item[i]);
  }

  size_t leaf_size = 32 + 8 + 8;
  compute_merkle_root(leaves, count, out_buf, leaf_size);

  free_leaves(leaves, count);

  return 0;
}

// Creates new account with the new balance
int create_new_account(state *current_state, transaction *tx) {
  current_state->accounts_count++;
  int count = current_state->accounts_count;
  account *new_accounts =
      realloc(current_state->accounts, sizeof(account) * count);

  account new = {0};
  new.nonce = 0;
  memcpy(new.public_key, tx->to, 32);

  if (new_accounts == NULL) {
    printf("Failed to add account\n");
    return 1;
  }

  current_state->accounts = new_accounts;
  current_state->accounts[current_state->accounts_count - 1] = new;
  return 0;
}

int update_state(state *current_state, transaction *tx) {
  if (tx->type == TX_TRANSFER) {
    account *from = get_account(current_state, tx->from);
    account *to = get_account(current_state, tx->to);
    if (to == NULL) {
      if (create_new_account(current_state, tx) == 1) {
        return 1;
      }
      // Creating account, reallocates memory - Have to get pointers again
      from = get_account(current_state, tx->from);
      to = get_account(current_state, tx->to);
    }
    to->balance += tx->amount;
    from->balance -= tx->amount;
    from->nonce++;
  }
  return 0;
}

block build_next_block(block *previous_block, node_ctx *ctx) {
  unsigned char prev_hash[32];
  hash_block(previous_block, prev_hash);
  block next_block = {0};
  next_block.height = previous_block->height + 1;
  next_block.tx_count = ctx->mempool->tx_count;
  next_block.transactions = ctx->mempool->tx;
  next_block.timestamp = (uint64_t)time(NULL);

  memcpy(next_block.proposer, ctx->wallet->public_key, 32);
  memcpy(next_block.prev_hash, prev_hash, 32);

  transaction *block_tx = malloc(sizeof(transaction) * ctx->mempool->tx_count);
  int tx_count = 0;
  for (int i = 0; i < ctx->mempool->tx_count; i++) {
    transaction tx = ctx->mempool->tx[i];
    if (validate_tx(&tx, ctx) == 0) {
      block_tx[tx_count] = tx;
      tx_count++;
      update_state(ctx->current_state, &tx);
    }
  }
  next_block.transactions = block_tx;
  unsigned char root[32];
  build_root(root, ctx->mempool);
  memcpy(next_block.tx_root, root, 32);

  unsigned char account_merkle[32];
  unsigned char val_merkle[32];
  build_root_hash((unsigned char *)ctx->current_state->accounts, account_merkle,
                  ctx->current_state->accounts_count);
  build_root_hash((unsigned char *)ctx->current_state->validators, val_merkle,
                  ctx->current_state->validators_count);
  memcpy(next_block.state_root, account_merkle, 32);
  memcpy(next_block.validator_root, val_merkle, 32);
  ctx->mempool->tx_count = 0;
  free(previous_block->transactions);
  return next_block;
}
