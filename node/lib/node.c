#include "node.h"
#include "block.h"
#include "ed25519.h"
#include "message.h"
#include <netinet/in.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_verify_64.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PORT 8080
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
  write_header(INIT_BALANCE, sizeof(int), res);
  int balance = get_balance(public_key, current_state);
  balance = htonl(balance);
  // Write balance to response
  memcpy(res + 5, &balance, 4);
  send(client_fd.fd, res, 1024, 0);
  free(public_key);
  return 0;
}

struct pollfd *start_server() {
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
  address.sin_port = htons(PORT);

  // Forcefully attaching socket to the port 8080
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
  nfds = 1;
  return fds;
}

int accept_connections(struct pollfd *fds, int *nfds) {
  int ready = poll(fds, *nfds, -1);
  if (ready < 0) {
    perror("poll");
    return 1;
  }
  if (fds[0].revents & POLLIN) {
    int client_fd = accept(fds[0].fd, NULL, NULL);
    if (client_fd >= 0 && *nfds < MAX_CLIENTS + 1) {
      fds[*nfds].fd = client_fd;
      fds[*nfds].events = POLLIN;
      *nfds += 1;
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

int broadcast_tx(node_ctx ctx, transaction tx) {
  // This is where we tell our friends about the new transaction
}

int handle_tx(unsigned char *payload, struct pollfd client_fd, node_ctx *ctx) {
  transaction tx = read_tx_from_buff(payload);
  if (verify_transaction(payload, &tx) != 1) {
    printf("Invalid signature.\n");
    return 1;
  }
  // Account validation...

  if (ctx->mempool->tx_count >= ctx->mempool->capacity) {
    printf("Mempool full\n");
    return 1;
  }
  // Check we don't already have this transaction
  if (mempool_contains(ctx->mempool, &tx) == 0) {
    printf("We already have this tx...\n");
    return 1;
  }
  account *account = get_account(ctx->current_state, tx.from);
  if (account == NULL) {
    return 1;
  }
  // Check account can withdraw (validator)
  if (tx.type == TX_STAKE_WITHDRAW) {
    validator *validator = get_validator(ctx->current_state, tx.from);
    if (validator == NULL) {
      return 1;
    }

    if (can_wirthdraw_stake(account, validator, &tx, ctx->current_state) == 1) {
      return 1;
    }
    printf("Valid stake withdrawl!");

  } else if (tx.type == TX_TRANSFER) {
    // Validate transfer, balance + nonce
    if (validate_funds(account, ctx->current_state, &tx) == 1) {
      return 1;
    }
  }
  int mempool_count = ctx->mempool->tx_count;
  ctx->mempool->tx[mempool_count] = tx;
  // TODO: Broadcast
  return 0;
}

int handle_decoded(Message *message, struct pollfd client_fd, node_ctx ctx) {
  switch (message->header->type) {
  case HANDSHAKE: {
    handle_handshake(message->payload, client_fd, ctx.current_state);
    break;
  }
  case TX_SUBMIT: {
    handle_tx(message->payload, client_fd, &ctx);
    break;
  }
  default: {
    break;
  }
  }
  return 0;
}

int listen_for_message(struct pollfd *fds, int *nfds, node_ctx ctx) {
  for (int i = 1; i < *nfds; i++) {
    if (!(fds[i].revents & POLLIN))
      continue;
    unsigned char buf[4096];
    ssize_t n = recv(fds[i].fd, buf, sizeof(buf), 0);
    if (n <= 0) {
      close(fds[i].fd);
      fds[i] = fds[*nfds - 1];
      *nfds -= 1;
      i--;
    } else {
      Message *message;
      decode_message(buf, &message);
      handle_decoded(message, fds[i], ctx);
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

int decrypt_wallet(FILE *fptr, unsigned char *private_key, char *password) {
  // Nonce = 24, Salt = 16, MAC = 16, Message = 32 + 64, + 2 commas + 2 space
  // Salt -> Nonce -> Cipher
  unsigned char salt[16];
  unsigned char nonce[24];
  unsigned char cipher[112]; // 32 + 64

  fread(salt, 1, sizeof(salt), fptr);
  fread(nonce, 1, sizeof(nonce), fptr);
  fread(cipher, 1, sizeof(cipher), fptr);
  unsigned char key[crypto_secretbox_KEYBYTES];
  if (crypto_pwhash(key, sizeof key, password, strlen(password), salt,
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_DEFAULT) != 0) {
    printf("Key derivation failed\n");
    return 1;
  }
  int ciphertext_len = sizeof(cipher);
  unsigned long long decrypted_len = ciphertext_len - crypto_secretbox_MACBYTES;
  unsigned char *decrypted = malloc(decrypted_len);

  if (crypto_secretbox_open_easy(decrypted, cipher, ciphertext_len, nonce,
                                 key) != 0) {
    printf("Wrong password or tampered data\n");
    return 1;
  }
  private_key = malloc(64);

  memcpy(private_key, &decrypted[32], 64);
  return 0;
}
