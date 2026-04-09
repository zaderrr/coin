#include "block.h"
#include "message.h"
#include "sodium.h"
#include <netinet/in.h>
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
  memcpy(public_key, buff + 5, 32);
  return public_key;
}

unsigned char *handle_handshake(unsigned char *buff, struct pollfd client_fd) {
  unsigned char *public_key = get_public_key(buff);
  unsigned char res[1024];
  // Write response + send
  write_header(INIT_BALANCE, sizeof(int), res);
  int balance = 100;
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

int handle_decoded(Message *message, struct pollfd client_fd) {
  switch (message->header->type) {
  case HANDSHAKE: {
    handle_handshake(message->payload, client_fd);
  }
  default: {
    break;
  }
  }
  return 0;
}

int listen_for_message(struct pollfd *fds, int *nfds) {
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
      buf[n] = '\0';
      Message *message;
      decode_message(buf, &message);
      handle_decoded(message, fds[i]);
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
// uint32_t height;
//  uint8_t prev_hash[32];
//  uint8_t state_root[32];
// uint8_t tx_root[32];
//  uint64_t timestamp;
//  uint8_t proposer[32];
//  uint8_t signature[64];
// uint32_t tx_count;
// transaction *transactions;

int compute_merkle_root(uint8_t **leaves, uint32_t count, uint8_t *root,
                        size_t leaf_size) {
  if (count == 0) {
    memset(root, 0, 32);
    return 1;
  }

  // hash each leaf
  uint8_t *hashes = malloc(count * 32);
  for (uint32_t i = 0; i < count; i++) {
    crypto_hash_sha256(hashes + i * 32, leaves[i], leaf_size);
  }

  // pair and hash up the tree
  uint32_t n = count;
  while (n > 1) {
    for (uint32_t i = 0; i < n; i += 2) {
      if (i + 1 < n) {
        // hash left || right
        uint8_t pair[64];
        memcpy(pair, hashes + i * 32, 32);
        memcpy(pair + 32, hashes + (i + 1) * 32, 32);
        crypto_hash_sha256(hashes + (i / 2) * 32, pair, 64);
      } else {
        // odd one out, promote it
        memcpy(hashes + (i / 2) * 32, hashes + i * 32, 32);
      }
    }
    n = (n + 1) / 2;
  }

  memcpy(root, hashes, 32);
  free(hashes);
  return 0;
}

block build_genesis(account *accounts, validator *validators) {
  block genesis = {
      .height = 0,
      .prev_hash = {0},
      .timestamp = 1712000000, // fixed, arbitrary
      .tx_count = 0,
      .transactions = NULL,
      .proposer = {0},
      .signature = {0},
      .tx_root = {0},
  };
  // leafing this as it is for now, as it works, they're the same size
  // (also did you like my joke?)
  size_t account_leaf_size = 32 + 8 + 8;
  uint8_t *leaf = malloc(account_leaf_size);
  memcpy(leaf, accounts[0].public_key, 32);
  memcpy(leaf + 32, &accounts[0].balance, 8);
  memcpy(leaf + 40, &accounts[0].nonce, 8);
  compute_merkle_root(&leaf, 1, genesis.state_root, account_leaf_size);

  memcpy(leaf, validators[0].public_key, 32);
  memcpy(leaf + 32, &validators[0].stake, 8);
  memcpy(leaf + 40, &validators[0].block_joined, 8);
  compute_merkle_root(&leaf, 1, genesis.validator_root, account_leaf_size);
  free(leaf);

  return genesis;
}

int build_gen_state(state *current_state) {
  account *accounts = malloc(sizeof(account));
  validator *validators = malloc(sizeof(validator));

  account init_account = {
      .public_key = {0x9e, 0x17, 0x0c, 0x42, 0xb3, 0xb9, 0x9d, 0xc2,
                     0x84, 0xe9, 0xc1, 0x3d, 0x65, 0x9c, 0x79, 0x88,
                     0xd4, 0x13, 0xb6, 0xc9, 0x55, 0x01, 0xfe, 0x96,
                     0x27, 0x96, 0x88, 0x5e, 0x40, 0x26, 0xf8, 0x76},
      .balance = 10000,
      .nonce = 0,
  };
  memcpy(accounts, &init_account, 48);
  validator init_validator = {
      .public_key = {0x9e, 0x17, 0x0c, 0x42, 0xb3, 0xb9, 0x9d, 0xc2,
                     0x84, 0xe9, 0xc1, 0x3d, 0x65, 0x9c, 0x79, 0x88,
                     0xd4, 0x13, 0xb6, 0xc9, 0x55, 0x01, 0xfe, 0x96,
                     0x27, 0x96, 0x88, 0x5e, 0x40, 0x26, 0xf8, 0x76},
      .stake = 1000,
      .block_joined = 0,
  };
  memcpy(validators, &init_validator, 48);
  current_state->accounts_count = 1;
  current_state->validators_count = 1;
  current_state->accounts = accounts;
  current_state->validators = validators;
  return 0;
}

int init_chain(state *current_state, block *gen_block) {
  build_gen_state(current_state);
  *gen_block =
      build_genesis(current_state->accounts, current_state->validators);
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
