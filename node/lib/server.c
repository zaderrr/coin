#include "handler.h"
#include "message.h"
#include "node.h"
#include "protocol.h"
#include "util.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_PEERS 12
#define MAX_CLIENTS 128

PeerManager *init_pm() {
  PeerManager *pm = calloc(1, sizeof(PeerManager));
  pm->peers = calloc(MAX_PEERS, sizeof(Peer));
  pm->fds = calloc(MAX_PEERS, sizeof(struct pollfd));
  return pm;
}

Peer *get_peers() {
  Peer *peers = malloc(sizeof(Peer) * 3);
  peers[0] = (Peer){.PORT = 8081, .IP = inet_addr("127.0.0.1")};
  peers[1] = (Peer){.PORT = 8082, .IP = inet_addr("127.0.0.1")};
  peers[2] = (Peer){.PORT = 8083, .IP = inet_addr("127.0.0.1")};
  return peers;
}

int connect_to_peer(Peer peer) {
  int status, valread, client_fd;
  struct sockaddr_in serv_addr;
  if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\n Socket creation error \n");
    return -1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(peer.PORT);
  serv_addr.sin_addr.s_addr = peer.IP;

  if ((status = connect(client_fd, (struct sockaddr *)&serv_addr,
                        sizeof(serv_addr))) < 0) {
    printf("\nConnection Failed \n");
    return -1;
  }
  return client_fd;
}

int connect_to_peers(node_ctx *ctx, struct pollfd server_fd, uint16_t port) {
  ctx->peer_manager->peer_count = 1;
  ctx->peer_manager->peers[0] = (Peer){.peer_fd = server_fd.fd};
  ctx->peer_manager->fds[0] = server_fd;
  Peer *default_peers = get_peers();
  // Hardcoded 3 peers for now
  // TODO: Make this gooder
  for (int i = 0; i < 3; i++) {
    if (default_peers[i].PORT == port) {
      continue;
    }
    int peer_fd = connect_to_peer(default_peers[i]);
    if (peer_fd == -1) {
      continue;
    }
    PeerManager *pm = ctx->peer_manager;
    pm->peers[pm->peer_count].peer_fd = peer_fd;
    pm->fds[pm->peer_count] = (struct pollfd){.fd = peer_fd, .events = POLLIN};
    pm->peer_count++;
    free(default_peers);
  }
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

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

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

int init_network(node_ctx *ctx, uint16_t port) {
  struct pollfd server_fd = start_server(port);
  connect_to_peers(ctx, server_fd, port);

  return 0;
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
