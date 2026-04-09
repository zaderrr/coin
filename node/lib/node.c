#include "block.h"
#include "message.h"
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
