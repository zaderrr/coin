#include "message.h"
#include <netinet/in.h>
#include <node.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define PORT 8080
#define MAX_CLIENTS 128

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

int main(int argc, char const *argv[]) {

  int server_fd, new_socket;
  ssize_t valread;
  struct sockaddr_in address;
  int opt = 1;
  socklen_t addrlen = sizeof(address);
  struct pollfd fds[MAX_CLIENTS + 1];
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

  while (1) {
    int ready = poll(fds, nfds, -1);
    if (ready < 0) {
      perror("poll");
      break;
    }
    if (fds[0].revents & POLLIN) {
      int client_fd = accept(server_fd, NULL, NULL);
      if (client_fd >= 0 && nfds < MAX_CLIENTS + 1) {
        fds[nfds].fd = client_fd;
        fds[nfds].events = POLLIN;
        nfds++;
        printf("new client: fd %d\n", client_fd);
      }
    }
    for (int i = 1; i < nfds; i++) {
      if (!(fds[i].revents & POLLIN))
        continue;
      unsigned char buf[4096];
      ssize_t n = recv(fds[i].fd, buf, sizeof(buf), 0);
      if (n <= 0) {
        close(fds[i].fd);
        fds[i] = fds[nfds - 1];
        nfds--;
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
  }
  return 0;
}
