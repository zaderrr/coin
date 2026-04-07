#include "message.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>

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
