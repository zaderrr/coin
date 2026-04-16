#include "message.h"
#include "util.h"
#include <arpa/inet.h>
#include <endian.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <unistd.h>

int read_header(unsigned char *buff, Message *message) {
  message->header = malloc(sizeof(struct MessageHeader));
  message->header->payload_len = 0;
  message->header->type = 0;
  Reader r = {buff, buff + 5};
  message->header->type = (enum MessageType)buff[0];

  READ_FIELD(&r, message->header->type, 1);
  READ_FIELD(&r, message->header->payload_len,
             sizeof(message->header->payload_len));
  message->header->payload_len = ntohl(message->header->payload_len);
  return 0;
}

int decode_message(unsigned char *buff, Message **message) {
  read_header(buff, *message);
  buff += 5;
  (*message)->payload = malloc((*message)->header->payload_len);
  memcpy((*message)->payload, buff, (*message)->header->payload_len);
  return 0;
}

// Writres the header to buff
// where length = payload length
// and buff = payload being sent
int write_header(MessageType type, uint32_t length, unsigned char *buff) {
  buff[0] = (char)type;
  uint32_t payload_len = htonl(length);
  memcpy(buff + 1, &payload_len, sizeof(payload_len));
  return 0;
}

// Writes header to `out` buffer, and coppies payload +5 header offset
int create_message(MessageType type, uint32_t length, unsigned char *payload,
                   unsigned char *out) {
  write_header(type, length, out);
  memcpy(out + 5, payload, length);
  return 0;
}

int send_message(int length, unsigned char *payload, int fd) {
  send(fd, payload, length, 0);
  return 0;
}
