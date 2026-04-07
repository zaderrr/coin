#include "message.h"
#include <arpa/inet.h>
#include <endian.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <unistd.h>

// Reads 4 bytes, increases pos by 4
uint32_t read_uint_32(unsigned char *message, int *read_pos) {
  uint32_t val = 0;
  memcpy(&val, message + *read_pos, 4);
  val = ntohl(val);
  *read_pos += 4;
  return val;
}

int read_header(unsigned char *buff, Message *message, int *read_pos) {
  message->header = malloc(sizeof(struct MessageHeader));
  message->header->payload_len = 0;
  message->header->type = 0;
  message->header->type = (enum MessageType)buff[0];
  *read_pos += 1;
  message->header->payload_len = read_uint_32(buff, read_pos);
  return 0;
}

int decode_message(unsigned char *buff, Message **message) {
  int read_pos = 0;
  *message = malloc(sizeof(struct Message));
  read_header(buff, *message, &read_pos);
  (*message)->payload = malloc((*message)->header->payload_len);
  memcpy((*message)->payload, buff + 5, (*message)->header->payload_len);
  return 0;
}

int write_header(MessageType type, uint32_t length, unsigned char *buff) {
  buff[0] = (char)type;
  uint32_t payload_len = htonl(length);
  memcpy(buff + 1, &payload_len, sizeof(payload_len));
  return 0;
}
