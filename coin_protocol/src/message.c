#include "message.h"
#include "block.h"
#include <arpa/inet.h>
#include <endian.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <unistd.h>

uint64_t read_uint_64(unsigned char *buff) {
  uint64_t val = 0;
  memcpy(&val, buff, 8);
  val = htonll(val);
  return val;
}

int read_signature(unsigned char *buff, unsigned char *dest) {
  memcpy(dest, buff, 64);
  return 0;
}

int *read_public_key(unsigned char *buff, unsigned char *dest) {
  memcpy(dest, buff, 32);
  return 0;
}

uint32_t read_uint_32(unsigned char *buff) {
  uint32_t val = 0;
  memcpy(&val, buff, 4);
  val = ntohl(val);
  return val;
}

int read_header(unsigned char *buff, Message *message) {
  message->header = malloc(sizeof(struct MessageHeader));
  message->header->payload_len = 0;
  message->header->type = 0;
  message->header->type = (enum MessageType)buff[0];
  buff = buff + 1;
  message->header->payload_len = read_uint_32(buff);
  return 0;
}

int decode_message(unsigned char *buff, Message **message) {
  *message = malloc(sizeof(struct Message));
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

int create_message(MessageType type, uint32_t length, unsigned char *payload,
                   unsigned char *out) {
  write_header(type, length, out);
  memcpy(out + 5, payload, length);
  return 0;
}
