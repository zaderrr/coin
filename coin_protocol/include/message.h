#ifndef COIN_MESSAGE_H
#define COIN_MESSAGE_H

#include <stdint.h>
#include <sys/poll.h>

typedef enum MessageType {
  HANDSHAKE,
  INIT_BALANCE,
  PING,
  TX_SUBMIT,
  GET_BLOCK,
  GET_BLOCKS,
  BLOCK,
  BLOCKS,
  GET_HEIGHT,
  HEIGHT,
  BLOCK_PROPOSAL
} MessageType;

typedef struct MessageHeader {
  enum MessageType type;
  uint32_t payload_len;
} MessageHeader;

typedef struct Message {
  MessageHeader *header;
  uint8_t *payload;
} Message;

typedef struct Handshake {
  unsigned char identity[32];
} Handshake;

int send_handshake(unsigned char *buffer, unsigned char *public_key);
int write_header(MessageType type, uint32_t length, unsigned char *buff);
int decode_message(unsigned char *buff, Message **message);
int handle_message(unsigned char *buff, struct pollfd client_fd);

int read_header(unsigned char *buff, Message *message);
int create_message(MessageType type, uint32_t length, unsigned char *payload,
                   unsigned char *out);
int send_message(int length, unsigned char *payload, int fd);
#endif
