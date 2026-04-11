#include "client.h"
#include "block.h"
#include "ed25519.h"
#include "sodium.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <math.h>
#include <message.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define PUB_KEY_LEN 32

int write_keys_to_file(FileEncryption *cipher, char wallet_loc[512]) {
  FILE *fptr;
  fptr = fopen(wallet_loc, "wb");
  if (fptr == NULL) {
    printf("Something went badly wrong...\n");
    return 1;
  }
  fwrite(cipher->salt, 1, crypto_pwhash_SALTBYTES, fptr);
  fwrite(cipher->nonce, 1, crypto_secretbox_NONCEBYTES, fptr);
  unsigned long long ciphertext_len = crypto_secretbox_MACBYTES + 32 + 64;
  fwrite(cipher->CipherText, 1, ciphertext_len, fptr);
  fclose(fptr);

  return 0;
}

int connect_to_node(Peer peer, unsigned char *public_key) {
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
  unsigned char buffer[1024];
  // Write public key to buffer and send
  write_header(HANDSHAKE, PUB_KEY_LEN, buffer);
  memcpy(buffer + 5, public_key, PUB_KEY_LEN);
  send(client_fd, buffer, 1024, 0);
  return client_fd;
}

uint64_t *read_balance(unsigned char *balance) {
  uint64_t *bal = malloc(8);
  memcpy(bal, balance, 8);
  *bal = htonll(*bal);
  return bal;
}

int handle_init_balance(unsigned char *balance, struct pollfd client_fd,
                        Wallet *wallet) {
  uint64_t *bal = read_balance(balance);
  wallet->balance = *bal;
  printf("Balance: %lu\n", *bal);
  return 0;
}

int read_friends(char *file_location, char *friends) {
  FILE *fptr;
  fptr = fopen(file_location, "r+");
  if (fptr == NULL) {
    printf("Couldn't open friend list");
    return 1;
  }
  char buff[1024];
  fgets(buff, 1024, fptr);
  printf("%s", buff);
  return 0;
}

int handle_decoded(Message *message, struct pollfd client_fd, Wallet *wallet) {
  switch (message->header->type) {
  case INIT_BALANCE: {
    handle_init_balance(message->payload, client_fd, wallet);
  }
  default: {
    break;
  }
  }
  return 0;
}

int handle_command(char *cmd, command *command) {
  char *token = strtok(cmd, " \n");
  if (!token)
    return 1;
  if (strncmp(cmd, "balance", 7) == 0) {
    return 1;
  } else if (strcmp(token, "send") == 0) {
    char *amount_str = strtok(NULL, " \n");
    char *address_str = strtok(NULL, " \n");

    if (!amount_str || !address_str) {
      printf("Usage: send <amount> <address>\n");
      return 1;
    }

    char *endptr;
    uint64_t amount = strtoull(amount_str, &endptr, 10);

    if (*endptr != '\0') {
      printf("Amount is not a valid number\n");
      return 1;
    }

    for (int i = 0; i < 64; i++) {
      if (!isxdigit(address_str[i])) {
        printf("Invalid recipient address\n");
        return 1;
      }
    }

    unsigned char receiver[32];
    for (int i = 0; i < 32; i++) {
      sscanf(address_str + i * 2, "%2hhx", &receiver[i]);
    }

    command->type = SEND;
    command->arg_count = 2;
    command->args = malloc(sizeof(char *) * 2);
    command->args[0] = strdup(amount_str);
    command->args[1] = malloc(32);
    memcpy(command->args[1], receiver, 32);
    return 0;
  }
  return 1;
}

int listen_for_command(struct pollfd *infd, command *cmd) {
  char command[256];
  ssize_t n = read(STDIN_FILENO, command, sizeof(command) - 1);
  if (n > 0) {
    command[n] = '\0';
    return handle_command(command, cmd);
  }
  return 1;
}

int peer_message(struct pollfd *srv, Wallet *wallet) {
  unsigned char buf[4096];
  ssize_t n = recv(srv->fd, buf, sizeof(buf), 0);
  if (n <= 0) {
    close(srv->fd);
  } else {
    buf[n] = '\0';
    Message *message;
    decode_message(buf, &message);
    handle_decoded(message, *srv, wallet);
    free(message->payload);
    free(message->header);
    free(message);
  }
  return 0;
}

int get_password(char *password) {
  printf("Enter password: ");
  fgets(password, sizeof password, stdin);
  password[strcspn(password, "\n")] = '\0';
  return 1;
}

int init_wallet(Wallet *wallet, char walletLoc[512]) {
  const char *home = getenv("HOME");
  if (!home) {
    fprintf(stderr, "HOME not set\n");
    return 1;
  }
  if (strlen(walletLoc) == 0) {
    snprintf(walletLoc, 512, "%s/Documents/keys/wallet.coin", home);
  }
  FILE *fptr;
  fptr = fopen(walletLoc, "rb");
  char password[128];
  get_password(password);
  if (fptr == NULL) {
    printf("Creating wallet...\n");
    create_wallet(wallet, password);
    struct FileEncryption *file;
    file = malloc(sizeof(struct FileEncryption));
    encrypt_keys(wallet->public_key, wallet->private_key, password, file);
    return write_keys_to_file(file, walletLoc);
  } else {
    return decrypt_wallet(fptr, wallet, password);
  }
  return 0;
}

#define TX_DATA_SIZE 81 // 1 + 32 + 32 + 8 + 8

int write_tx_to_buff(unsigned char *buff, transaction *tx) {
  uint64_t amount_n = htonll(tx->amount);
  uint64_t nonce_n = htonll(tx->nonce);
  memcpy(buff, &tx->type, 1);
  memcpy(buff + 1, tx->from, 32);
  memcpy(buff + 33, tx->to, 32);
  memcpy(buff + 65, &amount_n, 8);
  memcpy(buff + 73, &nonce_n, 8);
  // Signature coppied during signing
  return 0;
}

// Writes signature of transaction to tx.signature and copies signature to buff
int sign_transaction(transaction *tx, Wallet *wallet, unsigned char *buff) {
  ed25519_sign(tx->signature, buff, TX_DATA_SIZE, wallet->public_key,
               wallet->private_key);

  memcpy(buff + TX_DATA_SIZE, tx->signature, 64);
  return 0;
}

// Create transaction from args
transaction create_tx(char **args, Wallet *wallet) {
  uint64_t amount = strtoull(args[0], NULL, 10);

  transaction tx = {0};
  tx.amount = amount;
  tx.type = TX_TRANSFER;

  // TODO: Sync nonce from server
  tx.nonce = wallet->nonce;
  memcpy(tx.from, wallet->public_key, 32);
  memcpy(tx.to, args[1], 32);

  return tx;
}

// Send **args to fd
// args[0] = amount, args[1] = recipient
int send_transaction(char **args, int fd, Wallet *wallet) {
  transaction tx = create_tx(args, wallet);

  unsigned char tx_buff[sizeof(transaction)];
  // Write tx to buffer + sign it.
  write_tx_to_buff(tx_buff, &tx);
  sign_transaction(&tx, wallet, tx_buff);

  int32_t payload_len = sizeof(transaction);
  unsigned char buff[256];
  write_header(TX_SUBMIT, payload_len, buff);
  // + 5 header offset
  memcpy(buff + 5, tx_buff, sizeof(transaction));
  send(fd, buff, sizeof(buff), 0);
  free(args[0]);
  free(args[1]);
  wallet->nonce++;
  return 0;
}

void execute_command(command *cmd, int fd, Wallet *wallet) {
  if (cmd->type == SEND) {
    send_transaction(cmd->args, fd, wallet);
  }
}
