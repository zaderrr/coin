#include "block.h"
#include <sys/poll.h>
#include <sys/types.h>

unsigned char *get_public_key(unsigned char *buff);
unsigned char *handle_handshake(unsigned char *buff, struct pollfd client_fd);
struct pollfd *start_server();
int accept_connections(struct pollfd *fds, int *nfds);
int read_friends(char *file_location, char *friends);
int listen_for_message(struct pollfd *fds, int *nfds);
