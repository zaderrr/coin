#include <netinet/in.h>
#include <node.h>
#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char const *argv[]) {
  // build history
  char buff[128];
  char *location = "text.txt";
  read_friends(location, buff);
  //  Start node
  struct pollfd *fds = start_server();
  int nfds = 1;
  while (1) {
    accept_connections(fds, &nfds);
    listen_for_message(fds, &nfds);
  }
  return 0;
}
