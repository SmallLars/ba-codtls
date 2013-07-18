#include "random.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

void random_x(uint8_t *c, size_t len) {
  int fd_random = open("/dev/random", O_RDONLY);  // Block
  int fd_urandom = open("/dev/urandom", O_RDONLY); // Non Block
/*
  if (fd_random == -1 || fd_urandom == -1) {
    perror("Öffnen von random fehlgeschlagen: ");
    return;
  }
*/

  struct pollfd poll_random = {fd_random, POLLIN, 0};

  uint32_t i;
  for (i = 0; i < len; i++) {
    if (poll(&poll_random, 1, 0) > 0) {
      if (read(fd_random, c + i, 1) == 1) continue;
    }
    if (read(fd_urandom, c + i, 1) != 1) i--;
  }

  close(fd_random);
  close(fd_urandom);
}
