#ifndef _HANDLE_H_
#define _HANDLE_H_

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>

#include "util.h"

int handle_connection(int socket_fd, bool is_authorized);

#endif