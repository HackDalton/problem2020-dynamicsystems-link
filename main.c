#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netdb.h>
#include <netinet/in.h>

#include <sys/socket.h>

#include "handle.h"

#define PORT 9876

#define CONNECTION_BACKLOG 4

#define TRADEMARK_SYMBOL "\u2122"

int server_socket_fd;
struct sockaddr_in server_address;

int crash_error(char * message) {
	printf("Error!\n");
	printf("Message: %s\n", message);
	exit(1);
	return 1;
}

int main() {
	int err;

	printf("DynamicSystems" TRADEMARK_SYMBOL " link server\n");

	// open a socket file descriptor
	server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket_fd == -1) {
		return crash_error("Could not open socket!");
	}

	// set up our ip and port
	bzero(&server_address, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);
	server_address.sin_port = htons(PORT);

	// bind to the socket
	err = bind(server_socket_fd, (struct sockaddr *) &server_address, sizeof(server_address));
	if (err == -1) {
		return crash_error("Bind to socket failed!");
	}

	// listen to the socket
	err = listen(server_socket_fd, CONNECTION_BACKLOG);
	if (err == -1) {
		return crash_error("Listen to socket failed!");
	}

	while (1) {
		// accept a new connection
		struct sockaddr_in client_address;
		int client_address_length = sizeof(client_address);
		int client_socket_fd = accept(server_socket_fd, (struct sockaddr *) &client_address, &client_address_length);
		if (err == -1) {
			return crash_error("Accepting connection failed!");
		}

		// fork ourselves to handle the new connection
		int pid = fork();
		if (pid < 0) {
			return crash_error("Fork failed!");
		}

		if (pid == 0) {
			// we're the client handler
			// close the server socket since we don't need it
			close(server_socket_fd);

			// go to our processing code
			int result = handle_connection(client_socket_fd, false);

			return result;
		}

		// we're the main server
		// close the client socket and continue with our day
		close(client_socket_fd);
	}
}