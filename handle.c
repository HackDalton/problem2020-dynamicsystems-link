#include "handle.h"

#define FLAG_SIZE 48
#define MAX_DATA_SIZE 80
#define TIMEOUT_SECONDS 10

#define GREETING "Hello, and welcome to the DynamicSystems link server!"
#define SECURITY_TIP "Today's tip: If you disable all forms of security, then you can't get hacked."
#define TIMEOUT "You were disconnected due to inactivity."

// see section 2.1 of protocol reference
#define COMMAND_HEADER { 0x44, 0x4E, 0x53, 0x4D }

// see section 2.2.1 of protocol reference
#define COMMAND_SERVER_GREETING 0x01
#define COMMAND_SERVER_PROTOCOL_ERROR 0x02
#define COMMAND_SERVER_GENERIC_RESPONSE 0x03
#define COMMAND_SERVER_SECURE_RESPONSE 0x04
#define COMMAND_SERVER_TIMEOUT 0x05

// see section 2.2.2 of protocol reference
#define COMMAND_CLIENT_GET_TIME 0x81
#define COMMAND_CLIENT_START_SECURITY 0x82
#define COMMAND_CLIENT_PING 0x83
#define COMMAND_CLIENT_REQUEST_FLAG 0x84

// see section 2.1 of protocol reference
typedef struct __attribute__((packed)) {
	uint8_t header[4];
	uint8_t command_number;
	uint8_t sequence_number;
	uint8_t data_length;
	uint8_t security_flag;
	uint32_t security_message_key;
	uint8_t security_checksum[4];
} message_t;

// variables for connection
char message_buffer[sizeof(message_t)];

message_t message;
uint8_t data[MAX_DATA_SIZE];

int server_sequence_number;
int client_sequence_number;
bool security_enabled;
uint8_t connection_key[4];

char flag[FLAG_SIZE + 1];

int client_error(char * message) {
	printf("Error on client connection!\n");
	printf("Message: %s\n", message);
	exit(1);
	return 1;
}

int read_bytes(int socket_fd, size_t n, void * buffer) {
	int read_so_far = 0;
    while (read_so_far < n) {
        int result = read(socket_fd, buffer + read_so_far, n - read_so_far);
        if (result < 1) {
            return -1;
        }

        read_so_far += result;
    }
}

void random_bytes(uint8_t * buffer) {
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		client_error("Couldn't open random bytes!");
		return;
	}

	int err = read_bytes(fd, 4, buffer);
	if (err < 0) {
		client_error("Couldn't read random bytes!");
		return;
	}

	close(fd);
}

void security_operation(message_t * message) {
	uint8_t final_key[4];
	for (size_t i = 0; i < 4; i++) {
		final_key[i] = connection_key[i] + ((uint8_t *) &message->security_message_key)[i];
	}

	for (size_t i = 0; i < MAX_DATA_SIZE; i++) {
		data[i] = data[i] ^ final_key[i % 4];
	}
}

int write_message(int socket_fd, message_t * message) {
	// update the sequence number
	message->sequence_number = server_sequence_number;
	server_sequence_number++;

	if (message->security_flag) {
		// get the checksum of the plaintext
		uint32_t checksum = crc32(0, data, message->data_length);
		uint8_t * checksum_array = (uint8_t *) &checksum;
		for (size_t i = 0; i < 4; i++) {
			message->security_checksum[i] = checksum_array[i];
		}

		// generate message key
		random_bytes((uint8_t *) &message->security_message_key);

		// update security info
		security_operation(message);
	}

	// first write the message info
	int n = write(socket_fd, message, sizeof(message_t));
	if (n < 0) {
		return n;
	}

	// now write the data
	n = write(socket_fd, data, message->data_length);
	if (n < 0) {
		return n;
	}

	return 0;
}

int send_message_with_string(int socket_fd, int command_number, char * message) {
	message_t protocol_error = {
		.header = COMMAND_HEADER,
		.command_number = command_number,
		.sequence_number = 0,
		.data_length = strlen(message) + 1,
		.security_flag = 0
	};

	// copy the text into our buffer
	strncpy(data, message, MAX_DATA_SIZE);

	return write_message(socket_fd, &protocol_error);
}

void send_timeout(int socket_fd) {
	send_message_with_string(socket_fd, COMMAND_SERVER_TIMEOUT, TIMEOUT);
}

void send_protocol_error(int socket_fd, const char * message) {
	send_message_with_string(socket_fd, COMMAND_SERVER_PROTOCOL_ERROR, (char *) message);
}

int send_response(int socket_fd, char * text) {
	message_t response = {
		.header = COMMAND_HEADER,
		.command_number = COMMAND_SERVER_GENERIC_RESPONSE,
		.data_length = strlen(text) + 1,
		.security_flag = 0
	};

	// was our current message sent securely?
	if (message.security_flag != 0) {
		// security required
		response.command_number = COMMAND_SERVER_SECURE_RESPONSE;
		response.security_flag = 1;
	}

	// copy the text into our buffer
	strncpy(data, text, MAX_DATA_SIZE);

	return write_message(socket_fd, &response);
}

int handle_connection(int socket_fd, bool is_authorized) {
	// clear some variables
	bzero(&message, sizeof(message));
	bzero(data, MAX_DATA_SIZE);
	server_sequence_number = 0;
	client_sequence_number = 0;
	security_enabled = false;

	// generate a connection key
	// randomize it for EXTRA SECURITY
	random_bytes(connection_key);

	// set a read timeout
	// struct timeval timeout;
	// timeout.tv_sec = TIMEOUT_SECONDS;
	// timeout.tv_usec = 0;
	// setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

	// read the flag file
	FILE * flag_fd = fopen("flag.txt", "r");
	if (!flag_fd) {
		return client_error("Could not open flag!");
	}
	fread(flag, sizeof(char), FLAG_SIZE, flag_fd);
	flag[FLAG_SIZE] = '\0';
	fclose(flag_fd);

	// say hello
	int err = send_message_with_string(socket_fd, COMMAND_SERVER_GREETING, GREETING);
	if (err < 0) {
		return client_error("Could not write to socket!");
	}

	while (1) {
		// wait for a message
		err = read_bytes(socket_fd, sizeof(message), &message);
		if (err < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				// we timed out, complain and shut down the connection
				send_timeout(socket_fd);
				close(socket_fd);
			}

			return 0;
		}

		// we got a message, but how much data does it have?
		size_t data_to_read = message.data_length;
		if (data_to_read > MAX_DATA_SIZE) {
			// protection against buffer overflows
			data_to_read = MAX_DATA_SIZE;
		}

		// read the data
		err = read_bytes(socket_fd, data_to_read, &data);
		if (err < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				// we timed out, complain and shut down the connection
				send_timeout(socket_fd);
				close(socket_fd);
			}

			return 0;
		}

		// verify the header
		uint8_t correct_header[4] = COMMAND_HEADER;
		if (
			message.header[0] != correct_header[0] ||
			message.header[1] != correct_header[1] ||
			message.header[2] != correct_header[2] ||
			message.header[3] != correct_header[3]
		) {
			send_protocol_error(socket_fd, "Invalid header.");
			close(socket_fd);
			return 0;
		}

		// verify the sequence number
		if (message.sequence_number != client_sequence_number) {
			send_protocol_error(socket_fd, "Incorrect sequence number.");
			close(socket_fd);
			return 0;
		}
		client_sequence_number++;

		// verify the security flag is something sane
		if (message.security_flag != 0 && message.security_flag != 1) {
			send_protocol_error(socket_fd, "Invalid security flag.");
			close(socket_fd);
			return 0;
		}

		// verify that security is enabled if we're using it
		if (!security_enabled && message.security_flag != 0) {
			send_protocol_error(socket_fd, "You must enable security for this connection first.");
			close(socket_fd);
			return 0;
		}

		// some messages require security
		if (message.command_number == COMMAND_CLIENT_PING || message.command_number == COMMAND_CLIENT_REQUEST_FLAG) {
			if (message.security_flag != 1) {
				send_protocol_error(socket_fd, "That command requires a secure connection.");
				close(socket_fd);
				return 0;
			}
		}

		// decrypt it if needed
		if (message.security_flag == 1 && data_to_read != 0) {
			security_operation(&message);

			// verify checksum
			uint32_t checksum = crc32(0, data, data_to_read);
			for (size_t i = 0; i < 4; i++) {
				uint8_t checksum_byte = (checksum >> ((3 - i) * 8)) & 0xFF;
				if (message.security_checksum[i] != checksum_byte) {
					send_protocol_error(socket_fd, "Incorrect security checksum.");
					close(socket_fd);
					return 0;
				}
			}
		}

		// now we can figure out what the message was
		if (message.command_number == COMMAND_CLIENT_GET_TIME) {
			// tell them the time
			time_t tm = time(NULL);
			struct tm * current_time = gmtime(&tm);
			send_response(socket_fd, asctime(current_time));
		} else if (message.command_number == COMMAND_CLIENT_START_SECURITY) {
			// start security
			if (security_enabled) {
				send_protocol_error(socket_fd, "Security is already enabled on this connection.");
				close(socket_fd);
				return 0;
			}

			send_response(socket_fd, SECURITY_TIP);

			message_t key_info = {
				.header = COMMAND_HEADER,
				.command_number = COMMAND_SERVER_GENERIC_RESPONSE,
				.data_length = 4,
				.security_flag = 0
			};
			memcpy(data, (uint8_t *) &connection_key, 4);
			write_message(socket_fd, &key_info);

			security_enabled = true;
		} else if (message.command_number == COMMAND_CLIENT_PING) {
			// ping
			if (message.data_length == 0) {
				send_protocol_error(socket_fd, "You must send data to ping.");
				close(socket_fd);
				return 0;
			}

			message_t ping_response = {
				.header = COMMAND_HEADER,
				.command_number = COMMAND_SERVER_SECURE_RESPONSE,
				.data_length = message.data_length,
				.security_flag = 1,
				.security_message_key = 0,
				.security_checksum = 0
			};
			write_message(socket_fd, &ping_response);
		} else if (message.command_number == COMMAND_CLIENT_REQUEST_FLAG) {
			// are they authorized?
			if (is_authorized) {
				// give them the flag
				send_response(socket_fd, flag);
			} else {
				// no
				send_response(socket_fd, "You are not authorized to view the flag.");
			}
		} else {
			send_protocol_error(socket_fd, "Unknown command number.");
			close(socket_fd);
			return 0;
		}
	}

	close(socket_fd);
	return 0;
}