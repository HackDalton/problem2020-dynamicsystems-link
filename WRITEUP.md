# HackDalton: DynamicSystems Link
> Warning! There are spoilers ahead

The first part of this problem is implementing a client for the link server protocol given in the document. This can seem a bit daunting at first, but it's easier if you take it step by step: first try parsing the Greeting (`0x01`) message, then see if you can send a Get Time (`0x81`) message and get its response, and then try implementing the security mechanism.

(you can see an implementation of the protocol in the [solution](./solution) folder, but you should try implementing it yourself!)

Once you have a working client, it's time to look into the actual bug. The last part of the description seems to hint at something: _Don't forget the official motto of DynamicSystems: "Since 2014: Our hearts bleed for our clients!"_. Some research leads you to [the Heartbleed bug](https://en.wikipedia.org/wiki/Heartbleed), which was a vulnerability in the OpenSSL library. It's probably best summarized in [this image](https://en.wikipedia.org/wiki/File:Simplified_Heartbleed_explanation.svg). 

Looking at the protocol documentation with this in mind, one thing that seems suspicious is the Ping (`0x83`) command, which has a description helpfully letting us know to "Make sure that your data is as long as the data length you specify in the message! Also, make sure to abide by the maximum data length, as specified in section 2.1.". Looking at section 2.1, we see the maximum data length is 80 bytes.

So, what happens if we send a Ping (`0x83`) with 80 bytes of data, but adjust the message header to have a data length of 255 bytes (the maximum value of an unsigned 8-bit integer)? Well, you get back 255 bytes of data:
```
([]uint8) (len=255 cap=256) {
 00000000  aa aa aa aa aa aa aa aa  aa aa aa aa aa aa aa aa  |................|
 00000010  aa aa aa aa aa aa aa aa  aa aa aa aa aa aa aa aa  |................|
 00000020  aa aa aa aa aa aa aa aa  aa aa aa aa aa aa aa aa  |................|
 00000030  aa aa aa aa aa aa aa aa  aa aa aa aa aa aa aa aa  |................|
 00000040  aa aa aa aa aa aa aa aa  aa aa aa aa aa aa aa aa  |................|
 00000050  20 57 74 e7 26 57 74 e7  24 eb 0a 72 05 3f 15 84  | Wt.&Wt.$..r.?..|
 00000060  4e 13 15 8b 51 38 1a 9c  4b 64 02 d4 57 08 00 95  |N...Q8..Kd..W...|
 00000070  50 24 00 b8 4b 64 00 90  15 25 1f b8 14 39 04 92  |P$..Kd...%...9..|
 00000080  51 08 4d af 53 11 2c ae  1c 07 37 95 58 57 74 e7  |Q.M.S.,...7.XWt.|
 00000090  26 57 74 e7 25 57 74 e7  25 57 74 e7 25 57 74 e7  |&Wt.%Wt.%Wt.%Wt.|
 000000a0  27 57 52 73 25 57 74 e7  25 57 74 e7 25 57 74 e7  |'WRs%Wt.%Wt.%Wt.|
 000000b0  25 57 74 e7 25 57 74 e7  25 57 74 e7 25 57 74 e7  |%Wt.%Wt.%Wt.%Wt.|
 000000c0  24 57 74 e7 25 57 74 e7  85 5d 74 e7 25 57 74 e7  |$Wt.%Wt..]t.%Wt.|
 000000d0  dd ea eb a7 a4 28 74 e7  dd ea eb a7 a4 28 74 e7  |.....(t......(t.|
 000000e0  25 57 74 e7 25 57 74 e7  f6 ba ee a7 a4 28 74 e7  |%Wt.%Wt......(t.|
 000000f0  25 57 74 e7 25 57 74 e7  25 57 74 e7 25 57 74     |%Wt.%Wt.%Wt.%Wt|
}
```

The first 80 bytes are what we sent as the data for our initial Ping (`0x83`), but what's the rest of this data? Looking at the unencrypted version of the data, we see:

```
([]uint8) (len=255 cap=256) {
 00000000  6f 5d 0c 78 6f 5d 0c 78  6f 5d 0c 78 6f 5d 0c 78  |o].xo].xo].xo].x|
 00000010  6f 5d 0c 78 6f 5d 0c 78  6f 5d 0c 78 6f 5d 0c 78  |o].xo].xo].xo].x|
 00000020  6f 5d 0c 78 6f 5d 0c 78  6f 5d 0c 78 6f 5d 0c 78  |o].xo].xo].xo].x|
 00000030  6f 5d 0c 78 6f 5d 0c 78  6f 5d 0c 78 6f 5d 0c 78  |o].xo].xo].xo].x|
 00000040  6f 5d 0c 78 6f 5d 0c 78  6f 5d 0c 78 6f 5d 0c 78  |o].xo].xo].xo].x|
 00000050  05 00 00 00 03 00 00 00  01 35 0d ad f4 68 61 63  |.........5...hac|
 00000060  6b 44 61 6c 74 6f 6e 7b  6e 33 76 33 72 5f 74 72  |kDalton{n3v3r_tr|
 00000070  75 73 74 5f 6e 33 74 77  30 72 6b 5f 31 6e 70 75  |ust_n3tw0rk_1npu|
 00000080  74 5f 39 48 76 46 58 49  39 50 43 72 7d 00 00 00  |t_9HvFXI9PCr}...|
 00000090  03 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
 000000a0  02 00 26 94 00 00 00 00  00 00 00 00 00 00 00 00  |..&.............|
 000000b0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
 000000c0  01 00 00 00 00 00 00 00  a0 0a 00 00 00 00 00 00  |................|
 000000d0  f8 bd 9f 40 81 7f 00 00  f8 bd 9f 40 81 7f 00 00  |...@.......@....|
 000000e0  00 00 00 00 00 00 00 00  d3 ed 9a 40 81 7f 00 00  |...........@....|
 000000f0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00     |...............|
}
```

And our flag is there.

## What just happened?
Taking a look at the source code of the server, we can get a better understanding of why this worked.

At the top of `handle.c`, we can see the variables associated with a connection:
```c
typedef struct {
	message_t message;
	uint8_t data[MAX_DATA_SIZE];

	int server_sequence_number;
	int client_sequence_number;
	bool security_enabled;
	uint8_t connection_key[4];

	char flag[FLAG_SIZE + 1];
} connection_variables_t;

connection_variables_t connection;
```
(and, earlier in the file, `MAX_DATA_SIZE` is defined to be 80)

Going down to the part of the code that reads messages, we see:
```c
// we got a message, but how much data does it have?
size_t data_to_read = connection.message.data_length;
if (data_to_read > MAX_DATA_SIZE) {
	// protection against buffer overflows
	data_to_read = MAX_DATA_SIZE;
}

// read the data
err = read_bytes(socket_fd, data_to_read, &connection.data);
if (err < 0) {
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
		// we timed out, complain and shut down the connection
		send_timeout(socket_fd);
		close_connection(socket_fd);
	}

	return 0;
}
```

This code checks the data length provided by the user, and makes sure it's not larger than `MAX_DATA_SIZE`. This prevents a buffer overflow, since if you remember earlier, our data buffer is only set to `MAX_DATA_SIZE`. It then proceeds to read that many bytes from the connection. So in the case of our weird Ping (`0x83`) message from before, it would only read 80 bytes, even though we had a data length of 255.

However, if we go down to the part of the code that handles pings:
```c
} else if (connection.message.command_number == COMMAND_CLIENT_PING) {
	// ping
	if (connection.message.data_length == 0) {
		send_protocol_error(socket_fd, "You must send data to ping.");
		close_connection(socket_fd);
		return 0;
	}

	message_t ping_response = {
		.header = COMMAND_HEADER,
		.command_number = COMMAND_SERVER_SECURE_RESPONSE,
		.data_length = connection.message.data_length,
		.security_flag = 1,
		.security_message_key = 0,
		.security_checksum = 0
	};
	write_message(socket_fd, &ping_response);
}
```

This code creates a `message_t` with a `data_length` of `connection.message.data_length`. This is the user-controlled number from the message, not our `data_to_read` variable from the bounds check! `write_message` uses this `data_length` field to know how much to read from the data buffer and send to the client, and when it's given a length of 255, it reads right past the end of the data buffer, sending out the rest of our `connection_variables_t` struct, including the `flag` buffer.

If you look closely at the output from before, you can actually read off the rest of the connection variables! `server_sequence_number` was `0x05`, `client_sequence_number` was `0x03`, `security_enabled` was `0x01`, and `connection_key` was `0x35 0x0d 0xad 0xf4`.

## Why did we look at the unencrypted data?
The first 80 bytes of our Ping (`0x83`) came back encrypted (and so our code decrypted them fine), but the extra variables (the ones past our data buffer) were sent unencrypted. Why is that?

Looking at `write_message`, we can see the part of the code that handles sending secure messages:
```c
if (message->security_flag) {
	// get the checksum of the plaintext
	uint32_t checksum = crc32(0, connection.data, message->data_length);
	uint8_t * checksum_array = (uint8_t *) &checksum;
	for (size_t i = 0; i < 4; i++) {
		message->security_checksum[i] = checksum_array[i];
	}

	// generate message key
	random_bytes((uint8_t *) &message->security_message_key);

	// encrypt the message
	security_operation(message);
}
```

And if we look at `security_operation`:

```c
void security_operation(message_t * message) {
	uint8_t final_key[4];
	for (size_t i = 0; i < 4; i++) {
		final_key[i] = connection.connection_key[i] + ((uint8_t *) &message->security_message_key)[i];
	}

	for (size_t i = 0; i < MAX_DATA_SIZE; i++) {
		connection.data[i] = connection.data[i] ^ final_key[i % 4];
	}
}
```

We can see that the way this function works is by doing the XOR in-place, modifying the contents of the data buffer. Of course, it only does this on the data _in_ the data buffer, which is just the 80 bytes (`MAX_DATA_SIZE`) we sent in our ping. This makes sense&mdash;if we were doing this XOR on everything in `connection_variables_t`, we'd be corrupting those variables and confusing the rest of the code!

However, in the `write_message`, we can see that, after running `security_operation`, we're just dumping out the contents of `data` to the client.

```c
// now write the data
n = write(socket_fd, connection.data, message->data_length);
if (n < 0) {
	return n;
}
```

The `write` function doesn't know anything about encryption or secure messages&mdash;when we give it a `message->data_length` that's greater than `MAX_DATA_SIZE`, it'll just write whatever comes next, as-is. That's why we have to look at the raw data of the message to see the flag. Or, since XOR is reversible, we can just repeat the XOR on the decrypted data to get back the encrypted data, which is what the solution code does.