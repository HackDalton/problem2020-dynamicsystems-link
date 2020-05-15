package main

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net"

	"github.com/davecgh/go-spew/spew"
)

const HOST = "problems.hackdalton.com"
const PORT = 24992

const messageSize = 16

const (
	commandServerGreeting        = 0x01
	commandServerProtocolError   = 0x02
	commandServerGenericResponse = 0x03
	commandServerSecureResponse  = 0x04
	commandServerTimeout         = 0x05

	commandClientGetTime       = 0x81
	commandClientStartSecurity = 0x82
	commandClientPing          = 0x83
	commandClientRequestFlag   = 0x84
)

var messageHeader = [4]uint8{
	0x44, 0x4E, 0x53, 0x4D,
}

type message struct {
	header             [4]uint8
	command            uint8
	sequence           uint8
	dataLength         uint8
	securityFlag       uint8
	securityMessageKey uint32
	securityChecksum   uint32
}

var currentSequenceNumber uint8 = 0
var connectionKey []uint8

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func readMessage(conn net.Conn) (message, []byte, error) {
	messageBytes := make([]byte, messageSize)
	_, err := io.ReadFull(conn, messageBytes)
	if err != nil {
		return message{}, nil, err
	}

	// this is a hack
	// don't do this
	msg := message{
		header: [4]uint8{
			messageBytes[0],
			messageBytes[1],
			messageBytes[2],
			messageBytes[3],
		},
		command:            messageBytes[4],
		sequence:           messageBytes[5],
		dataLength:         messageBytes[6],
		securityFlag:       messageBytes[7],
		securityMessageKey: binary.BigEndian.Uint32(messageBytes[8:12]),
		securityChecksum:   binary.BigEndian.Uint32(messageBytes[12:16]),
	}

	messageData := make([]byte, msg.dataLength)
	_, err = io.ReadFull(conn, messageData)
	if err != nil {
		return message{}, nil, err
	}

	if msg.securityFlag == 1 && len(messageData) > 0 {
		newKey := []byte{0, 0, 0, 0}
		for i := 0; i < 4; i++ {
			newKey[i] = connectionKey[i] + uint8((msg.securityMessageKey>>((3-i)*8))&0xFF)
		}

		messageData = securityOperation(messageData, newKey)
	}

	return msg, messageData, nil
}

func writeMessage(conn net.Conn, msg message, data []byte) error {
	messageBytes := make([]byte, messageSize)

	dataToWrite := data
	if msg.securityFlag == 1 {
		// assume security message key is just 0
		dataToWrite = securityOperation(data, connectionKey)

		msg.securityChecksum = crc32.ChecksumIEEE(data)
	}
	// this is also a hack
	messageBytes[0] = msg.header[0]
	messageBytes[1] = msg.header[1]
	messageBytes[2] = msg.header[2]
	messageBytes[3] = msg.header[3]
	messageBytes[4] = msg.command
	messageBytes[5] = currentSequenceNumber
	messageBytes[6] = msg.dataLength
	messageBytes[7] = msg.securityFlag
	binary.BigEndian.PutUint32(messageBytes[8:12], msg.securityMessageKey)
	binary.BigEndian.PutUint32(messageBytes[12:16], msg.securityChecksum)

	currentSequenceNumber++

	_, err := conn.Write(messageBytes)
	if err != nil {
		return err
	}

	_, err = conn.Write(dataToWrite)
	if err != nil {
		return err
	}

	return nil
}

func securityOperation(data []byte, key []uint8) []byte {
	newData := []byte{}
	for i, d := range data {
		newData = append(newData, d^key[i%4])
	}
	return newData
}

func main() {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", HOST, PORT))
	check(err)

	defer conn.Close()

	// get greeting message
	msg, data, err := readMessage(conn)
	check(err)
	log.Println(string(data))

	// test connection with a get time
	err = writeMessage(conn, message{
		header:  messageHeader,
		command: commandClientGetTime,
	}, nil)
	check(err)

	// listen for response
	msg, data, err = readMessage(conn)
	check(err)
	log.Println(string(data))

	/*
	 * security time
	 */

	// start security
	err = writeMessage(conn, message{
		header:  messageHeader,
		command: commandClientStartSecurity,
	}, nil)
	check(err)

	// listen for security tip
	msg, data, err = readMessage(conn)
	check(err)
	log.Println(string(data))

	// listen for key
	msg, data, err = readMessage(conn)
	check(err)

	connectionKey = data

	// send ping with 80 bytes of data but 255 length
	pingData := []byte{}
	for i := 0; i < 80; i++ {
		pingData = append(pingData, 0xAA)
	}
	err = writeMessage(conn, message{
		header:       messageHeader,
		command:      commandClientPing,
		dataLength:   255,
		securityFlag: 1,
	}, pingData)
	check(err)

	// listen for response
	msg, data, err = readMessage(conn)
	check(err)

	// get the extra data
	bledData := data[80:]

	// decrypt it
	newKey := []byte{0, 0, 0, 0}
	for i := 0; i < 4; i++ {
		newKey[i] = connectionKey[i] + uint8((msg.securityMessageKey>>((3-i)*8))&0xFF)
	}

	// it should be somewhere in here
	spew.Dump(securityOperation(bledData, newKey))
}
