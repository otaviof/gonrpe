package gonrpe

/*
//
// Skeleton data structure used by NRPE query/response packages, code is
// inspired on their original source code (version 2.15), which can be found
// on Source-Forge:
//
//     http://downloads.sourceforge.net/project/nagios/nrpe-2.x/nrpe-2.15
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

// maximum size of a query/response buffer
#define MAX_PACKETBUFFER_LENGTH	1024

typedef struct packet_struct {
	int16_t   packet_version;
	int16_t   packet_type;
	u_int32_t crc32_value;
	int16_t   result_code;
	char      buffer[MAX_PACKETBUFFER_LENGTH];
} packet;


//
// Returns a array of unsigned long values to dub as CRC32's IEEE table
//
unsigned long *generate_crc32_table(void) {
	unsigned long crc, poly;
	int i, j;
    unsigned long *crc32_table = malloc(sizeof(unsigned long) * 257);

	poly = 0xEDB88320L;

	for (i = 0; i < 256; i++) {
		crc = i;
		for (j = 8; j > 0; j--) {
			if (crc & 1) {
				crc = (crc >> 1) ^ poly;
            } else {
				crc >>= 1;
            }
		}
		crc32_table[i] = crc;
    }


    return crc32_table;
}

//
// Calculates the CRC32 signature of a given C array of Chars, hereby
// represented as it's pointer. The return is the CRC32 unsigned long.
//
unsigned long crc32 (
    char *buffer,
    int buffer_size,
    unsigned long *crc32_table
) {
	register unsigned long crc;
	int this_char;
	int current_index;

	crc = 0xFFFFFFFF;

	for (current_index = 0; current_index < buffer_size; current_index++) {
		this_char = (int)buffer[current_index];
		crc = ((crc >> 8) & 0x00FFFFFF) ^ crc32_table[(crc ^ this_char) & 0xFF];
	}

	return (crc ^ 0xFFFFFFFF);
}

//
// Wrapper method around "crc32", to load a C.packet struct to remove current
// signature and use standard struct to calculate CRC32. The return is a
// unsinged long.
//
unsigned long calc_packet_crc32 (
    packet *receive_packet,
    unsigned long *crc32_table
) {
    unsigned long packet_crc32;
    unsigned long calculated_crc32;
    packet local_packet;

    // copying the received packet to a local variable
    memcpy(&local_packet, receive_packet, sizeof(local_packet));

    // converting back the packet crc32 to u_int32_t
    packet_crc32 = ntohl(local_packet.crc32_value);

    // erasing saved signature so calculcation of struct's CRC32 will have the
    // same keys and values when created
    local_packet.crc32_value = 0L;

	return crc32(
        (char *)&local_packet,
        sizeof(local_packet),
        crc32_table
    );
}
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

type NrpePacket struct {
	Version int16
	Type    int16
	CRC32   uint32
	Buffer  string
	cPacket *C.packet
	cbytes  []byte
	size    int
}

const (
	NRPE_PACKET_VERSION_3      = 3
	NRPE_PACKET_VERSION_2      = 2
	NRPE_PACKET_VERSION_1      = 1
	NRPE_PACKET_QUERY          = 1
	NRPE_PACKET_RESPONSE       = 2
	NRPE_PACKET_SIZE           = 1036
	NRPE_HELLO_COMMAND         = "_NRPE_CHECK"
	MAX_PACKETBUFFER_LENGTH    = 1024
	MAX_COMMAND_ARGUMENTS      = 16
	DEFAULT_SOCKET_TIMEOUT     = 10
	DEFAULT_CONNECTION_TIMEOUT = 300
	STATE_UNKNOWN              = 3
	STATE_CRITICAL             = 2
	STATE_WARNING              = 1
	STATE_OK                   = 0
)

var cIEEETable *C.ulong = C.generate_crc32_table()

// Interface to handle different data structures but still responding to the
// same information, required to handle NRPE queries.
type NrpeResponser interface {
	// name of the check, or nrpe command
	GetName() string
	// status, or the return code of the given check
	GetStatus() int
	// the actual check's output
	GetStdout() []string
}

// Wrapping C binary ending conversions to Go, inspired on:
//   https://github.com/chamaken/cgolmnlo
func htons(i uint16) uint16 {
	var b []byte = make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func htonl(i uint32) uint32 {
	var b []byte = make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return *(*uint32)(unsafe.Pointer(&b[0]))
}

func ntohl(i uint32) uint32 {
	return binary.BigEndian.Uint32((*(*[4]byte)(unsafe.Pointer(&i)))[:])
}

// Transforms a normal Response object back into a NRPE Packet, with proper
// flags to be considered a response.
func NrpePacketFromResponse(resp NrpeResponser) []byte {
	var cPkt *C.packet
	var cast *C.char
	var n int
	var bytevalue byte
	// auxiliary local type to reflect a NRPE type of packet with appropriated
	// Go types and C compatible naming
	var goPkt struct {
		packet_version int16
		packet_type    int16
		crc32_value    uint32
		result_code    int16
		buffer         [1024]int8
		pad_cgo_0      [2]byte
	}

	// initial type-casting from Go to C
	goPkt.packet_version = (int16)(htons(NRPE_PACKET_VERSION_2))
	goPkt.packet_type = (int16)(htons(NRPE_PACKET_RESPONSE))
	goPkt.result_code = (int16)(htons(uint16(resp.GetStatus())))
	goPkt.crc32_value = (uint32)(0)

	for n, bytevalue = range []byte(strings.Join(resp.GetStdout(), " ")) {
		goPkt.buffer[n] = int8(bytevalue)
	}

	// adding CRC32 signature
	cPkt = (*C.packet)(unsafe.Pointer(&goPkt))
	goPkt.crc32_value = uint32(
		htonl(uint32(C.calc_packet_crc32(cPkt, cIEEETable))))

	// casting back to original formats in order to carry CRC32
	cPkt = (*C.packet)(unsafe.Pointer(&goPkt))
	cast = (*C.char)(unsafe.Pointer(cPkt))

	return C.GoBytes(unsafe.Pointer(cast), NRPE_PACKET_SIZE)
}

// Creates and validate a NRPE packet, using c bytes input.
func NewNrpePacket(cbytes []byte, size int) (*NrpePacket, error) {
	var err error
	var pkt *NrpePacket = &NrpePacket{cbytes: cbytes, size: size}

	if err = pkt.checkPacketSize(); err != nil {
		return nil, err
	}

	// bootstraping C struct from informed bytes
	pkt.cbytesIntoStruct()

	if err = pkt.validateCRC32(); err != nil {
		return nil, err
	}

	return pkt, err
}

// Wraps the most of type-casting for a C packet into Go.
func (pkt *NrpePacket) cbytesIntoStruct() {
	var cChar *C.char

	// extracting original bytes on local C.char pointer
	cChar = (*C.char)(unsafe.Pointer(&pkt.cbytes[0]))
	// casting extracted C.char array into a C.packet struct
	pkt.cPacket = (*C.packet)(unsafe.Pointer(cChar))

	// also extracting crc32 value
	pkt.CRC32 = uint32(ntohl(uint32(pkt.cPacket.crc32_value)))
	// packet's buffer
	pkt.Buffer = C.GoString((*C.char)(unsafe.Pointer(&pkt.cPacket.buffer)))
}

// Double check if informed packet size matches defaults.
func (pkt *NrpePacket) checkPacketSize() error {
	var err error
	if pkt.size != NRPE_PACKET_SIZE {
		err = errors.New(
			fmt.Sprintf(
				"Invalid NRPE packet size: '%d', expected: '%d'",
				pkt.size, NRPE_PACKET_SIZE))
		return err
	}
	return nil
}

// Calculates the CRC32 using C function and compares with informed value, all
// ulong are cast into uint32 type.
func (pkt *NrpePacket) validateCRC32() error {
	var err error
	var crc32 uint32 = (uint32)(C.calc_packet_crc32(pkt.cPacket, cIEEETable))

	if pkt.CRC32 != crc32 {
		err = errors.New(fmt.Sprintf("CRC32 mismatch %d/%d", crc32, pkt.CRC32))
		return err
	}

	return nil
}

// Separates the command and arguments from a packet's buffer.
func (pkt *NrpePacket) ExtractCmdAndArgsFromBuffer() (string, []string, error) {
	var err error
	var buffer []string
	var cmd string
	var args []string = []string{}

	// splitting informed buffer based on exclamation marks, defualt for NRPE
	buffer = strings.Split(pkt.Buffer, "!")

	// command will always be the first option, a nagios check name
	cmd = fmt.Sprintf("%s", buffer[0])

	// checking how many items we have, at least one to compose a command
	switch len(buffer) {
	case 0:
		err = errors.New("Can't extract command from buffer:" + pkt.Buffer)
		return "", nil, err
	case 1:
		// command is already been extracted
	default:
		cmd = fmt.Sprintf("%s", buffer[0])
		args = buffer[1:]
	}

	return cmd, args, nil
}

/* EOF */
