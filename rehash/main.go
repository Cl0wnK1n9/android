package main

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
)

// global variables
var data, err = ioutil.ReadFile("classes.dex")

// classes.dex header struct
type header struct {
	magic           [8]byte
	checksum        uint
	signature       [20]byte
	file_size       uint
	header_size     uint
	endian_tag      uint
	link_size       uint
	link_off        uint
	map_off         uint
	string_ids_size uint
	string_ids_off  uint
	type_ids_size   uint
	type_ids_off    uint
	proto_ids_size  uint
	proto_ids_off   uint
	field_ids_size  uint
	field_ids_off   uint
	method_ids_size uint
	method_ids_off  uint
	class_defs_size uint
	class_defs_off  uint
	data_size       uint
	data_off        uint
}

// string_id_item struct
type string_id_item struct {
	string_data_off uint
}

// string_data_item struct
type string_data_item struct {
	utf16_size uint
	data       []byte
}

// Normal function
func little_endian(data []byte) uint32 {
	return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
}

func get_data_from_offset(data []byte, offset uint, size uint) []byte {
	return data[offset : offset+size]
}

func menu() {
	fmt.Println("[+] Select an option:")
	fmt.Println("[1] Show header")
	fmt.Println("[2] Show string IDs")
	fmt.Println("[3] Show type IDs")
	fmt.Println("[4] Show proto IDs")
	fmt.Println("[5] Show field IDs")
	fmt.Println("[6] Show method IDs")
	fmt.Println("[7] Show class defs")
	fmt.Println("[8] Show data")
	fmt.Println("[9] Show all")
	fmt.Println("[0] Exit")
	fmt.Println("")
}

// parser functions
// parse header from class.dex
func parseHeader(data []byte) *header {
	h := &header{}
	h.magic = [8]byte{data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]}
	h.checksum = uint(data[8]) | uint(data[9])<<8 | uint(data[10])<<16 | uint(data[11])<<24
	h.signature = [20]byte{data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31]}
	h.file_size = uint(data[32]) | uint(data[33])<<8 | uint(data[34])<<16 | uint(data[35])<<24
	h.header_size = uint(data[36]) | uint(data[37])<<8 | uint(data[38])<<16 | uint(data[39])<<24
	h.endian_tag = uint(data[40]) | uint(data[41])<<8 | uint(data[42])<<16 | uint(data[43])<<24
	h.link_size = uint(data[44]) | uint(data[45])<<8 | uint(data[46])<<16 | uint(data[47])<<24
	h.link_off = uint(data[48]) | uint(data[49])<<8 | uint(data[50])<<16 | uint(data[51])<<24
	h.map_off = uint(data[52]) | uint(data[53])<<8 | uint(data[54])<<16 | uint(data[55])<<24
	h.string_ids_size = uint(data[56]) | uint(data[57])<<8 | uint(data[58])<<16 | uint(data[59])<<24
	h.string_ids_off = uint(data[60]) | uint(data[61])<<8 | uint(data[62])<<16 | uint(data[63])<<24
	h.type_ids_size = uint(data[64]) | uint(data[65])<<8 | uint(data[66])<<16 | uint(data[67])<<24
	h.type_ids_off = uint(data[68]) | uint(data[69])<<8 | uint(data[70])<<16 | uint(data[71])<<24
	h.proto_ids_size = uint(data[72]) | uint(data[73])<<8 | uint(data[74])<<16 | uint(data[75])<<24
	h.proto_ids_off = uint(data[76]) | uint(data[77])<<8 | uint(data[78])<<16 | uint(data[79])<<24
	h.field_ids_size = uint(data[80]) | uint(data[81])<<8 | uint(data[82])<<16 | uint(data[83])<<24
	h.field_ids_off = uint(data[84]) | uint(data[85])<<8 | uint(data[86])<<16 | uint(data[87])<<24
	h.method_ids_size = uint(data[88]) | uint(data[89])<<8 | uint(data[90])<<16 | uint(data[91])<<24
	h.method_ids_off = uint(data[92]) | uint(data[93])<<8 | uint(data[94])<<16 | uint(data[95])<<24
	h.class_defs_size = uint(data[96]) | uint(data[97])<<8 | uint(data[98])<<16 | uint(data[99])<<24
	h.class_defs_off = uint(data[100]) | uint(data[101])<<8 | uint(data[102])<<16 | uint(data[103])<<24
	h.data_size = uint(data[104]) | uint(data[105])<<8 | uint(data[106])<<16 | uint(data[107])<<24
	h.data_off = uint(data[108]) | uint(data[109])<<8 | uint(data[110])<<16 | uint(data[111])<<24
	return h
}

func checkAndroidversion(data byte) {
	// switch case
	switch data {
	case 0x39:
		fmt.Println("[+] Android version: 9")
	case 0x38:
		fmt.Println("[+] Android version: 8")
	case 0x37:
		fmt.Println("[+] Android version: 7")
	case 0x36:
		fmt.Println("[+] Android version: 6")
	case 0x35:
		fmt.Println("[+] Android version: 5")
	case 0x34:
		fmt.Println("[+] Android version: 4")
	case 0x33:
		fmt.Println("[+] Android version: 3")
	case 0x32:
		fmt.Println("[+] Android version: 2")
	case 0x31:
		fmt.Println("[+] Android version: 1")
	case 0x30:
		fmt.Println("[+] Android version: 0")
	default:
		fmt.Println("[+] Android version: unknown")
	}
}

// parse header function
func showHeader(h *header) {
	fmt.Printf("[+] Checksum: 0x%x\n", h.checksum)
	fmt.Printf("[+] Signature: %x\n", h.signature)
	fmt.Printf("[+] File size: 0x%x\n", h.file_size)
	fmt.Printf("[+] Header size: 0x%x\n", h.header_size)
	fmt.Printf("[+] Endian tag: 0x%x\n", h.endian_tag)
	fmt.Printf("[+] Link size: 0x%x\n", h.link_size)
	fmt.Printf("[+] Link offset: 0x%x\n", h.link_off)
	fmt.Printf("[+] Map offset: 0x%x\n", h.map_off)
	fmt.Printf("[+] String IDs size: 0x%x\n", h.string_ids_size)
	fmt.Printf("[+] String IDs offset: 0x%x\n", h.string_ids_off)
	fmt.Printf("[+] Type IDs size: 0x%x\n", h.type_ids_size)
	fmt.Printf("[+] Type IDs offset: 0x%x\n", h.type_ids_off)
	fmt.Printf("[+] Proto IDs size: 0x%x\n", h.proto_ids_size)
	fmt.Printf("[+] Proto IDs offset: 0x%x\n", h.proto_ids_off)
	fmt.Printf("[+] Field IDs size: 0x%x\n", h.field_ids_size)
	fmt.Printf("[+] Field IDs offset: 0x%x\n", h.field_ids_off)
	fmt.Printf("[+] Method IDs size: 0x%x\n", h.method_ids_size)
	fmt.Printf("[+] Method IDs offset: 0x%x\n", h.method_ids_off)
	fmt.Printf("[+] Class defs size: 0x%x\n", h.class_defs_size)
	fmt.Printf("[+] Class defs offset: 0x%x\n", h.class_defs_off)
	fmt.Printf("[+] Data size: 0x%x\n", h.data_size)
	fmt.Printf("[+] Data offset: 0x%x\n", h.data_off)
	fmt.Printf("===============================================================================\n")

}

// parse string_ids functions
func parse_string_ids(data []byte, offset uint) []string_id_item {
	string_data_offset := []string_id_item{}
	for i := 0; i < int(offset*4); i += 4 {
		string_off := little_endian(data[i : i+4])
		string_data_offset = append(string_data_offset, string_id_item{uint(string_off)})
	}
	return string_data_offset
}

func show_string(string_data_offset []string_id_item, ID uint) {
	offset := string_data_offset[ID].string_data_off
	string_size := uint(get_data_from_offset(data, offset, 1)[0])
	string_data := get_data_from_offset(data, offset+1, string_size)
	fmt.Printf("[+] String[%d] size: %s\n", ID, string_data)
}

// Adler-32 checksum calculate
func adler32(data []byte) uint32 {
	var a, b uint32 = 1, 0
	for i := 0; i < len(data); i++ {
		a = (a + uint32(data[i])) % 65521
		b = (b + a) % 65521
	}
	return (b << 16) | a
}

func uint2byteArr(data uint32) []byte {
	output := make([]byte, 4)
	binary.LittleEndian.PutUint32(output, uint32(data))
	return output
}

// main function
func main() {
	h := parseHeader(data)
	showHeader(h)

	Signdata := data[32:]
	// sha1 byte array
	sha1 := sha1.New()
	sha1.Write(Signdata)
	sha1sum := sha1.Sum(nil)
	fmt.Printf("[+] Actual Signature   : %x\n", sha1sum)
	fmt.Printf("[+] Current Signature  : %x\n", h.signature)
	// copy sha1sum to h.signature
	copy(h.signature[:], sha1sum)

	// change signature to sha1sum
	for i := 0; i < 20; i++ {
		data[i+12] = h.signature[i]
	}

	tmp_check_sum := adler32(data[12:])
	fmt.Printf("[+] Actual checksum : %x\n", tmp_check_sum)
	fmt.Printf("[+] Current checksum: %x\n\n\n", h.checksum)

	tmp2_check_sum := uint2byteArr(adler32(data[12:]))
	// copy tmp_check_sum to h.checksum
	for i := 0; i < 4; i++ {
		data[i+8] = tmp2_check_sum[i]
	}

	k := parseHeader(data)
	showHeader(k)

	// write data to file
	f, err := os.Create("output.dex")
	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()
	f.Write(data)
	fmt.Println("[+] File saved to output.dex")
}
