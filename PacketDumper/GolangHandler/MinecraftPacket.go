package main

//#include "cgo.h"
//#cgo LDFLAGS: -Wl,--allow-multiple-definition
import "C"
import (
	"bytes"
	"log"
	"os"
	"reflect"
	"runtime/debug"
	"unsafe"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"go.uber.org/atomic"
)

type MyConn struct {
	GameData   minecraft.GameData
	shieldID   atomic.Int32
	PlayerName string
	PlayerXuid string
	ClientInfo login.ClientData
}

var ConnList map[uint64]*MyConn = make(map[uint64]*MyConn)

func main() {}

func SendPkt(data []byte, pktId uint32, playerName string) int {
	return int(C.RunSendPlayerPacket(C.CString(playerName), (*C.char)(C.CBytes(data)), C.int(len(data)), C.int(pktId)))
}
func PktToBytes(pkt interface{ Marshal(w *protocol.Writer) }, id atomic.Int32) (data []byte) {
	realBuf := bytes.NewBuffer([]byte(""))
	bufWriter := protocol.NewWriter(realBuf, id.Load())
	pkt.Marshal(bufWriter)
	data = make([]byte, realBuf.Len())
	realBuf.Read(data)
	return
}

//export setSendPlayerPacketHandler
func setSendPlayerPacketHandler(p unsafe.Pointer) {
	C.SetSendPlayerPacket(p)
}

//export OutPakcetHandler
func OutPakcetHandler(pkt *C.char, size uint64, pktId int32, pktName *C.char, conid uint64) C.externApiRet {
	//return C.makeReturn(C.CString(""), -1)
	csize := C.int(size)
	data := C.GoBytes(unsafe.Pointer(pkt), csize)
	//fmt.Printf("Out(Size:%d) %d %s\n", size, pktId, C.GoString(pktName))
	for _, v := range []int32{2, 6, 7, 39, 40, 58, 63, 111, 123, 136, 174} {
		if pktId == v {
			return C.makeReturn(C.CString(""), -1)
		}
	}
	UnmarshalPackets(uint32(pktId), data[1:], "Out")
	return C.makeReturn(C.CString(""), -1)
}
func UnmarshalPackets(PktId uint32, data []byte, perfix string) {
	buf := bytes.NewBuffer(data)
	bufReader := protocol.NewReader(buf, 0)
	var pkt packet.Packet
	pkFunc, ok := Packets[PktId]
	if !ok {
		pkt = &packet.Unknown{PacketID: PktId}
	}
	pkt = pkFunc()
	defer func() {
		err := recover()
		if err != nil {
			log.Println("Failed to decode Packet", err)
			log.Printf("%+v\n", pkt)
			debug.PrintStack()
		}
	}()
	pkt.Unmarshal(bufReader)

	log.Printf("%s [%s][%d] %+v\n", perfix, reflect.TypeOf(pkt).String()[8:], PktId, pkt)
}

func UnmarshalItemStackRequest(data []byte, perfix string) {
	log.Printf("%s %+v\n", perfix, data)
	buf := bytes.NewBuffer(data)
	bufReader := protocol.NewReader(buf, 0)
	var pkt packet.ItemStackRequest
	defer func() {
		err := recover()
		if err != nil {
			log.Println("Failed to decode Packet", err)
			log.Printf("%+v\n", pkt)
			debug.PrintStack()
		}
	}()
	pkt.Unmarshal(bufReader)

	log.Printf("%s [%s][%d] %+v\n", perfix, reflect.TypeOf(pkt).String()[8:], pkt.ID(), pkt)
}

//export InPakcetHandler
func InPakcetHandler(pkt *C.char, size uint64, pktId int32, pktName *C.char, conid uint64) C.externApiRet {
	//return C.makeReturn(C.CString(""), -1)
	//fmt.Printf("In (Size:%d) %d %s\n", size, pktId, C.GoString(pktName))
	csize := C.int(size)
	data := C.GoBytes(unsafe.Pointer(pkt), csize)
	for _, v := range []int32{135, 144, 175} {
		if pktId == v {
			return C.makeReturn(C.CString(""), -1)
		}
	}
	if pktId == 147 {
		UnmarshalItemStackRequest(data[4:], "In")
	} else {
		UnmarshalPackets(uint32(pktId), data[1:], "In ")
	}
	return C.makeReturn(C.CString(""), -1)
}

func init() {
	//set log to file
	f, err := os.OpenFile("PacketDumperGo.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	//log.SetOutput(f)
}
