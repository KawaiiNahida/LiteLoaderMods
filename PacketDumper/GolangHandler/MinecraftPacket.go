package main

//#include "cgo.h"
//#cgo LDFLAGS: -Wl,--allow-multiple-definition
import "C"
import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
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

func HandleLoginPacket(data []byte, conid uint64) {
	fmt.Println("Recived Packet Size:", len(data))
	ident, client, auth, err := login.Parse(data)
	if err == nil {
		if auth.XBOXLiveAuthenticated {
			fmt.Println("The Client is XBOXLiveAuthenticated")
		} else {
			fmt.Println("The Client is Can't pass XBOXLiveAuth")
		}
		var identState string = "true"
		if identVaild := ident.Validate(); identVaild != nil {
			identState = identVaild.Error()
		}
		var clientState string = "true"
		if clientVaild := client.Validate(); clientVaild != nil {
			clientState = clientVaild.Error()
		}
		fmt.Printf("Parsed LoginPacket:\n  Vaild:%s\n  IdentName:%s\n  UUID:%s\n  XUID:%s\n", identState, ident.DisplayName, ident.Identity, ident.XUID)
		fmt.Printf("ClientInfo        :\n  Vaild:%s\n  DeviceID:%s\n", clientState, client.DeviceID)
		var conn MyConn
		conn.PlayerName = ident.DisplayName
		conn.PlayerXuid = ident.XUID
		conn.ClientInfo = client
		ConnList[conid] = &conn
	} else {
		fmt.Println("Failed to Parse Packet", err)
	}
}

func StartGamePacket(data []byte, conid uint64) {
	buf := bytes.NewBuffer(data)
	bufReader := protocol.NewReader(buf, 0)
	var pkt packet.StartGame
	pkt.Unmarshal(bufReader)
	var conn *MyConn = ConnList[conid]
	conn.GameData = minecraft.GameData{
		Difficulty:                   pkt.Difficulty,
		WorldName:                    pkt.WorldName,
		EntityUniqueID:               pkt.EntityUniqueID,
		EntityRuntimeID:              pkt.EntityRuntimeID,
		PlayerGameMode:               pkt.PlayerGameMode,
		PlayerPosition:               pkt.PlayerPosition,
		Pitch:                        pkt.Pitch,
		Yaw:                          pkt.Yaw,
		Dimension:                    pkt.Dimension,
		WorldSpawn:                   pkt.WorldSpawn,
		GameRules:                    pkt.GameRules,
		Time:                         pkt.Time,
		CustomBlocks:                 pkt.Blocks,
		Items:                        pkt.Items,
		PlayerMovementSettings:       pkt.PlayerMovementSettings,
		WorldGameMode:                pkt.WorldGameMode,
		ServerAuthoritativeInventory: pkt.ServerAuthoritativeInventory,
		Experiments:                  pkt.Experiments,
	}
	for _, item := range pkt.Items {
		if item.Name == "minecraft:shield" {
			conn.shieldID.Store(int32(item.RuntimeID))
		}
	}
}

func AddItemActorPacket(data []byte, conid uint64) {
	buf := bytes.NewBuffer(data)
	id := ConnList[conid].shieldID
	bufReader := protocol.NewReader(buf, id.Load())
	var pkt packet.AddItemActor
	pkt.Unmarshal(bufReader)
	//fmt.Printf("AddItemActorPacket %+v\n", pkt)
	if pkt.Item.Stack.NBTData["display"] != nil {
		itemName := pkt.Item.Stack.NBTData["display"].(map[string]interface{})["Name"]
		if itemName != nil {
			if strings.HasPrefix(itemName.(string), "playNote") {
				fmt.Println("PlayNote Item", itemName.(string)[8:])
				var pkt1 packet.LevelSoundEvent
				if itemName.(string)[8:] == "mopemope" {
					go func() {
						pkt1.SoundType = packet.SoundEventNote
						pkt1.Position = pkt.Position
						pkt1.DisableRelativeVolume = true

						pkt1.BabyMob = false

						note := [][2]int64{
							{15 + 5, 10},
							{15 + 3, 10},
							{15 + 1, 10},
							{15 + 5, 10},

							{15 + 5, 5},
							{15 + 6, 5},
							{15 + 5, 5},
							{15 + 4, 5},

							{15 + 5, 5},

							{15 + 5, 5},
							{15 + 1, 5},
						}
						for _, v := range note {
							pkt1.ExtraData = int32(v[0])
							sRead := PktToBytes(&pkt1, id)
							SendPkt(sRead, pkt1.ID(), ConnList[conid].PlayerName)
							time.Sleep(time.Duration(v[1]) * time.Second / 200)
						}

					}()
					fmt.Printf("Make and send LevelSoundPkt[noteblock] mopemope to Current Player:%s\n", ConnList[conid].PlayerName)
					return
				}
				i, err := strconv.Atoi(itemName.(string)[8:])
				if err != nil {
					return
				}
				pkt1.SoundType = packet.SoundEventNote
				pkt1.Position = pkt.Position
				pkt1.DisableRelativeVolume = true
				pkt1.ExtraData = int32(i)
				pkt1.BabyMob = false
				sRead := PktToBytes(&pkt1, id)
				ret := SendPkt(sRead, pkt1.ID(), ConnList[conid].PlayerName)
				fmt.Printf("Make and send LevelSoundPkt[noteblock] to Current Player:%s PktStatue:%d\n", ConnList[conid].PlayerName, ret)
			}
		}
	}
}
func InvAction(r protocol.IO, x *protocol.InventoryAction) {
	r.Varuint32(&x.SourceType)
	fmt.Println("styp", x.SourceType)
	switch x.SourceType {
	case protocol.InventoryActionSourceContainer, protocol.InventoryActionSourceTODO:
		r.Varint32(&x.WindowID)
	case protocol.InventoryActionSourceWorld:
		r.Varuint32(&x.SourceFlags)
	}
	r.Varuint32(&x.InventorySlot)
	r.ItemInstance(&x.OldItem)
	r.ItemInstance(&x.NewItem)
}
func InventoryTransactionPacket(data []byte) {
	buf := bytes.NewBuffer(data)
	bufReader := protocol.NewReader(buf, 1)
	var pkt packet.InventoryTransaction
	var length, transactionType uint32
	bufReader.Varint32(&pkt.LegacyRequestID)
	if pkt.LegacyRequestID != 0 {
		bufReader.Varuint32(&length)
		fmt.Println("len", length)
		pkt.LegacySetItemSlots = make([]protocol.LegacySetItemSlot, length)
		for i := uint32(0); i < length; i++ {
			protocol.SetItemSlot(bufReader, &pkt.LegacySetItemSlots[i])
		}
	}
	bufReader.Varuint32(&transactionType)
	bufReader.Varuint32(&length)
	fmt.Println("typ", transactionType)
	fmt.Println("len", length)
	bufReader.LimitUint32(length, 512)

	pkt.Actions = make([]protocol.InventoryAction, length)
	for i := uint32(0); i < length; i++ {
		// Each InventoryTransaction packet has a list of actions at the start, with a transaction data object
		// after that, depending on the transaction type.
		InvAction(bufReader, &pkt.Actions[i])
	}
	switch transactionType {
	case packet.InventoryTransactionTypeNormal:
		pkt.TransactionData = &protocol.NormalTransactionData{}
	case packet.InventoryTransactionTypeMismatch:
		pkt.TransactionData = &protocol.MismatchTransactionData{}
	case packet.InventoryTransactionTypeUseItem:
		pkt.TransactionData = &protocol.UseItemTransactionData{}
	case packet.InventoryTransactionTypeUseItemOnEntity:
		pkt.TransactionData = &protocol.UseItemOnEntityTransactionData{}
	case packet.InventoryTransactionTypeReleaseItem:
		pkt.TransactionData = &protocol.ReleaseItemTransactionData{}
	default:
		bufReader.UnknownEnumOption(transactionType, "inventory transaction type")
	}
	pkt.TransactionData.Unmarshal(bufReader)
	fmt.Printf("InventoryTransaction %v\n", pkt)
}
func ItemStackResponse(data []byte) {
	buf := bytes.NewBuffer(data)
	bufReader := protocol.NewReader(buf, 1)
	var pkt packet.ItemStackResponse
	pkt.Unmarshal(bufReader)
	fmt.Printf("ItemStackResp %+v\n", pkt)
}
func ItemStackRequest(data []byte) {
	buf := bytes.NewBuffer(data)
	bufReader := protocol.NewReader(buf, 1)
	var pkt packet.ItemStackRequest
	pkt.Unmarshal(bufReader)
	fmt.Printf("ItemStackReq %+v\n", pkt)
}
func LevelSoundEventPacket(data []byte) {
	buf := bytes.NewBuffer(data)
	bufReader := protocol.NewReader(buf, 1)
	var pkt packet.LevelSoundEvent
	pkt.Unmarshal(bufReader)
	if pkt.SoundType == packet.SoundEventNote {
		fmt.Printf("NoteBlock %d\n", pkt.ExtraData)
	}
	//fmt.Printf("LevelSoundEventPacket %+v\n", pkt)
}

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
	// if pktId == 123 {
	// 	LevelSoundEventPacket(data[1:])
	// 	return C.makeReturn(C.CString(""), -1)
	// }
	if pktId == 11 {
		StartGamePacket(data[1:], conid)
		return C.makeReturn(C.CString(""), -1)
	}
	if pktId == 148 {
		ItemStackResponse(data[1:])
		return C.makeReturn(C.CString(""), -1)
	}
	// if pktId == 15 {
	// 	AddItemActorPacket(data[1:], conid)
	// 	return C.makeReturn(C.CString(""), -1)
	// }
	return C.makeReturn(C.CString(""), -1)
}

//export InPakcetHandler
func InPakcetHandler(pkt *C.char, size uint64, pktId int32, pktName *C.char, conid uint64) C.externApiRet {
	//return C.makeReturn(C.CString(""), -1)
	csize := C.int(size)
	data := C.GoBytes(unsafe.Pointer(pkt), csize)
	if pktId == 1 {
		HandleLoginPacket(data[8:], conid)
		return C.makeReturn(C.CString(""), -1)
	}
	// if pktId == 30 {
	// 	fmt.Println(data)
	// 	InventoryTransactionPacket(data[1:])
	// 	return C.makeReturn(C.CString(""), -1)
	// }
	if pktId == 147 {
		ItemStackRequest(data[1:])
		return C.makeReturn(C.CString(""), -1)
	}
	return C.makeReturn(C.CString(""), -1)
}
