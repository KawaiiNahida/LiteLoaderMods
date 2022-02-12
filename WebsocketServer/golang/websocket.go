package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"
	"unsafe"

	"github.com/gorilla/websocket"
)

//#include "cgoMain.h"
//#cgo LDFLAGS: -Wl,--allow-multiple-definition
import "C"

var WebsocketConnections map[int64]*websocket.Conn
var WebsocketUpgrade = websocket.Upgrader{} // use default options
var enableLog bool = true

func LogInfo(str string) {
	if enableLog {
		C.Log(0, C.CString(str))
	}
}
func LogError(str string) {
	if enableLog {
		C.Log(2, C.CString(str))
	}
}
func ContainsValue(m map[int64]*websocket.Conn, value *websocket.Conn) bool {
	for _, v := range m {
		if v == value {
			return true
		}
	}
	return false
}
func FindValue(m map[int64]*websocket.Conn, key int64) (bool, *websocket.Conn) {
	for k, v := range m {
		if k == key {
			return true, v
		}
	}
	return false, nil
}
func FindKey(m map[int64]*websocket.Conn, value *websocket.Conn) (bool, int64) {
	for k, v := range m {
		if v == value {
			return true, k
		}
	}
	return false, 0
}
func HttpHandler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		err := recover()
		if err != nil {
			LogError(fmt.Sprintf("%v", err))
		}
	}()
	conn, err := WebsocketUpgrade.Upgrade(w, r, nil)
	if err != nil {
		//log.Print("upgrade:", err)
		return
	}
	conn.SetCloseHandler(func(code int, text string) error {
		LogError("A Connection Closed <" + strconv.Itoa(code) + ">:" + text)
		return nil
	})
	LogInfo("WS NewConnection Created > " + conn.RemoteAddr().String())
	tmpTimestamp := time.Now().UnixNano()
	if ok, _ := FindValue(WebsocketConnections, tmpTimestamp); ok {
		conn.Close()
	}
	WebsocketConnections[time.Now().UnixNano()] = conn
	defer func() {
		LogInfo("WS Connection Closed " + conn.RemoteAddr().String())
		ok, k := FindKey(WebsocketConnections, conn)
		if ok {
			delete(WebsocketConnections, k)
		}
		_ = conn.Close()
	}()
	for {
		mt, message, err := conn.ReadMessage()
		if err != nil {
			//log.Println("read:", err)
			// if websocket.IsCloseError(err) || websocket.IsUnexpectedCloseError(err) {
			// 	//log.Println("Connection Closed:", err)
			// }

			return
		}
		conn.SetCloseHandler(nil)

		go WebsocketHandler(conn, string(message), mt)

	}
}

//export GlobalSend
func GlobalSend(uniqueid int64, cmsg *C.char) {

	found, conn := FindValue(WebsocketConnections, uniqueid)
	if found {
		_ = conn.WriteMessage(websocket.TextMessage, []byte(C.GoString(cmsg)))
	} else {
		LogError("Error Failed to Find target WsConn")
	}
}

//export GlobalClosed
func GlobalClosed(uniqueid int64, closed int, cmsg *C.char) {
	found, conn := FindValue(WebsocketConnections, uniqueid)
	if found {
		_ = conn.WriteMessage(closed, []byte(C.GoString(cmsg)))
		_ = conn.Close()
	} else {
		LogInfo("Error Failed to Find target WsConn")
	}
}

//export GlobalBroadcast
func GlobalBroadcast(cmsg *C.char) {
	msg := C.GoString(cmsg)
	Broadcast(msg)
}
func Broadcast(msg string) {
	for _, v := range WebsocketConnections {
		_ = v.WriteMessage(websocket.TextMessage, []byte(msg))
	}
}

//export setMessageHandler
func setMessageHandler(p unsafe.Pointer) {
	C.SetMsgHandler(p)
}

//export setLogger
func setLogger(p unsafe.Pointer) {
	C.SetLogger(p)
}
func WebsocketHandler(conn *websocket.Conn, msg string, msgtype int) {

	//LogInfo(fmt.Sprintf("WS [%s]:<%d>> %s", conn.RemoteAddr().String(), msgtype, msg))
	ok, key := FindKey(WebsocketConnections, conn)
	if ok {
		C.RunMsgHandler((C.longlong)(key), C.CString(msg))
	}
}

//export Init
func Init(path *C.char, addr *C.char, elog bool) {
	enableLog = elog
	go func() {
		gaddr := C.GoString(addr)
		gpath := C.GoString(path)
		WebsocketConnections = make(map[int64]*websocket.Conn)
		http.HandleFunc(gpath, HttpHandler)
		LogInfo("LLWebsocketGo Listening on " + gaddr + gpath)
		log.Fatal(http.ListenAndServe(gaddr, nil))
	}()
}
func main() {
	//MyLog("asd", "asd", "aaa")
	//Init(C.CString("/echo"), C.CString("0.0.0.0:8081"))
}
