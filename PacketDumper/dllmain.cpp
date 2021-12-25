#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <time.h>
#include <HookAPI.h>

#include <LLAPI.h>

#include <fstream>
#include <iostream>
#include <string>
#include <memory>
#include <iomanip>
#include <functional>
#include <filesystem>

#include <LoggerAPI.h>

#include <MC/Level.hpp>
#include <MC/Actor.hpp>
#include <MC/Mob.hpp>
#include <MC/Player.hpp>

#include <MC/Packet.hpp>
#include <MC/Minecraft.hpp>
#include <MC/BinaryStream.hpp>
#include <MC/WebToken.hpp>
#include <MC/Certificate.hpp>
#include <MC/ExtendedCertificate.hpp>

#include <MC/NetworkPeer.hpp>
#include <MC/NetworkIdentifier.hpp>
#include <MC/NetworkHandler.hpp>

#include <GlobalServiceAPI.h>

Logger logger("PktDumper");
class EasyPkt : public Packet {
public:
	string_view view;
	MinecraftPacketIds pktid;
	EasyPkt(string_view sv,int pid)
		: view(sv), pktid(MinecraftPacketIds(pid)){
		incompressible = true;
	}
	inline virtual ~EasyPkt() {
	}
	virtual MinecraftPacketIds getId() const {
		return pktid;
	}
	virtual std::string getName() const {
		return "EasyPkt";
	}
	virtual void write(BinaryStream& bs) const {
		bs.getRaw().append(view);
	}
	virtual void dummyread() {
	}
	virtual bool disallowBatching() const {
		return false;
	}
private:
	virtual StreamReadResult _read(ReadOnlyBinaryStream&) {
		return StreamReadResult(1);
	}
};
void hexDumper(std::string& data) {
	int i, j;
	unsigned int offset = 0;
	int total_row = data.length() / 16;
	int left_data_len = data.length() % 16;
	/* print data_len / 16 */
	for (j = 0; j < total_row; j++) {
		std::cout << std::hex << std::setw(8) << std::setfill('0') << offset;
		std::cout << "   ";
		for (i = 0; i < 16; i++) {
			int dt = (int)data[j * 16 + i];
			if (dt > 0xffffff00) {
				dt = dt - 0xffffff00;
			}
			std::cout << std::hex << std::setw(2) << std::setfill('0') << dt;
			std::cout << " ";
		}

		for (i = 0; i < 16; i++) {
			if ((data[j * 16 + i] < 0x20) || (data[j * 16 + i] > 0x7F)) {
				std::cout << ".";
			}
			else {
				std::cout << data[j * 16 + i];
			}
		}
		offset += 16;
		std::cout << std::endl;
	}
	/* print data_len % 16 */
	if (left_data_len > 0) {
		std::cout << std::hex << std::setw(8) << std::setfill('0') << offset;
		std::cout << "   ";
		for (i = 0; i < left_data_len; i++) {
			int dt = (int)data[j * 16 + i];
			if (dt > 0xffffff00) {
				dt = dt - 0xffffff00;
			}
			std::cout << std::hex << std::setw(2) << std::setfill('0') << dt;
			std::cout << " ";
		}
		for (i = 0; i < 16 - left_data_len; i++) {
			std::cout << "   ";
		}
		for (i = 0; i < left_data_len; i++) {
			if ((data[total_row * 16 + i] < 0x20) || (data[total_row * 16 + i] > 0x7F)) {
				std::cout << ".";
			}
			else {
				std::cout << data[j * 16 + i];
			}
		}
		std::cout << std::endl;
	}
	return;
}
void hexDumper(std::stringstream& ss, std::string& data) {
	int i, j;
	unsigned int offset = 0;
	int total_row = data.length() / 16;
	int left_data_len = data.length() % 16;
	/* print data_len / 16 */
	for (j = 0; j < total_row; j++) {
		ss << std::hex << std::setw(8) << std::setfill('0') << offset;
		ss << "   ";
		for (i = 0; i < 16; i++) {
			int dt = (int)data[j * 16 + i];
			if (dt > 0xffffff00) {
				dt = dt - 0xffffff00;
			}
			ss << std::hex << std::setw(2) << std::setfill('0') << dt;
			ss << " ";
		}

		for (i = 0; i < 16; i++) {
			if ((data[j * 16 + i] < 0x20) || (data[j * 16 + i] > 0x7F)) {
				ss << ".";
			}
			else {
				ss << data[j * 16 + i];
			}
		}
		offset += 16;
		ss << std::endl;
	}
	/* print data_len % 16 */
	if (left_data_len > 0) {
		ss << std::hex << std::setw(8) << std::setfill('0') << offset;
		ss << "   ";
		for (i = 0; i < left_data_len; i++) {
			int dt = (int)data[j * 16 + i];
			if (dt > 0xffffff00) {
				dt = dt - 0xffffff00;
			}
			ss << std::hex << std::setw(2) << std::setfill('0') << dt;
			ss << " ";
		}
		for (i = 0; i < 16 - left_data_len; i++) {
			ss << "   ";
		}
		for (i = 0; i < left_data_len; i++) {
			if ((data[total_row * 16 + i] < 0x20) || (data[total_row * 16 + i] > 0x7F)) {
				ss << ".";
			}
			else {
				ss << data[j * 16 + i];
			}
		}
		ss << std::endl;
	}
	return;
}

CRITICAL_SECTION outp;
struct externApiRet {
	long long size;
	char* pkt;
};

int SendNetworkPacket(char* PlayerName, char* PktContent, int PktSize, int PktId) {
	Level* mcLevel = Global<Level>;
	if (mcLevel == nullptr) {
		//printf("Level* is nullptr\n");
		return -1;
	}
	Player* pl = nullptr;
	auto PlayerList = Level::getAllPlayers();
	for (auto sp : PlayerList){
		if (ExtendedCertificate::getIdentityName(*sp->getCertificate()) == PlayerName) {
			pl = sp;
			break;
		}
	}
	if (pl == nullptr) {
		//printf("Player* is nullptr\n");
		return -2;
	}	
	string dat;
	dat.resize(PktSize);
	memcpy_s(dat.data(), PktSize, PktContent, PktSize);
	EasyPkt pkt(dat,PktId);
	//printf("PacketCreated\n");
	pl->sendNetworkPacket(pkt);
	return 0;
}
externApiRet(*OutPakcetHandler)(const char* pkt, size_t pktsize, int pktId, const char* pktName, size_t nwIdent) = nullptr;
externApiRet(*InPakcetHandler)(const char* pkt, size_t pktsize, int pktId, const char* pktName, size_t nwIdent) = nullptr;
void(*SetSendPktFunc)(int(*)(char* PlayerName, char* PktContent, int PktSize, int PktId)) = nullptr;
extern "C" {
	_declspec(dllexport) void onPostInit() {
		InitializeCriticalSection(&outp);
		if (std::filesystem::exists(std::filesystem::path(".\\PacketHandler.dll"))) {
			auto lib = LoadLibrary(L".\\PacketHandler.dll");
			if (lib) {
				std::cout << "[NetworkDumper][Loading] Loaded .\\PacketHandler.dll\n";
				OutPakcetHandler = (externApiRet(*)(const char* pkt, size_t pktsize, int pktId, const char* pktName, size_t nwIdent))GetProcAddress(lib, "OutPakcetHandler");
				InPakcetHandler = (externApiRet(*)(const char* pkt, size_t pktsize, int pktId, const char* pktName, size_t nwIdent))GetProcAddress(lib, "InPakcetHandler");
				SetSendPktFunc = (void(*)(int(*)(char* PlayerName, char* PktContent, int PktSize, int PktId)))GetProcAddress(lib, "setSendPlayerPacketHandler");
				std::cout << "[NetworkDumper][Loading] ExternApi:OutPakcetHandler " << OutPakcetHandler << std::endl
					<< "[NetworkDumper][Loading] ExternApi:InPakcetHandler " << InPakcetHandler << std::endl
					<< "[NetworkDumper][Loading] ExternApi:setSendPlayerPacketHandler " << SetSendPktFunc << std::endl;
				SetSendPktFunc(SendNetworkPacket);
			}
			std::cout << "[NetworkDumper][Init] Loaded " __TIMESTAMP__ "\n";
		}
	}
	//extern __declspec(dllexport) void HandleLoginPacket(char* inData, long long);
}
#define CaptureDebugger         \
		if (IsDebuggerPresent())\
            __debugbreak();


THook(void**,
	"?getEncryptedPeerForUser@NetworkHandler@@QEAA?AV?$weak_ptr@VEncryptedNetworkPeer@@@std@@AEBVNetworkIdentifier@@@Z",
	void* self, void** ret, void* id) {
	ret[0] = ret[1] = 0;
	return ret;
}


TInstanceHook(
	NetworkPeer::DataStatus,
	"?receivePacket@Connection@NetworkHandler@@QEAA?AW4DataStatus@NetworkPeer@@AEAV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AEBV?$shared_ptr@V?$time_point@Usteady_clock@chrono@std@@V?$duration@_JU?$ratio@$00$0DLJKMKAA@@std@@@23@@chrono@std@@@6@@Z",
	NetworkHandler::Connection, std::string& data) {
	auto status = original(this, data);

	if (status == NetworkPeer::DataStatus::OK) {
		auto stream = ReadOnlyBinaryStream(data, 0i64);
		auto pktid = stream.getUnsignedVarInt();
		auto pkthash = do_hash(data.c_str());
		auto pkttime = _time64(0);
		Packet* pkt;
		SymCall(
			"?createPacket@MinecraftPackets@@SA?AV?$shared_ptr@VPacket@@@std@@W4MinecraftPacketIds@@@Z",
			void*, Packet**, int)(&pkt, pktid);
		auto pktname = pkt->getName().c_str();
		if (InPakcetHandler != nullptr) {
			auto externReturn = InPakcetHandler(data.c_str(), data.length(), pktid, pktname, ((NetworkIdentifier*)this)->getHash());
			if (externReturn.size == -1) {
				return status;
			}
		}
		logger.debug("[Network][I][{}]\tLength:{}\tPkt:{}({})", pkttime, data.length(), pkt->getName(), pkt->getId());//std::cout << "[Network][I][" << pkttime << "]\tLength:" << data.length() << "\tPktID:" << pktid << "[" << pktname << "]\tHash:" << pkthash << "\n";
		//hexDumper(ss, data);
		EnterCriticalSection(&outp);
		std::ofstream out("NetworkPacket.txt", std::ios::out | std::ios::app);
		out << "[Network][I][" << pkttime << "]\tLength:" << data.length() << "\tPktID:" << pktid << "[" << pktname << "]\tHash:" << pkthash << "\n";
		out.flush();
		out.close();
		char* binaryPacket = new char[128];
		sprintf_s(binaryPacket, 128, "packet/INwPkt-%d-%llu-%lld.bin", pktid, pkthash, pkttime);
		std::ofstream out2(binaryPacket, std::ios::out | std::ios::binary | std::ios::trunc);
		out2 << data;
		out2.flush();
		out2.close();
		LeaveCriticalSection(&outp);
		CaptureDebugger
	}
	return status;
}
TClasslessInstanceHook(
	void,
	"?_sendInternal@NetworkHandler@@AEAAXAEBVNetworkIdentifier@@AEBVPacket@@AEBV?$basic_string@DU?$char_traits@D@std@@"
	"V?$allocator@D@2@@std@@@Z",
	NetworkIdentifier const& id, Packet const& pkt, std::string& data) {

	auto stream = ReadOnlyBinaryStream(data, 0i64);
	auto pktid = stream.getUnsignedVarInt();
	auto pkthash = do_hash(data.c_str());
	auto pkttime = _time64(0);
	if (OutPakcetHandler != nullptr) {
		auto externReturn = OutPakcetHandler(data.c_str(), data.length(), pktid, pkt.getName().c_str(), id.getHash());
		if (externReturn.size >= 0) {
			data = externReturn.pkt;
			return original(this, id, pkt, data);
		}
		if (externReturn.size == -1) {
			return original(this, id, pkt, data);
		}
	}
	std::cout << "[Network][O][" << pkttime << "]\tLength:" << data.length() << "\tPktID:" << pktid << "[" << pkt.getName() << "]\tHash:" << pkthash << "\n";
	EnterCriticalSection(&outp);
	std::ofstream out("NetworkPacket.txt", std::ios::out | std::ios::app);
	out << "[Network][O][" << pkttime << "]\tLength:" << data.length() << "\tPktID:" << pktid << "[" << pkt.getName() << "]\tHash:" << pkthash << "\n";
	out.flush();
	out.close();
	char* binaryPacket = new char[128];
	sprintf_s(binaryPacket, 128, "packet/ONwPkt-%d-%llu-%lld.bin", pktid, pkthash, pkttime);
	std::ofstream out2(binaryPacket, std::ios::out | std::ios::binary | std::ios::trunc);
	out2 << data;
	out2.flush();
	out2.close();
	LeaveCriticalSection(&outp);
	original(this, id, pkt, data);
}