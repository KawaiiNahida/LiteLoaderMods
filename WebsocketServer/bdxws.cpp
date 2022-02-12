#include <iostream>
#include <time.h>
#include <fstream>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <HookAPI.h>
#include <LLAPI.h>
#include <GlobalServiceAPI.h>
#include <EventAPI.h>

#include <MC/Actor.hpp>
#include <MC/Mob.hpp>
#include <MC/Player.hpp>
#include <MC/Level.hpp>
#include <MC/ActorDamageSource.hpp>

#include "./json.hpp"

#include <openssl/md5.h>
#include "./encrypt_helper.h"
#include "MemoryModule.h"
#include "resource.h"
#pragma warning(disable:4996)
#pragma comment (lib,"Crypt32.lib")

Logger logger("LLWS");

using namespace std;
using json = nlohmann::json;
inline HMODULE DllMainAddr;
using string = std::string;
string& replaceAll(string& str, const string& old_value, const string& new_value) {
	while (true) {
		string::size_type pos(0);
		if ((pos = str.find(old_value)) != string::npos)
			str.replace(pos, old_value.length(), new_value);
		else
			break;
	}
	return str;
}
inline void BraceRemove(std::string& str) {
	replaceAll(str, "{", "{{");
	replaceAll(str, "}", "}}");
}

namespace GolangBridge {
	typedef void(*SetMsgHandler)(void (*)(__int64, char*));
	typedef void(*SetLogger)(void (*)(int, char*));
	typedef void(*GolangWSInit)(const char*, const char*, bool);
	typedef void(*GlobalSend)(__int64, const char*);
	typedef void(*GlobalClosed)(__int64, int, const char*);
	typedef void(*GlobalBroadcast)(const char*);
	namespace func {
		SetMsgHandler FnSetMsgHandler;
		GolangWSInit FnGolangWSInit;
		GlobalSend FnGlobalSend;
		GlobalClosed FnGlobalClosed;
		GlobalBroadcast FnGlobalBroadcast;
		SetLogger FnSetLogger;
	}
	void InitGoBridge() {

		HRSRC DLL = ::FindResource(DllMainAddr, MAKEINTRESOURCE(101), L"DLL");
		unsigned int ResSize = ::SizeofResource(DllMainAddr, DLL);
		HGLOBAL ResData = ::LoadResource(DllMainAddr, DLL);
		void* ResDataRef = ::LockResource(ResData);
		HMEMORYMODULE memoryDll = MemoryLoadLibrary(ResDataRef, ResSize);
		//cout << ResSize << ResData << ResDataRef << endl;
		sizeof(void*);
		func::FnSetMsgHandler = (SetMsgHandler)MemoryGetProcAddress(memoryDll, "setMessageHandler");
		func::FnSetLogger = (SetLogger)MemoryGetProcAddress(memoryDll, "setLogger");
		func::FnGolangWSInit = (GolangWSInit)MemoryGetProcAddress(memoryDll, "Init");
		func::FnGlobalSend = (GlobalSend)MemoryGetProcAddress(memoryDll, "GlobalSend");
		func::FnGlobalClosed = (GlobalClosed)MemoryGetProcAddress(memoryDll, "GlobalClosed");
		func::FnGlobalBroadcast = (GlobalBroadcast)MemoryGetProcAddress(memoryDll, "GlobalBroadcast");
		
		//cout << "---------------Init Golang Bridge---------------" << endl
		//	<< "[GoBridge]" << "Init\t\t\t" << func::FnGolangWSInit << endl
		//	<< "[GoBridge]" << "setMessageHandler\t" << func::FnSetMsgHandler << endl
		//	<< "[GoBridge]" << "GlobalSend\t\t" << func::FnGlobalSend << endl
		//	<< "[GoBridge]" << "GlobalBroadcast\t" << func::FnGlobalBroadcast << endl
		//	<< "[GoBridge]" << "GlobalClosed\t\t" << func::FnGlobalClosed << endl
		//	<< "--------------- Go Bridge Inited ---------------" << endl;
	}
}
//127.0.0.1:8080/mc
namespace config {
	string wsaddr = "0.0.0.0:8080";
	string endpoint = "/mc";
	string wspasswdbase = "passwd";
	string encrypt_mode_str = "aes256";
	bool enableLog = true;
	enum encrypt_type {
		none = 0,
		aes_cbc_pck7padding = 1,
		aes_cbc_pkcs7padding = 2,
	};
	int encrypt_mode = config::encrypt_type::none;
}
//get systime with sec
inline string gettime() {
	time_t rawtime;
	tm* LocTime;
	char timestr[20];
	time(&rawtime);
	LocTime = localtime(&rawtime);

	strftime(timestr, 20, "%Y-%m-%d %H:%M:%S", LocTime);
	return string(timestr);
}

void loadconf() {
	ifstream in("plugins/LiteLoader/websocket/config.json");
	if (in.fail()) {
		cout << "> ErrorOpen LLWebsocket Config File \"plugins/LiteLoader/websocket/config.json\"" << endl;
		Sleep(100000);
		exit(1);
	}
	else {
		ostringstream tmp;
		tmp << in.rdbuf();
		string data = tmp.str();
		json wsconfig = nullptr;
		try {
			wsconfig = json::parse(data);
		}
		catch (json::parse_error& e) {
			logger.error << "Config Error: " << e.what();
			Sleep(100000);
			exit(1);
		}
		if (wsconfig["enableLog"].is_boolean())
			config::enableLog = wsconfig["enableLog"];
		else
			logger.warn("loadconf", "config::enableLog not found, use \"true\" instead");

		if (wsconfig["wsaddr"].is_string())
			config::wsaddr = wsconfig["wsaddr"];
		else
			logger.warn("loadconf", "config::wsaddr not found, use \"0.0.0.0:8080\" instead");

		if (wsconfig["endpoint"].is_string())
			config::endpoint = wsconfig["endpoint"];
		else
			logger.warn("loadconf", "endpoint not found, use default value instead");

		if (wsconfig["encrypt"].is_string()) {
			config::encrypt_mode_str = wsconfig["encrypt"];
			std::transform(config::encrypt_mode_str.begin(), config::encrypt_mode_str.end(),config::encrypt_mode_str.begin(), ::tolower);
			if (config::encrypt_mode_str == "null" || config::encrypt_mode_str == "none") {
				config::encrypt_mode = config::encrypt_type::none;
				logger.warn("Config", "You're running in unsafe, everyone may execute command without permission");
			}
			else if ((config::encrypt_mode_str == "aes_cbc_pck7padding") || (config::encrypt_mode_str == "aes/cbc/pck7padding")) {
				if (!wsconfig["wspasswd"].is_null()) {
					config::encrypt_mode = config::encrypt_type::aes_cbc_pck7padding;
					config::wspasswdbase = MD5(wsconfig["wspasswd"]);
				}
				else {
					logger.error("loadconf", "Running in aes/cbc/pck7padding, but passwd not found!!!!!!!!!!");
					Sleep(100000);
					exit(1);
				}
			}
			else if ((config::encrypt_mode_str == "aes_cbc_pkcs7padding") || (config::encrypt_mode_str == "aes/cbc/pkcs7padding")) {
				if (!wsconfig["wspasswd"].is_null()) {
					config::encrypt_mode = config::encrypt_type::aes_cbc_pkcs7padding;
					config::wspasswdbase = MD5(wsconfig["wspasswd"]);
				}
				else {
					logger.error("loadconf", "Running in aes/cbc/pck7padding, but passwd not found!!!!!!!!!!");
					Sleep(100000);
					exit(1);
				}
			}
			else {
				logger.error("loadconf", "No Such Encrypt Method!!!!!!!!!!");
				Sleep(100000);
				exit(1);
			}

		}
		else {
			logger.error("loadconf", "encrypt mode not found!!!!!!!!!!");
			Sleep(100000);
			exit(1);
		}

	}
}




inline string& repall(string& str, const string& olds, const string& news)
{
	string::size_type pos = 0;
	while ((pos = str.find(olds)) != string::npos)
	{
		str = str.replace(str.find(olds), olds.length(), news);
	}
	return str;
}

inline void wsinitmsg() {
	//cout << "__          __  _     _____            _        _" << endl;
	//cout << "\\ \\        / / | |   / ____|          | |      | |" << endl;
	//cout << " \\ \\  /\\  / /__| |__| (___   ___   ___| | _____| |_" << endl;
	//cout << "  \\ \\/  \\/ / _ \\ '_ \\\\___ \\ / _ \\ / __| |/ / _ \\ __|" << endl;
	//cout << "   \\  /\\  /  __/ |_) |___) | (_) | (__|   <  __/ |_" << endl;
	//cout << "    \\/  \\/ \\___|_.__/_____/ \\___/ \\___|_|\\_\\___|\\__|" << endl;
	logger.info << " BDSWebsocket Loaded! Acthor: WangYneos & YQ." << Logger::endl;
	logger.info << "[" << gettime() << " Init][WSI] [WS Port     ] " << config::wsaddr << Logger::endl;
	logger.info << "[" << gettime() << " Init][WSI] [Base Passwd ] " << config::wspasswdbase << Logger::endl;
	logger.info << "[" << gettime() << " Init][WSI] [Encrypt Mode] " << config::encrypt_mode_str << Logger::endl;
	logger.info << "[" << gettime() << " Init][WSI] [End Point   ] " << config::endpoint << Logger::endl;
	logger.info << "[" << gettime() << " Init][WSI] [BuildDate   ] " << __TIMESTAMP__ << Logger::endl;
	//cout << "[" << gettime() << " Init][WSI] This Is A PreRelease Version!!!" << endl;
}

/// <summary>
/// Encrypt the packet using the key and method that config provide
/// </summary>
/// <param name="str">the packet to send</param>
/// <param name="connection">the ws connection ptr</param>
inline void encrypt_send(const string& str, __int64 connection) {
	if (config::encrypt_mode == config::encrypt_type::aes_cbc_pck7padding) {
		json j =
		{
			{"type", "encrypted"},
			{
				"params", {
					{"mode", "aes_cbc_pck7padding"},
					{"raw", base64_aes_cbc_encrypt(str, (unsigned char*)config::wspasswdbase.substr(0, 16).c_str(), (unsigned char*)config::wspasswdbase.substr(16, 16).c_str())}
				}
			}
		};
		GolangBridge::func::FnGlobalSend(connection, j.dump().c_str());
		return;
	}

	if (config::encrypt_mode == config::encrypt_type::aes_cbc_pkcs7padding) {
		json j =
		{
			{"type", "encrypted"},
			{
				"params", {
					{"mode", "aes_cbc_pkcs7padding"},
					{"raw", base64_aes_cbc_encrypt(str, (unsigned char*)config::wspasswdbase.substr(0, 16).c_str(), (unsigned char*)config::wspasswdbase.substr(16, 16).c_str())}
				}
			}
		};
		GolangBridge::func::FnGlobalSend(connection, j.dump().c_str());
		return;
	}

	if (config::encrypt_mode == config::encrypt_type::none) {
		GolangBridge::func::FnGlobalSend(connection, str.c_str());
		return;
	}

}

/// <summary>
/// Encrypt the packet and boardcast to all endpoint 
/// </summary>
/// <param name="str">the packet to send</param>
inline void encrypt_broadcast(const string& str) {

	if (config::encrypt_mode == config::encrypt_type::aes_cbc_pck7padding) {

		json j =
		{
			{"type", "encrypted"},
			{
				"params", {
					{"mode", "aes_cbc_pck7padding"},
					{"raw", base64_aes_cbc_encrypt(str, (unsigned char*)config::wspasswdbase.substr(0, 16).c_str(), (unsigned char*)config::wspasswdbase.substr(16, 16).c_str())}
				}
			}
		};
		GolangBridge::func::FnGlobalBroadcast(j.dump().c_str());
		return;
	}
	if (config::encrypt_mode == config::encrypt_type::aes_cbc_pkcs7padding) {
		json j =
		{
			{"type", "encrypted"},
			{
				"params", {
					{"mode", "aes_cbc_pkcs7padding"},
					{"raw", base64_aes_cbc_encrypt(str, (unsigned char*)config::wspasswdbase.substr(0, 16).c_str(), (unsigned char*)config::wspasswdbase.substr(16, 16).c_str())}
				}
			}
		};
		GolangBridge::func::FnGlobalBroadcast(j.dump().c_str());
		return;
	}
	if (config::encrypt_mode == config::encrypt_type::none) {
		GolangBridge::func::FnGlobalBroadcast(str.c_str());
		return;
	}

}


namespace EventHandle {
	string OnPlayerJoin(const string& player_name, const string& xuid, const string& ip) {
		json join =
		{
			{"type", "pack"},
			{"cause","join"},
			{
				"params", {
					{"sender", player_name},
					{"xuid", xuid},
					{"ip", ip}
				}
			}
		};
		return join.dump();
	}
	string OnPlayerLeft(const string& player_name, const string& xuid) {
		json left =
		{
			{"type", "pack"},
			{"cause","left"},
			{
				"params", {
					{"sender", player_name},
					{"xuid", xuid},
				}
			}
		};
		return left.dump();
	}
	string OnPlayerUseCmd(const string& player_name, const string& cmd) {
		json usecmd =
		{
			{"type", "pack"},
			{"cause","cmd"},
			{
				"params", {
					{"sender", player_name},
					{"cmd", cmd},
				}
			}
		};
		return usecmd.dump();
	}
	string OnPlayerChat(const string& player_name, string text) {
		json chat =
		{
			{"type", "pack"},
			{"cause","chat"},
			{
				"params", {
					{"sender", player_name},
					{"text", text},
				}
			}
		};
		return chat.dump();

	}

	string OnMobDie(const string& MobType, const string& MobName, const string& SrcType, const string& SrcName, const int& causecode, const string& cause, const Vec3& pos) {
		json mobdie =
		{
			{"type", "pack"},
			{"cause","mobdie"},
			{
				"params", {
					{"mobtype", MobType},
					{"mobname", MobName},

					{"srctype", SrcType},
					{"srcname", SrcName},

					{"dmcase", causecode},
					{"dmname", cause},

					{
						"pos",{
							{"x", pos.x},
							{"y", pos.y},
							{"z", pos.z},
						}
					},
				}
			}
		};
		return mobdie.dump();
	}
}
#include <set>
namespace ClientMsgHandle {
	std::set<uint64_t> usedids;
	void cmd(json cmd_request, __int64 connection) {
		//cout << cmd_request.dump(4) << endl;
		string ret;
		if (!cmd_request["id"].is_null()) {
			if (cmd_request["id"].is_string()) {
				if (usedids.find(do_hash(cmd_request["id"].get<string>().c_str())) != usedids.end()) {
					throw "SecurityError Don't reuse id";
				}
			}
			else
				if (cmd_request["id"].is_number_integer()) {
					if (usedids.find(cmd_request["id"].get<int>()) != usedids.end()) {
						throw "SecurityError Don't reuse id";
					}
				}
				else {
					throw "SecurityError Unknown id Type";
				}

		}
		else {
			throw "SecurityError Please Specific a id for this Request";
		}
		if (!cmd_request.is_null() && cmd_request["cmd"].is_string()) {
			string cmd(cmd_request["cmd"]);
			std::cout << cmd << std::endl;
			BraceRemove(cmd);
			std::cout << cmd << std::endl;
			logger.info("Running cmd > {}" , cmd);
			ret = Level::runcmdEx(string(cmd_request["cmd"])).second;
		}
		else
			throw "JsonParseError [params][cmd] Not Found or Not a String";
		json runcmdfeedback =
		{
			{"type", "pack"},
			{"cause","runcmdfeedback"},
			{
				"params", {
					{"result", ret},
				}
			}
		};
		if (cmd_request["id"].is_string()) {
			runcmdfeedback["params"]["id"] = cmd_request["id"].get<string>();
			usedids.insert(do_hash(cmd_request["id"].get<string>().c_str()));
		}
		if (cmd_request["id"].is_number_integer()) {
			runcmdfeedback["params"]["id"] = cmd_request["id"].get<int>();
			usedids.insert(cmd_request["id"].get<int>());
		}
		encrypt_send(runcmdfeedback.dump(), connection);
	}



	void sendtext(json tellraw_request, __int64 connection) {
		if (!tellraw_request["id"].is_null()) {
			if (tellraw_request["id"].is_string()) {
				if (usedids.find(do_hash(tellraw_request["id"].get<string>().c_str())) != usedids.end()) {
					throw "SecurityError Don't reuse id";
				}
			}
			else
				if (tellraw_request["id"].is_number_integer()) {
					if (usedids.find(tellraw_request["id"].get<int>()) != usedids.end()) {
						throw "SecurityError Don't reuse id";
					}
				}
				else {
					throw "SecurityError Unknown id Type";
				}

		}
		else {
			throw "SecurityError Please Specific a id for this Request";
		}

		if (!tellraw_request.is_null() && tellraw_request["text"].is_string()) {
			logger.info("SendingText > {}" , string(tellraw_request["text"]));
		}
		else
			throw "JsonParseError [params][text] Not Found or Not a String";
		//{"rawtext":[{"text":"Hello world"}]}
		json tellraw;
		tellraw["rawtext"] = vector<pair<string, string>>{ };
		tellraw["rawtext"][0]["text"] = tellraw_request["text"];
		Level::runcmdEx("tellraw @a " + tellraw.dump());
		if (tellraw_request["id"].is_string()) {
			//runcmdfeedback["params"]["id"] = cmd_request["id"].get<string>();
			usedids.insert(do_hash(tellraw_request["id"].get<string>().c_str()));
		}
		if (tellraw_request["id"].is_number_integer()) {
			//tellraw_request["params"]["id"] = cmd_request["id"].get<int>();
			usedids.insert(tellraw_request["id"].get<int>());
		}
	}

	void action_switch(json in_json, __int64 connection) {
		//cout << "PackJson > " << in_json.dump(4) << endl;
		if (in_json["type"].is_string()) {
			if (in_json["type"] != "pack") {
				GolangBridge::func::FnGlobalSend(connection, "{\"type\":\"pack\",\"cause\":\"invalidrequest\",\"params\":{\"msg\":\"err type\"}}");
				Sleep(1000);
				GolangBridge::func::FnGlobalClosed(connection, 1001, "");
			}
			else {
				if (in_json["action"].is_string()) {
					switch (do_hash(in_json["action"].get<std::string>().c_str())) {
					case do_hash("runcmdrequest"):
						ClientMsgHandle::cmd(in_json["params"], connection);
						break;
					case do_hash("sendtext"):
						ClientMsgHandle::sendtext(in_json["params"], connection);
						break;
					default:
						throw string("JsonParseError [params][params] No Such Action");
						break;
					}
				}
				else {
					throw string("JsonParseError [action] Not Found or Not a object");
				}
			}
		}
		else {
			throw string("JsonParseError [type] Not Found or Not a object");
		}
	}
}


inline void fw(std::string filen, std::string instr) {
	std::ofstream outfile;
	outfile.open(filen, std::ios::app);
	outfile << instr << std::endl;
	outfile.close();
}
void WsMsgHandler(__int64 connection, char* msg) {
	string in_msg = string(msg);
	//cout << in_msg << endl;
	//rapidjson::Document in_json;
	//rapidjson::ParseResult parse_result = in_json.Parse(in_msg.c_str());
	json in_json = nullptr;
	try {
		in_json = json::parse(in_msg);

		if (in_json.is_object()) {
			if (in_json["type"].is_string()) {
				if (in_json["type"] == "pack" && config::encrypt_mode != 0) {
					GolangBridge::func::FnGlobalSend(connection, "{\"type\":\"pack\",\"cause\":\"invalidrequest\",\"params\":{\"msg\":\"A encrypt pack required\"}}");
					Sleep(1000);
					GolangBridge::func::FnGlobalClosed(connection, 1011, "");
				}
				else {
					if (in_json["type"] == "encrypted") {
						if (in_json["params"].is_object()) {
							//handle switch(action) 
							if (in_json["params"]["mode"].is_string()) {
								if ((in_json["params"]["mode"] == "aes_cbc_pck7padding" && config::encrypt_mode == 1)&&(in_json["params"]["mode"] == "aes_cbc_pck7spadding" && config::encrypt_mode == 2)) {

									if (in_json["params"]["raw"].is_string()) {
										string str = base64_aes_cbc_decrypt(in_json["params"]["raw"], (unsigned char*)config::wspasswdbase.substr(0, 16).c_str(), (unsigned char*)config::wspasswdbase.substr(16, 16).c_str());
										in_json = json::parse(str);
										if (in_json.is_object())
											ClientMsgHandle::action_switch(in_json, connection);
									}
									else {
										throw string("JsonParseError> Require ObjectType Raw Json with at least one member");
									}
								}
								else {
									throw string("DecodeError> Encrypt mode Not Support");
								}
							}
						}
						else {
							throw string("JsonParseError> [params] Not Found or Not a object");
						}
					}
					else {
						if (in_json["type"] == "pack") {
							ClientMsgHandle::action_switch(in_json, connection);
						}
						else {
							throw string("Unknown Packet Type");
						}
					}
				}
			}
			//json_parse type↓
			else {
				throw string("JsonParseError [type] Not Found or Not a string");
			}
		}
		else {
			throw string("JsonParseError> Require ObjectType Json with at least one member");
		}
	}

	catch (string exp) {
		json err =
		{
			{"type", "pack"},
			{"cause","decodefailed"},
			{
				"params", {
					{"msg", exp},
				}
			}
		};
		if (!in_json["params"]["id"].is_null()) {
			if (in_json["params"]["id"].is_string()) {
				err["params"]["id"] = in_json["params"]["id"].get<string>();
			}
			if (in_json["params"]["id"].is_number_integer()) {
				err["params"]["id"] = in_json["params"]["id"].get<int>();
			}
		}
		logger.error("JSON", exp);
		GolangBridge::func::FnGlobalSend(connection, err.dump().c_str());
	}
	catch (json::parse_error& e) {
		logger.error("JSON", "JsonErr > " + string(e.what()));
		json err =
		{
			{"type", "pack"},
			{"cause","decodefailed"},
			{
				"params", {
					{"msg", "JsonErr > " + string(e.what())},
				}
			}
		};
		if (!in_json["params"]["id"].is_null()) {
			if (in_json["params"]["id"].is_string()) {
				err["params"]["id"] = in_json["params"]["id"].get<string>();
			}
			if (in_json["params"]["id"].is_number_integer()) {
				err["params"]["id"] = in_json["params"]["id"].get<int>();
			}
		}
		logger.error("JSON", "JsonErr > " + string(e.what()));
		GolangBridge::func::FnGlobalSend(connection, err.dump().c_str());
	}
	catch (json::type_error& e) {
		logger.error("JSON", "JsonErr > " + string(e.what()));
		json err =
		{
			{"type", "pack"},
			{"cause","decodefailed"},
			{
				"params", {
					{"msg", "JsonErr > " + string(e.what())},
				}
			}
		};
		if (!in_json["params"]["id"].is_null()) {
			if (in_json["params"]["id"].is_string()) {
				err["params"]["id"] = in_json["params"]["id"].get<string>();
			}
			if (in_json["params"]["id"].is_number_integer()) {
				err["params"]["id"] = in_json["params"]["id"].get<int>();
			}
		}
		logger.error("JSON", "JsonErr > " + string(e.what()));
		GolangBridge::func::FnGlobalSend(connection, err.dump().c_str());
	}
	catch (...) {
		logger.error("EXP", "Unknown Expection > ");
	}

}
inline void reglist() {
	using namespace Event;
	Event::PlayerChatEvent::subscribe([](const PlayerChatEvent& ev)->bool {
		encrypt_broadcast(EventHandle::OnPlayerChat(ev.mPlayer->getNameTag(), ev.mMessage));
		return true;
		});

	Event::PlayerJoinEvent::subscribe([](const PlayerJoinEvent& ev)->bool {
		encrypt_broadcast(EventHandle::OnPlayerJoin(ev.mPlayer->getNameTag(), ev.mPlayer->getXuid(), ev.mPlayer->getIP()));
		return true;
		});
	Event::PlayerLeftEvent::subscribe([](const PlayerLeftEvent& ev)->bool {
		encrypt_broadcast(EventHandle::OnPlayerLeft(ev.mPlayer->getNameTag(), ev.mPlayer->getXuid()));
		return true;
		});
	Event::PlayerCmdEvent::subscribe([](const PlayerCmdEvent& ev)->bool {
		encrypt_broadcast(EventHandle::OnPlayerUseCmd(ev.mPlayer->getNameTag(), ev.mCommand));
		return true;
		});
	Event::MobDieEvent::subscribe([](const MobDieEvent& ev)->bool {
		if (!ev.mMob)
			return true;
		string MobType = ev.mMob->getTypeName();
		string MobName = ev.mMob->getNameTag();
		string DamageSourceString = ActorDamageSource::lookupCauseName(ev.mDamageSource->getCause());
		Vec3 Position = ev.mMob->getPos();

		Actor* source = ev.mDamageSource->getEntity();
		if (source) {
			string SrcType = source->getTypeName();
			string SrcName = source->getNameTag();
			encrypt_broadcast(EventHandle::OnMobDie(MobType, MobName, SrcType, SrcName, (int)ev.mDamageSource->getCause(), DamageSourceString, Position));
		}
		else {
			encrypt_broadcast(EventHandle::OnMobDie(MobType, MobName, "unknown", "unknown", (int)ev.mDamageSource->getCause(), DamageSourceString, Position));
		}
		return true;
		});
}

void GolangLoggerWrapper(int loglvl, char* text) {
	std::string str(text);
	BraceRemove(str);
	std::cout << str << std::endl;
	switch (loglvl) {
	case 0:
		logger.info(str);
		break;
	case 1:
		logger.warn(str);
		break;
	case 2:
		logger.error(str);
		break;
	default:
		logger.info(str);
		break;
	}
}

void wst_entry() {
	loadconf();

	Event::ServerStartedEvent::subscribe([](const Event::ServerStartedEvent& ev)->bool {
		GolangBridge::InitGoBridge();
		GolangBridge::func::FnSetMsgHandler(WsMsgHandler);
		GolangBridge::func::FnSetLogger(GolangLoggerWrapper);
		GolangBridge::func::FnGolangWSInit(config::endpoint.c_str(), config::wsaddr.c_str(), config::enableLog);
		return true;
		});
	logger.setFile("logs/llws.log");
	Sleep(300);
	wsinitmsg();
	reglist();
}