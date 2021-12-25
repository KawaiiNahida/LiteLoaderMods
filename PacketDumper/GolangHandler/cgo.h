#include <stdbool.h>
typedef struct {
	long long size;
	char* pkt;
}externApiRet;
externApiRet makeReturn(char* pkt,long long size){
	externApiRet ret;
	ret.pkt = pkt;
	ret.size = size;
	return ret;
}
void* CppSendPlayerPacket;
int RunSendPlayerPacket(char* PlayerName, char* PktContent, int PktSize, int PktId){
	return ((int(*)(char*, char*, int, int))CppSendPlayerPacket)(PlayerName,PktContent,PktSize,PktId);
}
void SetSendPlayerPacket(void* i){
	CppSendPlayerPacket = i;
}

