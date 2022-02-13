// This Header is auto generated by BDSLiteLoader Toolchain
#pragma once
#define AUTO_GENERATED
#include "../Global.h"
#include "Packet.hpp"

#define BEFORE_EXTRA
// Include Headers or Declare Types Here

#undef BEFORE_EXTRA

class EntityServerPacket : public Packet {

#define AFTER_EXTRA
// Add Member There

#undef AFTER_EXTRA

#ifndef DISABLE_CONSTRUCTOR_PREVENTION_ENTITYSERVERPACKET
public:
    class EntityServerPacket& operator=(class EntityServerPacket const&) = delete;
    EntityServerPacket(class EntityServerPacket const&) = delete;
#endif

public:
    /*0*/ virtual ~EntityServerPacket();
    /*1*/ virtual enum MinecraftPacketIds getId() const = 0;
    /*2*/ virtual std::string getName() const = 0;
    /*3*/ virtual void write(class BinaryStream&) const;
    /*6*/ virtual enum StreamReadResult _read(class ReadOnlyBinaryStream&);
    /*
    inline  ~EntityServerPacket(){
         (EntityServerPacket::*rv)();
        *((void**)&rv) = dlsym("??1EntityServerPacket@@UEAA@XZ");
        return (this->*rv)();
    }
    */
    MCAPI EntityServerPacket(class EntityContext const&);
    MCAPI EntityServerPacket();

protected:

private:

};