// This Header is auto generated by BDSLiteLoader Toolchain
#pragma once
#define AUTO_GENERATED
#include "../Global.h"

#define BEFORE_EXTRA
// Include Headers or Declare Types Here

#undef BEFORE_EXTRA

class TradeableSystem {

#define AFTER_EXTRA
// Add Member There

#undef AFTER_EXTRA

#ifndef DISABLE_CONSTRUCTOR_PREVENTION_TRADEABLESYSTEM
public:
    class TradeableSystem& operator=(class TradeableSystem const&) = delete;
    TradeableSystem(class TradeableSystem const&) = delete;
    TradeableSystem() = delete;
#endif

public:
    /*0*/ virtual ~TradeableSystem();
    /*1*/ virtual void __unk_vfn_1();
    /*2*/ virtual void tick(class EntityRegistry&);

protected:

private:

};