// This Header is auto generated by BDSLiteLoader Toolchain
#pragma once
#define AUTO_GENERATED
#include "../Global.h"

#define BEFORE_EXTRA
// Include Headers or Declare Types Here

#undef BEFORE_EXTRA

class FindUnderwaterTreasureGoal {

#define AFTER_EXTRA
// Add Member There

#undef AFTER_EXTRA

#ifndef DISABLE_CONSTRUCTOR_PREVENTION_FINDUNDERWATERTREASUREGOAL
public:
    class FindUnderwaterTreasureGoal& operator=(class FindUnderwaterTreasureGoal const&) = delete;
    FindUnderwaterTreasureGoal(class FindUnderwaterTreasureGoal const&) = delete;
    FindUnderwaterTreasureGoal() = delete;
#endif

public:
    /*0*/ virtual ~FindUnderwaterTreasureGoal();
    /*1*/ virtual bool canUse();
    /*2*/ virtual bool canContinueToUse();
    /*3*/ virtual void __unk_vfn_3();
    /*4*/ virtual void start();
    /*5*/ virtual void stop();
    /*6*/ virtual void tick();
    /*7*/ virtual void appendDebugInfo(std::string&) const;
    /*
    inline bool canBeInterrupted(){
        bool (FindUnderwaterTreasureGoal::*rv)();
        *((void**)&rv) = dlsym("?canBeInterrupted@FindUnderwaterTreasureGoal@@UEAA_NXZ");
        return (this->*rv)();
    }
    */
    MCAPI FindUnderwaterTreasureGoal(class Mob&, float, int, int);

protected:

private:

};