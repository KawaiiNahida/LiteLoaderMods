// This Header is auto generated by BDSLiteLoader Toolchain
#pragma once
#define AUTO_GENERATED
#include "../Global.h"

#define BEFORE_EXTRA
// Include Headers or Declare Types Here

#undef BEFORE_EXTRA

class LookAtBlockNode {

#define AFTER_EXTRA
// Add Member There

#undef AFTER_EXTRA

#ifndef DISABLE_CONSTRUCTOR_PREVENTION_LOOKATBLOCKNODE
public:
    class LookAtBlockNode& operator=(class LookAtBlockNode const&) = delete;
    LookAtBlockNode(class LookAtBlockNode const&) = delete;
#endif

public:
    /*0*/ virtual ~LookAtBlockNode();
    /*1*/ virtual enum BehaviorStatus tick(class Actor&);
    /*
    inline void initializeFromDefinition(class Actor& a0){
        void (LookAtBlockNode::*rv)(class Actor&);
        *((void**)&rv) = dlsym("?initializeFromDefinition@LookAtBlockNode@@EEAAXAEAVActor@@@Z");
        return (this->*rv)(std::forward<class Actor&>(a0));
    }
    */
    MCAPI LookAtBlockNode();

protected:

private:

};