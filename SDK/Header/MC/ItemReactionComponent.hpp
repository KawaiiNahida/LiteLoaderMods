// This Header is auto generated by BDSLiteLoader Toolchain
#pragma once
#define AUTO_GENERATED
#include "../Global.h"

#define BEFORE_EXTRA
// Include Headers or Declare Types Here

#undef BEFORE_EXTRA

class ItemReactionComponent {

#define AFTER_EXTRA
// Add Member There

#undef AFTER_EXTRA

#ifndef DISABLE_CONSTRUCTOR_PREVENTION_ITEMREACTIONCOMPONENT
public:
    class ItemReactionComponent& operator=(class ItemReactionComponent const&) = delete;
    ItemReactionComponent(class ItemReactionComponent const&) = delete;
    ItemReactionComponent() = delete;
#endif

public:
    /*0*/ virtual ~ItemReactionComponent();
    /*1*/ virtual void __unk_vfn_1();
    /*2*/ virtual void __unk_vfn_2();
    /*3*/ virtual void _onEnd(class LabTableReaction&, class BlockSource&);

protected:

private:

};