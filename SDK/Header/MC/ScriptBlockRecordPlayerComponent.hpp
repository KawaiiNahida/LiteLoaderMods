// This Header is auto generated by BDSLiteLoader Toolchain
#pragma once
#define AUTO_GENERATED
#include "../Global.h"
#include "ScriptObject.hpp"

#define BEFORE_EXTRA
// Include Headers or Declare Types Here

#undef BEFORE_EXTRA

class ScriptBlockRecordPlayerComponent : public ScriptObject {

#define AFTER_EXTRA
// Add Member There

#undef AFTER_EXTRA

#ifndef DISABLE_CONSTRUCTOR_PREVENTION_SCRIPTBLOCKRECORDPLAYERCOMPONENT
public:
    class ScriptBlockRecordPlayerComponent& operator=(class ScriptBlockRecordPlayerComponent const&) = delete;
    ScriptBlockRecordPlayerComponent() = delete;
#endif

public:
    /*0*/ virtual ~ScriptBlockRecordPlayerComponent();
    /*
    inline  ~ScriptBlockRecordPlayerComponent(){
         (ScriptBlockRecordPlayerComponent::*rv)();
        *((void**)&rv) = dlsym("??1ScriptBlockRecordPlayerComponent@@UEAA@XZ");
        return (this->*rv)();
    }
    */
    MCAPI ScriptBlockRecordPlayerComponent(class ScriptBlockRecordPlayerComponent const&);
    MCAPI ScriptBlockRecordPlayerComponent(class ScriptBlockRecordPlayerComponent&&);
    MCAPI class ScriptBlockRecordPlayerComponent& operator=(class ScriptBlockRecordPlayerComponent&&);
    MCAPI static class Scripting::ClassBindingBuilder<class ScriptBlockRecordPlayerComponent> bind(struct Scripting::Version);
    MCAPI static class Scripting::StrongTypedObjectHandle<class ScriptBlockRecordPlayerComponent> tryCreate(class BlockSource&, class BlockPos, class Scripting::WeakLifetimeScope const&);

protected:
    MCAPI class Scripting::Result<void> clearRecord();
    MCAPI class Scripting::Result<bool> isPlaying();
    MCAPI class Scripting::Result<void> setRecord(class ScriptItemType const&);

private:

};