// This Header is auto generated by BDSLiteLoader Toolchain
#pragma once
#define AUTO_GENERATED
#include "../Global.h"
#include "ScriptApi.hpp"

#define BEFORE_EXTRA
// Include Headers or Declare Types Here

#undef BEFORE_EXTRA

class ApplyLegacyEntityBinding {

#define AFTER_EXTRA
// Add Member There

#undef AFTER_EXTRA

#ifndef DISABLE_CONSTRUCTOR_PREVENTION_APPLYLEGACYENTITYBINDING
public:
    class ApplyLegacyEntityBinding& operator=(class ApplyLegacyEntityBinding const&) = delete;
    ApplyLegacyEntityBinding(class ApplyLegacyEntityBinding const&) = delete;
    ApplyLegacyEntityBinding() = delete;
#endif

public:
    /*0*/ virtual ~ApplyLegacyEntityBinding();
    /*1*/ virtual bool createAndApplyTemplate(class ScriptApi::ScriptVersionInfo const&, class ScriptEngine&, class ScriptServerContext&, class Actor* *, std::string const&) const;

protected:

private:

};