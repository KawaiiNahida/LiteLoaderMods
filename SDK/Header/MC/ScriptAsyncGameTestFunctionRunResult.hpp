// This Header is auto generated by BDSLiteLoader Toolchain
#pragma once
#define AUTO_GENERATED
#include "../Global.h"

#define BEFORE_EXTRA

#undef BEFORE_EXTRA

class ScriptAsyncGameTestFunctionRunResult {

#define AFTER_EXTRA

#undef AFTER_EXTRA

#ifndef DISABLE_CONSTRUCTOR_PREVENTION_SCRIPTASYNCGAMETESTFUNCTIONRUNRESULT
public:
    class ScriptAsyncGameTestFunctionRunResult& operator=(class ScriptAsyncGameTestFunctionRunResult const&) = delete;
    ScriptAsyncGameTestFunctionRunResult(class ScriptAsyncGameTestFunctionRunResult const&) = delete;
    ScriptAsyncGameTestFunctionRunResult() = delete;
#endif

public:
    /*0*/ virtual ~ScriptAsyncGameTestFunctionRunResult();
    /*1*/ virtual bool isComplete() const;
    /*2*/ virtual class std::optional<struct gametest::GameTestError> getError();
    MCAPI ScriptAsyncGameTestFunctionRunResult(class Scripting::Result<class Scripting::Future<void> >);

protected:

private:

};