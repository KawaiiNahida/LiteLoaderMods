// This Header is auto generated by BDSLiteLoader Toolchain
#pragma once
#define AUTO_GENERATED
#include "../Global.h"

#define BEFORE_EXTRA
// Include Headers or Declare Types Here

#undef BEFORE_EXTRA

class GrowingPlantFeature {

#define AFTER_EXTRA
// Add Member There

#undef AFTER_EXTRA

#ifndef DISABLE_CONSTRUCTOR_PREVENTION_GROWINGPLANTFEATURE
public:
    class GrowingPlantFeature& operator=(class GrowingPlantFeature const&) = delete;
    GrowingPlantFeature(class GrowingPlantFeature const&) = delete;
#endif

public:
    /*0*/ virtual ~GrowingPlantFeature();
    /*1*/ virtual class std::optional<class BlockPos> place(class IBlockWorldGenAPI&, class BlockPos const&, class Random&, class RenderParams&) const;
    MCAPI GrowingPlantFeature();

protected:

private:

};