// This Header is auto generated by BDSLiteLoader Toolchain
#pragma once
#define AUTO_GENERATED
#include "../Global.h"
#include "CraftHandlerBase.hpp"

#define BEFORE_EXTRA
// Include Headers or Declare Types Here

#undef BEFORE_EXTRA

class CraftHandlerGrindstone : public CraftHandlerBase {

#define AFTER_EXTRA
// Add Member There

#undef AFTER_EXTRA

#ifndef DISABLE_CONSTRUCTOR_PREVENTION_CRAFTHANDLERGRINDSTONE
public:
    class CraftHandlerGrindstone& operator=(class CraftHandlerGrindstone const&) = delete;
    CraftHandlerGrindstone(class CraftHandlerGrindstone const&) = delete;
    CraftHandlerGrindstone() = delete;
#endif

public:
    /*0*/ virtual ~CraftHandlerGrindstone();
    /*3*/ virtual void endRequestBatch();
    /*4*/ virtual enum ItemStackNetResult _handleCraftAction(class ItemStackRequestActionCraftBase const&);
    /*5*/ virtual void _postCraftRequest(bool);
    MCAPI CraftHandlerGrindstone(class Player&, class ItemStackRequestActionCraftHandler&);

protected:

private:
    MCAPI class ItemStack _createResultItem(class ItemStack const&, class ItemStack const&);
    MCAPI int _getExperienceFromItem(class ItemStack const&) const;
    MCAPI class ItemStack _getResultItemWithNoEnchants(std::vector<class ItemStack> const&, bool&);
    MCAPI bool _resolveNetIdAndValidate(enum ContainerEnumName, unsigned char, struct ItemStackNetIdVariant const&);

};