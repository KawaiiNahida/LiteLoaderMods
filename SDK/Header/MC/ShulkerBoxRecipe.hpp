// This Header is auto generated by BDSLiteLoader Toolchain
#pragma once
#define AUTO_GENERATED
#include "../Global.h"
#include "ShapelessRecipe.hpp"

#define BEFORE_EXTRA
// Include Headers or Declare Types Here

#undef BEFORE_EXTRA

class ShulkerBoxRecipe : public ShapelessRecipe {

#define AFTER_EXTRA
// Add Member There

#undef AFTER_EXTRA

#ifndef DISABLE_CONSTRUCTOR_PREVENTION_SHULKERBOXRECIPE
public:
    class ShulkerBoxRecipe& operator=(class ShulkerBoxRecipe const&) = delete;
    ShulkerBoxRecipe(class ShulkerBoxRecipe const&) = delete;
    ShulkerBoxRecipe() = delete;
#endif

public:
    /*0*/ virtual ~ShulkerBoxRecipe();
    /*1*/ virtual std::vector<class ItemInstance> const& assemble(class CraftingContainer&) const;
    /*4*/ virtual std::vector<class ItemInstance> const& getResultItem() const;
    /*10*/ virtual bool isMultiRecipe() const;
    /*12*/ virtual bool itemsMatch(class ItemDescriptor const&, class ItemDescriptor const&) const;
    /*14*/ virtual bool itemsMatch(class ItemDescriptor const&, int, int, class CompoundTag const*) const;
    MCAPI ShulkerBoxRecipe(class gsl::basic_string_span<char const, -1>, std::vector<class RecipeIngredient> const&, std::vector<class ItemInstance> const&, class HashedString, int, class mce::UUID const*);
    MCAPI static class mce::UUID const ID;

protected:

private:

};