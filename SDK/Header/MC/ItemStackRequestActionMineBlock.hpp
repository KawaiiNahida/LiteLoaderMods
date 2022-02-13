// This Header is auto generated by BDSLiteLoader Toolchain
#pragma once
#define AUTO_GENERATED
#include "../Global.h"

#define BEFORE_EXTRA
// Include Headers or Declare Types Here

#undef BEFORE_EXTRA

class ItemStackRequestActionMineBlock {

#define AFTER_EXTRA
// Add Member There
public:
enum PreValidationStatus;

#undef AFTER_EXTRA

#ifndef DISABLE_CONSTRUCTOR_PREVENTION_ITEMSTACKREQUESTACTIONMINEBLOCK
public:
    class ItemStackRequestActionMineBlock& operator=(class ItemStackRequestActionMineBlock const&) = delete;
    ItemStackRequestActionMineBlock(class ItemStackRequestActionMineBlock const&) = delete;
    ItemStackRequestActionMineBlock() = delete;
#endif

public:
    /*0*/ virtual ~ItemStackRequestActionMineBlock();
    /*1*/ virtual void __unk_vfn_1();
    /*2*/ virtual void __unk_vfn_2();
    /*3*/ virtual void __unk_vfn_3();
    /*4*/ virtual void _write(class BinaryStream&) const;
    /*5*/ virtual bool _read(class ReadOnlyBinaryStream&);
    MCAPI enum ItemStackRequestActionMineBlock::PreValidationStatus getPreValidationStatus() const;
    MCAPI int getPredictedDurability() const;
    MCAPI struct ItemStackRequestSlotInfo getSrc() const;
    MCAPI void setPreValidationStatus(enum ItemStackRequestActionMineBlock::PreValidationStatus) const;

protected:

private:

};