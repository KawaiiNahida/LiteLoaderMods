// This Header is auto generated by BDSLiteLoader Toolchain
#pragma once
#define AUTO_GENERATED
#include "../Global.h"

#define BEFORE_EXTRA
// Include Headers or Declare Types Here

#undef BEFORE_EXTRA

class ItemStackRequestActionBeaconPayment {

#define AFTER_EXTRA
// Add Member There

#undef AFTER_EXTRA

#ifndef DISABLE_CONSTRUCTOR_PREVENTION_ITEMSTACKREQUESTACTIONBEACONPAYMENT
public:
    class ItemStackRequestActionBeaconPayment& operator=(class ItemStackRequestActionBeaconPayment const&) = delete;
    ItemStackRequestActionBeaconPayment(class ItemStackRequestActionBeaconPayment const&) = delete;
    ItemStackRequestActionBeaconPayment() = delete;
#endif

public:
    /*0*/ virtual ~ItemStackRequestActionBeaconPayment();
    /*1*/ virtual void __unk_vfn_0();
    /*2*/ virtual void __unk_vfn_1();
    /*3*/ virtual void __unk_vfn_2();
    /*4*/ virtual void _write(class BinaryStream&) const;
    /*5*/ virtual bool _read(class ReadOnlyBinaryStream&);

protected:

private:

};