// This Header is auto generated by BDSLiteLoader Toolchain
#pragma once
#define AUTO_GENERATED
#include "../Global.h"

#define BEFORE_EXTRA
// Include Headers or Declare Types Here
class Actor;

#undef BEFORE_EXTRA

class ActorDamageSource {

#define AFTER_EXTRA
// Add Member There
public:
    LIAPI Actor* getEntity();

#undef AFTER_EXTRA

#ifndef DISABLE_CONSTRUCTOR_PREVENTION_ACTORDAMAGESOURCE
public:
    class ActorDamageSource& operator=(class ActorDamageSource const&) = delete;
    ActorDamageSource(class ActorDamageSource const&) = delete;
    ActorDamageSource() = delete;
#endif

public:
    /*0*/ virtual ~ActorDamageSource();
    /*1*/ virtual bool isEntitySource() const;
    /*2*/ virtual void __unk_vfn_0();
    /*3*/ virtual bool isBlockSource() const;
    /*4*/ virtual bool isFire() const;
    /*5*/ virtual struct std::pair<std::string, std::vector<std::string> > getDeathMessage(std::string, class Actor*) const;
    /*6*/ virtual bool getIsCreative() const;
    /*7*/ virtual bool getIsWorldBuilder() const;
    /*8*/ virtual void __unk_vfn_1();
    /*9*/ virtual void __unk_vfn_2();
    /*10*/ virtual enum ActorCategory getEntityCategories() const;
    /*11*/ virtual bool getDamagingEntityIsCreative() const;
    /*12*/ virtual bool getDamagingEntityIsWorldBuilder() const;
    /*13*/ virtual struct ActorUniqueID getDamagingEntityUniqueID() const;
    /*14*/ virtual enum ActorType getDamagingEntityType() const;
    /*15*/ virtual enum ActorCategory getDamagingEntityCategories() const;
    /*16*/ virtual std::unique_ptr<class ActorDamageSource> clone() const;
    /*
    inline bool isChildEntitySource() const{
        bool (ActorDamageSource::*rv)() const;
        *((void**)&rv) = dlsym("?isChildEntitySource@ActorDamageSource@@UEBA_NXZ");
        return (this->*rv)();
    }
    inline enum ActorType getEntityType() const{
        enum ActorType (ActorDamageSource::*rv)() const;
        *((void**)&rv) = dlsym("?getEntityType@ActorDamageSource@@UEBA?AW4ActorType@@XZ");
        return (this->*rv)();
    }
    inline struct ActorUniqueID getEntityUniqueID() const{
        struct ActorUniqueID (ActorDamageSource::*rv)() const;
        *((void**)&rv) = dlsym("?getEntityUniqueID@ActorDamageSource@@UEBA?AUActorUniqueID@@XZ");
        return (this->*rv)();
    }
    */
    MCAPI ActorDamageSource(enum ActorDamageCause);
    MCAPI enum ActorDamageCause getCause() const;
    MCAPI void setCause(enum ActorDamageCause);
    MCAPI static enum ActorDamageCause lookupCause(std::string const&);
    MCAPI static std::string const& lookupCauseName(enum ActorDamageCause);

protected:

private:

};