// This Header is auto generated by BDSLiteLoader Toolchain
#pragma once
#define AUTO_GENERATED
#include "../Global.h"
#include "Actor.hpp"
#include "Monster.hpp"

#define BEFORE_EXTRA
// Include Headers or Declare Types Here

#undef BEFORE_EXTRA

class Piglin : public Monster {

#define AFTER_EXTRA
// Add Member There

#undef AFTER_EXTRA

#ifndef DISABLE_CONSTRUCTOR_PREVENTION_PIGLIN
public:
    class Piglin& operator=(class Piglin const&) = delete;
    Piglin(class Piglin const&) = delete;
    Piglin() = delete;
#endif

public:
    /*14*/ virtual ~Piglin();
    /*20*/ virtual bool isRuntimePredictedMovementEnabled() const;
    /*41*/ virtual void __unk_vfn_41();
    /*52*/ virtual float getRidingHeight();
    /*61*/ virtual void __unk_vfn_61();
    /*68*/ virtual void __unk_vfn_68();
    /*78*/ virtual float getCameraOffset() const;
    /*82*/ virtual void __unk_vfn_82();
    /*87*/ virtual void __unk_vfn_87();
    /*88*/ virtual void playerTouch(class Player&);
    /*94*/ virtual void __unk_vfn_94();
    /*97*/ virtual void __unk_vfn_97();
    /*100*/ virtual bool isDamageBlocked(class ActorDamageSource const&) const;
    /*104*/ virtual void __unk_vfn_104();
    /*106*/ virtual void __unk_vfn_106();
    /*107*/ virtual void __unk_vfn_107();
    /*108*/ virtual void __unk_vfn_108();
    /*113*/ virtual bool isValidTarget(class Actor*) const;
    /*116*/ virtual void adjustDamageAmount(int&) const;
    /*120*/ virtual void onTame();
    /*121*/ virtual void onFailedTame();
    /*130*/ virtual void vehicleLanded(class Vec3 const&, class Vec3 const&);
    /*140*/ virtual void onBounceStarted(class BlockPos const&, class Block const&);
    /*152*/ virtual void awardKillScore(class Actor&, int);
    /*172*/ virtual struct ActorUniqueID getSourceUniqueID() const;
    /*179*/ virtual int getPortalWaitTime() const;
    /*181*/ virtual bool canChangeDimensions() const;
    /*182*/ virtual void __unk_vfn_182();
    /*184*/ virtual struct ActorUniqueID getControllingPlayer() const;
    /*193*/ virtual bool canPickupItem(class ItemStack const&) const;
    /*194*/ virtual bool canBePulledIntoVehicle() const;
    /*196*/ virtual void __unk_vfn_196();
    /*199*/ virtual bool canSynchronizeNewEntity() const;
    /*221*/ virtual void __unk_vfn_221();
    /*222*/ virtual void __unk_vfn_222();
    /*227*/ virtual bool isWorldBuilder() const;
    /*228*/ virtual bool isCreative() const;
    /*229*/ virtual bool isAdventure() const;
    /*232*/ virtual bool getInteraction(class Player&, class ActorInteraction&, class Vec3 const&);
    /*233*/ virtual bool canDestroyBlock(class Block const&) const;
    /*234*/ virtual void setAuxValue(int);
    /*240*/ virtual void stopSpinAttack();
    /*242*/ virtual void __unk_vfn_242();
    /*245*/ virtual void __unk_vfn_245();
    /*255*/ virtual void updateEntitySpecificMolangVariables(class RenderParams&);
    /*257*/ virtual void __unk_vfn_257();
    /*261*/ virtual void readAdditionalSaveData(class CompoundTag const&, class DataLoadHelper&);
    /*262*/ virtual void addAdditionalSaveData(class CompoundTag&);
    /*265*/ virtual void __unk_vfn_265();
    /*274*/ virtual void __unk_vfn_274();
    /*276*/ virtual void spawnAnim();
    /*290*/ virtual void aiStep();
    /*299*/ virtual float getItemUseStartupProgress() const;
    /*300*/ virtual float getItemUseIntervalProgress() const;
    /*303*/ virtual void __unk_vfn_303();
    /*305*/ virtual bool isAlliedTo(class Mob*);
    /*307*/ virtual void __unk_vfn_307();
    /*316*/ virtual void sendArmorDamage(class std::bitset<4> const&);
    /*331*/ virtual void onBorn(class Actor&, class Actor&);
    /*338*/ virtual void __unk_vfn_338();
    /*348*/ virtual void _serverAiMobStep();
    /*354*/ virtual void __unk_vfn_354();
    /*
    inline bool canExistInPeaceful() const{
        bool (Piglin::*rv)() const;
        *((void**)&rv) = dlsym("?canExistInPeaceful@Piglin@@UEBA_NXZ");
        return (this->*rv)();
    }
    */
    MCAPI Piglin(class ActorDefinitionGroup*, struct ActorDefinitionIdentifier const&, class EntityContext&);

protected:

private:

};