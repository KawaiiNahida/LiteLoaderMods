// This Header is auto generated by BDSLiteLoader Toolchain
#pragma once
#define AUTO_GENERATED
#include "../Global.h"

#define BEFORE_EXTRA
// Include Headers or Declare Types Here

#undef BEFORE_EXTRA

class PhysicsComponent {

#define AFTER_EXTRA
// Add Member There

#undef AFTER_EXTRA

#ifndef DISABLE_CONSTRUCTOR_PREVENTION_PHYSICSCOMPONENT
public:
    class PhysicsComponent& operator=(class PhysicsComponent const&) = delete;
    PhysicsComponent(class PhysicsComponent const&) = delete;
    PhysicsComponent() = delete;
#endif

public:
    MCAPI bool _isAffectedByGravity(class SynchedActorData const&) const;
    MCAPI bool isAffectedByGravity(struct IActorMovementProxy const&) const;
    MCAPI void setAffectedByGravity(struct IActorMovementProxy&, bool) const;
    MCAPI void setHasCollision(class Actor&, bool);

protected:

private:

};