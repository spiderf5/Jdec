package demo.mixin;

import net.minecraft.entity.PlayerEntity;
import org.spongepowered.asm.mixin.At;
import org.spongepowered.asm.mixin.Inject;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Overwrite;

/**
 * The interesting case: a target given as a Class reference, plus injections
 * whose method names are plain strings.
 */
@Mixin(PlayerEntity.class)
public abstract class PlayerHooks {
    @Inject(method = "tick", at = @At("HEAD"))
    private void onTickHead() {
    }

    @Inject(method = {"tick", "jump"}, at = @At("RETURN"))
    private void onTickOrJump() {
    }

    @Overwrite
    public void jump() {
    }
}
