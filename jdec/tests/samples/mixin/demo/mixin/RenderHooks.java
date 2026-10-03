package demo.mixin;

import org.spongepowered.asm.mixin.At;
import org.spongepowered.asm.mixin.Inject;
import org.spongepowered.asm.mixin.Mixin;

/**
 * A target declared by dotted string instead of by Class reference, and an
 * injection named the way Fabric rewrites it at build time: the intermediary
 * name, with the real one parked in the refmap. That is what an obfuscated mod
 * actually looks like, so the fixture should too.
 */
@Mixin(targets = "net.minecraft.client.Minecraft")
public class RenderHooks {
    @Inject(method = "method_9012", at = @At("TAIL"))
    private void onRunTick() {
    }
}
