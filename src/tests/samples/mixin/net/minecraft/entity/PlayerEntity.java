package net.minecraft.entity;

/** Stands in for a game class: this is what a mixin targets. */
public class PlayerEntity {
    public int tickCount;

    public void tick() {
        this.tickCount++;
    }

    public void jump() {
    }
}
