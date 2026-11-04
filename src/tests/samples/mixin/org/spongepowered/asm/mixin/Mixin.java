package org.spongepowered.asm.mixin;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Stand-in for SpongePowered's @Mixin, redefined here so the test fixture can
 * be compiled with nothing but javac. The shape that matters to jdec is
 * identical: RUNTIME retention, Class[] value(), String[] targets().
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface Mixin {
    Class<?>[] value() default {};

    String[] targets() default {};
}
