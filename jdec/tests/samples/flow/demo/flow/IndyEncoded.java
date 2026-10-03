package demo.flow;

/**
 * Shaped like a superblaubeere27 / JObf call-target table: the real call
 * targets sit in a static String[] as "owner:member:descriptor" plus trailing
 * spaces, where the number of spaces says which operation it was. javac puts
 * these literals in the constant pool verbatim, which is all jdec needs - the
 * decoding is pure text, nothing has to be executed.
 */
public class IndyEncoded {
    private static final String[] TABLE = {
        "net/minecraft/client/Minecraft:runTick:()V  ",
        "net/minecraft/entity/PlayerEntity:tick:()V  ",
        "com/example/Api:getToken:()Ljava/lang/String; ",
        "net/minecraft/client/Minecraft:fps:Ljava/lang/String;   ",
        "com/example/LicenseManager:serial:Ljava/lang/String;    ",
        "net/minecraft/entity/PlayerEntity:isAlive:()Z  ",
    };

    private static final Class<?>[] TYPES = {
        String.class, String.class, String.class,
    };

    public static String lookup(int i) {
        return TABLE[i];
    }

    public static Class<?> type(int i) {
        return TYPES[i];
    }
}
