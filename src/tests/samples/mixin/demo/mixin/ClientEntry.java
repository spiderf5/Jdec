package demo.mixin;

/** Named as the Fabric client entrypoint so the fixture's metadata is real. */
public class ClientEntry {
    public void onInitializeClient() {
        System.out.println(Licence.decode(PAYLOAD));
    }

    private static final String PAYLOAD = "none";
}
