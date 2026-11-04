package demo.collide;

/** Case-twin of Widget: distinct body, distinct marker. Own source root. */
public class widget {
    public static final String MARKER = "lower-widget";

    private long widgetGamma;

    public long widgetGamma() {
        return this.widgetGamma;
    }

    public void widgetShift(long bits) {
        this.widgetGamma = bits << 3;
    }

    public String widgetRender() {
        return MARKER + ":" + this.widgetGamma;
    }
}
