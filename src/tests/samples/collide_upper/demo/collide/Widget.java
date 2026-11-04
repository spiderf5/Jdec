package demo.collide;

/**
 * ZKM-style name mangling can emit class names that differ only by letter case.
 * On a case-insensitive filesystem (Windows, macOS) `Widget.class` and
 * `widget.class` land on the same path, so a decompiler writing both into one
 * output directory silently loses one of them.
 *
 * Bodies differ in member names AND in MARKER, so "both classes came back"
 * cannot be satisfied by a single file being counted twice.
 *
 * This is the upper-case twin; it lives in its own source root because javac
 * cannot hold case-twin sources in one directory on Windows.
 */
public class Widget {
    public static final String MARKER = "upper-Widget";

    private int widgetAlpha;

    public int widgetAlpha() {
        return this.widgetAlpha;
    }

    public void widgetBump(int amount) {
        this.widgetAlpha += amount;
    }

    public String widgetDescribe() {
        return MARKER + ":" + this.widgetAlpha;
    }
}
