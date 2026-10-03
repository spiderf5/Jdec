package demo.legacy;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class OldStyle {

    public interface Callback {
        void run(int value);
    }

    public void spawn(final int n) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                for (int i = 0; i < n; i++) {
                    System.out.println("tick " + i);
                }
            }
        }).start();
    }

    public void withCallback(Callback cb) {
        for (int i = 0; i < 4; i++) {
            cb.run(i * i);
        }
    }

    public String pick(String key) {
        switch (key) {
            case "alpha":
                return "A";
            case "beta":
                return "B";
            case "gamma":
                return "C";
            default:
                return "?";
        }
    }

    public int messy(int a) {
        int r = 0;
        try {
            r = 10 / a;
        } catch (ArithmeticException e) {
            r = -1;
        } finally {
            r = r * 2;
        }
        return r;
    }

    public String nested(int a, int b, int c) {
        return a > b ? (b > c ? "x" : "y") : (c > a ? "z" : "w");
    }

    public Map<String, Integer> tally(List<String> words) {
        Map<String, Integer> counts = new HashMap<String, Integer>();
        for (String w : words) {
            Integer prev = counts.get(w);
            counts.put(w, prev == null ? 1 : prev + 1);
        }
        return counts;
    }

    public List<String> filtered(List<String> in) {
        List<String> out = new ArrayList<String>();
        for (String s : in) {
            if (s != null && s.length() > 3) {
                out.add(s.toUpperCase());
            }
        }
        return out;
    }
}
