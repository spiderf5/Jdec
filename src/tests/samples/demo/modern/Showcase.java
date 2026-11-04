package demo.modern;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

public class Showcase {

    public record Point(int x, int y) {
        public String label() {
            return "p" + x + ":" + y;
        }
    }

    sealed interface Shape permits Circle, Rect {
    }

    record Circle(double r) implements Shape {
    }

    record Rect(double w, double h) implements Shape {
    }

    public double area(Shape s) {
        return switch (s) {
            case Circle c -> Math.PI * c.r() * c.r();
            case Rect r -> r.w() * r.h();
        };
    }

    public String classify(int n) {
        return switch (n) {
            case 1, 2, 3 -> "small";
            default -> {
                if (n > 100) {
                    yield "huge";
                }
                yield "medium";
            }
        };
    }

    public Map<String, List<Integer>> group(Collection<String> in) {
        Map<String, List<Integer>> out = new HashMap<>();
        for (String s : in) {
            out.computeIfAbsent(s, k -> new ArrayList<>()).add(s.length());
        }
        return out;
    }

    public <T extends Comparable<T>> T maxOf(List<T> xs, T fallback) {
        T best = fallback;
        for (T x : xs) {
            if (best == null || x.compareTo(best) > 0) {
                best = x;
            }
        }
        return best;
    }

    public Function<String, String> pipeline() {
        return s -> s.trim().toLowerCase().replace(' ', '_');
    }

    public String readFirstLine(Path p) {
        try (BufferedReader r = Files.newBufferedReader(p)) {
            return r.readLine();
        } catch (IOException e) {
            return "";
        }
    }

    public int tricky(int a, int b) {
        int r = 0;
        for (int i = 0; i < a; i++) {
            for (int j = 0; j < b; j++) {
                if ((i ^ j) % 3 == 0) {
                    r += i * j;
                    continue;
                } else if (i > j) {
                    r -= 1;
                } else {
                    r += 2;
                }
            }
        }
        return r;
    }
}
