import com.strobel.assembler.metadata.JarTypeLoader;
import com.strobel.assembler.metadata.MetadataSystem;
import com.strobel.assembler.metadata.TypeDefinition;
import com.strobel.assembler.metadata.TypeReference;
import com.strobel.decompiler.DecompilationOptions;
import com.strobel.decompiler.DecompilerSettings;
import com.strobel.decompiler.PlainTextOutput;

import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Thin CLI over the Procyon API (the released jar ships no command line driver).
 * Usage: ProcyonBridge <input.jar> <outputDir> [flatten:0|1] [only:internal/Name;other]
 */
public class ProcyonBridge {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: ProcyonBridge <jar> <outDir> [flatten]");
            System.exit(2);
        }
        String in = args[0];
        Path outDir = Paths.get(args[1]);
        boolean flatten = args.length > 2 && "1".equals(args[2]);

        DecompilerSettings settings = DecompilerSettings.javaDefaults();
        settings.setForceExplicitImports(true);
        settings.setFlattenSwitchBlocks(true);
        settings.setShowSyntheticMembers(false);
        settings.setRetainRedundantCasts(true);
        settings.setUnicodeOutputEnabled(true);
        settings.setMergeVariables(flatten);
        DecompilationOptions options = new DecompilationOptions();
        options.setSettings(settings);
        options.setFullDecompilation(true);

        int ok = 0, fail = 0;
        try (JarFile jar = new JarFile(in)) {
            MetadataSystem metadata = new MetadataSystem(new JarTypeLoader(jar));
            List<JarEntry> entries = new ArrayList<>();
            Enumeration<JarEntry> en = jar.entries();
            while (en.hasMoreElements()) {
                JarEntry e = en.nextElement();
                if (!e.isDirectory() && e.getName().endsWith(".class")) {
                    entries.add(e);
                }
            }
            Collections.sort(entries, (x, y) -> x.getName().compareTo(y.getName()));
            for (JarEntry entry : entries) {
                String internal = entry.getName();
                internal = internal.substring(0, internal.length() - ".class".length());
                try {
                    TypeReference ref = metadata.lookupType(internal);
                    if (ref == null) {
                        fail++;
                        continue;
                    }
                    TypeDefinition type = ref.resolve();
                    if (type == null) {
                        fail++;
                        continue;
                    }
                    StringWriter w = new StringWriter();
                    settings.getLanguage().decompileType(type, new PlainTextOutput(w), options);
                    String src = w.toString();
                    if (src.trim().isEmpty()) {
                        fail++;
                        continue;
                    }
                    Path target = outDir.resolve(internal + ".java");
                    Files.createDirectories(target.getParent());
                    Files.write(target, src.getBytes(StandardCharsets.UTF_8));
                    ok++;
                } catch (Throwable t) {
                    fail++;
                }
            }
        }
        System.out.println("procyon: ok=" + ok + " fail=" + fail);
    }
}
