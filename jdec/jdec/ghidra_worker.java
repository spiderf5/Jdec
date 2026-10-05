// Ghidra headless script for jdec: decompiles JNI export functions and entry points.
//
// Usage via analyzeHeadless:
//   analyzeHeadless <projDir> <projName> -import <lib> -postScript ghidra_worker.java <outDir> [<filterFile>] -deleteProject

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ghidra_worker extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length == 0) {
            println("[jdec-ghidra] Error: outDir argument missing");
            return;
        }

        File outDir = new File(args[0]);
        File srcDir = new File(outDir, "src");
        if (!srcDir.exists()) {
            srcDir.mkdirs();
        }

        Set<String> filterSymbols = null;
        if (args.length > 1 && new File(args[1]).exists()) {
            filterSymbols = new HashSet<String>(Files.readAllLines(new File(args[1]).toPath(), StandardCharsets.UTF_8));
        }

        println("[jdec-ghidra] Analyzing program: " + currentProgram.getName());
        println("[jdec-ghidra] Output dir: " + outDir.getAbsolutePath());

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        int totalFound = 0;
        int decompiledCount = 0;
        StringBuilder jsonSummary = new StringBuilder();
        jsonSummary.append("{\n");
        jsonSummary.append("  \"program\": \"").append(currentProgram.getName()).append("\",\n");
        jsonSummary.append("  \"functions\": [\n");

        boolean firstEntry = true;
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            String name = func.getName();

            boolean isJni = name.startsWith("Java_") || name.equals("JNI_OnLoad") || name.equals("JNI_OnUnload");
            boolean inFilter = (filterSymbols != null && filterSymbols.contains(name));

            if (!isJni && !inFilter) {
                continue;
            }

            totalFound++;
            println("[jdec-ghidra] Decompiling: " + name + " @ " + func.getEntryPoint());

            DecompileResults res = decompiler.decompileFunction(func, 60, monitor);
            if (res != null && res.decompileCompleted()) {
                DecompiledFunction decompFunc = res.getDecompiledFunction();
                if (decompFunc != null) {
                    String cCode = decompFunc.getC();
                    String safeName = name.replaceAll("[^A-Za-z0-9_.$]", "_");
                    File outFile = new File(srcDir, safeName + ".c");

                    PrintWriter pw = new PrintWriter(new FileWriter(outFile));
                    try {
                        pw.println("/*");
                        pw.println(" * Decompiled by Ghidra (jdec native engine)");
                        pw.println(" * Program   : " + currentProgram.getName());
                        pw.println(" * Function  : " + name);
                        pw.println(" * Address   : " + func.getEntryPoint());
                        pw.println(" * Signature : " + func.getPrototypeString(true, true));
                        pw.println(" */");
                        pw.println();
                        pw.println(cCode);
                    } finally {
                        pw.close();
                    }

                    if (!firstEntry) {
                        jsonSummary.append(",\n");
                    }
                    jsonSummary.append("    {")
                               .append("\"name\": \"").append(name).append("\", ")
                               .append("\"entry\": \"").append(func.getEntryPoint()).append("\", ")
                               .append("\"file\": \"src/").append(safeName).append(".c\"")
                               .append("}");
                    firstEntry = false;
                    decompiledCount++;
                }
            } else {
                println("[jdec-ghidra] Failed/timed out decompiling: " + name);
            }
        }

        jsonSummary.append("\n  ],\n");
        jsonSummary.append("  \"total_matched\": ").append(totalFound).append(",\n");
        jsonSummary.append("  \"decompiled_count\": ").append(decompiledCount).append("\n");
        jsonSummary.append("}\n");

        File summaryFile = new File(outDir, "decompiled_summary.json");
        Files.write(summaryFile.toPath(), jsonSummary.toString().getBytes(StandardCharsets.UTF_8));

        println("[jdec-ghidra] Done: " + decompiledCount + "/" + totalFound + " functions decompiled to " + srcDir.getAbsolutePath());
    }
}
