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
        java.util.List<Object[]> addrEntries = new java.util.ArrayList<>();
        // args[1..] 按 内容 判别:含制表符 = 地址表(mappings),否则 = 符号过滤表
        for (int ai = 1; ai < args.length; ai++) {
            File f = new File(args[ai]);
            if (!f.exists()) {
                continue;
            }
            java.util.List<String> lines = Files.readAllLines(f.toPath(), StandardCharsets.UTF_8);
            boolean isMappings = false;
            for (String line : lines) {
                if (line.contains("\t")) {
                    isMappings = true;
                    break;
                }
            }
            if (isMappings) {
                for (String line : lines) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;
                    String[] pp = line.split("\t");
                    if (pp.length < 2) continue;
                    try {
                        long ptr = Long.parseLong(pp[1].replace("0x", ""), 16);
                        // 第 3 列 = 运行时模块基址(frida 转储);缺省 -1 表示 ptr 已是偏移
                        long base = (pp.length > 2 && !pp[2].equals("-"))
                                ? Long.parseLong(pp[2].replace("0x", ""), 16) : -1;
                        addrEntries.add(new Object[]{pp[0], ptr, base});
                    } catch (NumberFormatException ignored) {
                    }
                }
            } else if (filterSymbols == null) {
                filterSymbols = new HashSet<String>(lines);
            }
        }
        long imageBase = currentProgram.getImageBase().getOffset();

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

        // 地址表模式:frida regnatives 转储的动态注册函数(无静态导出)
        ghidra.program.model.address.AddressFactory addrFactory =
            currentProgram.getAddressFactory();
        for (Object[] entry : addrEntries) {
            String name = (String) entry[0];
            long ptr = (Long) entry[1];
            long rtBase = (Long) entry[2];
            // frida 记录的是运行时地址(ASLR);有 base 就换算成文件偏移,
            // 再加到 Ghidra 的镜像基址上
            ghidra.program.model.address.Address addr =
                addrFactory.getDefaultAddressSpace().getAddress(
                    rtBase >= 0 ? imageBase + (ptr - rtBase) : ptr);
            Function func = getFunctionAt(addr);
            if (func == null) {
                func = createFunction(addr, name);
            }
            if (func == null) {
                println("[jdec-ghidra] ! cannot create function at " + addr + " (" + name + ")");
                continue;
            }
            totalFound++;
            println("[jdec-ghidra] Decompiling (addr-table): " + name + " @ " + addr);

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
                        pw.println(" * Decompiled by Ghidra (jdec native engine, address table)");
                        pw.println(" * Program   : " + currentProgram.getName());
                        pw.println(" * Function  : " + name);
                        pw.println(" * RuntimePtr: 0x" + Long.toHexString(ptr));
                        pw.println(" * Address   : " + func.getEntryPoint());
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
                               .append("\"entry\": \"").append(addr).append("\", ")
                               .append("\"file\": \"src/").append(safeName).append(".c\"")
                               .append("}");
                    firstEntry = false;
                    decompiledCount++;
                }
            } else {
                println("[jdec-ghidra] Failed/timed out decompiling (addr-table): " + name);
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
