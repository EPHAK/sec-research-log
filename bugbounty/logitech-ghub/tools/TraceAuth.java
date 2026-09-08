// For a set of seed functions, dump the function, its callers (2 levels), and referenced strings.
// @category Logi
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class TraceAuth extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outDir = System.getenv("GH_OUT");
        if (outDir == null) outDir = "/tmp/ghout";
        String seedsEnv = System.getenv("GH_SEEDS");   // comma separated hex addrs
        if (seedsEnv == null || seedsEnv.isEmpty()) { println("no GH_SEEDS"); return; }
        new File(outDir).mkdirs();
        String base = currentProgram.getName();

        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager refs = currentProgram.getReferenceManager();
        Listing listing = currentProgram.getListing();

        Set<Function> level0 = new LinkedHashSet<>();
        for (String s : seedsEnv.split(",")) {
            s = s.trim();
            if (s.isEmpty()) continue;
            Address a = currentProgram.getAddressFactory().getAddress(s);
            Function f = fm.getFunctionContaining(a);
            if (f != null) level0.add(f);
        }

        // expand callers
        Set<Function> all = new LinkedHashSet<>(level0);
        Set<Function> frontier = new LinkedHashSet<>(level0);
        for (int depth = 0; depth < 2; depth++) {
            Set<Function> next = new LinkedHashSet<>();
            for (Function f : frontier) {
                for (Reference r : refs.getReferencesTo(f.getEntryPoint())) {
                    Function c = getFunctionContaining(r.getFromAddress());
                    if (c != null && all.add(c)) next.add(c);
                }
            }
            frontier = next;
            if (frontier.isEmpty()) break;
        }

        PrintWriter rep = new PrintWriter(new File(outDir, base + ".auth.txt"));
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);

        for (Function f : all) {
            rep.println("\n/* ===== " + f.getName() + " @ " + f.getEntryPoint()
                    + (level0.contains(f) ? "  [SEED]" : "") + " ===== */");
            // strings referenced inside this function
            List<String> strs = new ArrayList<>();
            AddressSetView body = f.getBody();
            InstructionIterator ii = listing.getInstructions(body, true);
            while (ii.hasNext()) {
                Instruction ins = ii.next();
                for (Reference r : ins.getReferencesFrom()) {
                    Data d = listing.getDataAt(r.getToAddress());
                    if (d != null && d.getValue() instanceof String) {
                        String v = (String) d.getValue();
                        if (v.length() > 3 && strs.size() < 40) strs.add(v.replace("\n", "\\n"));
                    }
                }
            }
            if (!strs.isEmpty()) {
                rep.println("  STRINGS: ");
                for (String s : strs) rep.println("    | " + s.substring(0, Math.min(150, s.length())));
            }
            DecompileResults r2 = di.decompileFunction(f, 200, monitor);
            if (r2.decompileCompleted()) rep.print(r2.getDecompiledFunction().getC());
            else rep.println("/* decompile failed */");
            rep.flush();
        }
        rep.close();
        di.dispose();
        println("TraceAuth: dumped " + all.size() + " functions");
    }
}
