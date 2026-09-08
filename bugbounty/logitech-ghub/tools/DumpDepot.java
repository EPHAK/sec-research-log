// Dump functions around depot extraction, symlink creation, path traversal and updater IPC.
// @category Logi
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.io.File;
import java.io.PrintWriter;
import java.util.*;

public class DumpDepot extends GhidraScript {

    static final String[] TARGETS = {
        "Path traversal detected",
        "Broken symlink in depot",
        "Cannot extract unknown file",
        "Failed to create folder for extracted file",
        "Failed to extract local depots archive",
        "Failed to extract depot manifest",
        "logi.updater_ipc.protocol",
        "unable to connect from remote origin",
        "Connection rejected",
        "Blocked unsigned DLL",
    };
    // imports whose callers we want decompiled
    static final Set<String> DECOMP_IMPORTS = new HashSet<>(Arrays.asList(
        "CreateSymbolicLinkW", "WinVerifyTrust", "GetExtendedTcpTable"));
    // imports we only want a call-site map for
    static final Set<String> MAP_IMPORTS = new HashSet<>(Arrays.asList(
        "CreateSymbolicLinkW", "WinVerifyTrust", "GetExtendedTcpTable",
        "OpenProcessToken", "GetTokenInformation", "ImpersonateNamedPipeClient",
        "GetNamedPipeClientProcessId", "CreateNamedPipeW", "QueryFullProcessImageNameW",
        "CreateProcessAsUserW", "CreateProcessW", "DeviceIoControl"));

    @Override
    public void run() throws Exception {
        String outDir = System.getenv("GH_OUT");
        if (outDir == null) outDir = "/tmp/ghout";
        new File(outDir).mkdirs();
        String base = currentProgram.getName();

        Listing listing = currentProgram.getListing();
        ReferenceManager refs = currentProgram.getReferenceManager();
        SymbolTable st = currentProgram.getSymbolTable();

        PrintWriter map = new PrintWriter(new File(outDir, base + ".map.txt"));
        Set<Function> wanted = new LinkedHashSet<>();

        // --- strings ---
        Iterator<Data> it = listing.getDefinedData(true);
        int scanned = 0;
        while (it.hasNext()) {
            if (monitor.isCancelled()) break;
            Data d = it.next();
            scanned++;
            Object v = d.getValue();
            if (!(v instanceof String)) continue;
            String s = (String) v;
            for (String t : TARGETS) {
                if (!s.contains(t)) continue;
                map.println("STRING [" + t + "] @ " + d.getAddress() + " :: "
                        + s.substring(0, Math.min(160, s.length())).replace("\n", "\\n"));
                for (Function f : callers(refs, d.getAddress())) {
                    map.println("    <- " + f.getName() + " @ " + f.getEntryPoint());
                    wanted.add(f);
                }
                break;
            }
        }
        map.println("\n(scanned " + scanned + " defined data items)\n");

        // --- imports ---
        for (Symbol sym : st.getAllSymbols(true)) {
            if (monitor.isCancelled()) break;
            String n = sym.getName();
            if (!MAP_IMPORTS.contains(n)) continue;
            Set<Function> cs = callers(refs, sym.getAddress());
            if (cs.isEmpty()) continue;
            map.println("IMPORT " + n + " @ " + sym.getAddress());
            for (Function f : cs) {
                map.println("    <- " + f.getName() + " @ " + f.getEntryPoint());
                if (DECOMP_IMPORTS.contains(n)) wanted.add(f);
            }
        }

        map.println("\nDECOMPILING " + wanted.size() + " functions");
        map.close();

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        PrintWriter dec = new PrintWriter(new File(outDir, base + ".decomp.c"));
        for (Function f : wanted) {
            if (monitor.isCancelled()) break;
            dec.println("\n/* ============ " + f.getName() + " @ " + f.getEntryPoint() + " ============ */");
            DecompileResults r = di.decompileFunction(f, 240, monitor);
            if (r.decompileCompleted()) dec.print(r.getDecompiledFunction().getC());
            else dec.println("/* decompile failed: " + r.getErrorMessage() + " */");
            dec.flush();
        }
        dec.close();
        di.dispose();
        println("DumpDepot: wrote " + wanted.size() + " functions for " + base);
    }

    private Set<Function> callers(ReferenceManager refs, Address addr) {
        Set<Function> out = new LinkedHashSet<>();
        for (Reference r : refs.getReferencesTo(addr)) {
            Function f = getFunctionContaining(r.getFromAddress());
            if (f != null) out.add(f);
        }
        return out;
    }
}
