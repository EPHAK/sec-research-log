// Dump MessageWrapper<T> vtables and any tiny constant-returning methods. @category Logi
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import java.io.*;
import java.util.*;

public class Wrappers extends GhidraScript {
    public void run() throws Exception {
        String outFile = System.getenv("GH_OUTFILE");
        if (outFile == null) outFile = "/tmp/wrappers.txt";
        String pat = System.getenv("GH_PAT");
        if (pat == null) pat = "MessageWrapper<";
        PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(outFile)));
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        Memory mem = currentProgram.getMemory();
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();

        List<Symbol> vts = new ArrayList<>();
        SymbolIterator si = currentProgram.getSymbolTable().getAllSymbols(true);
        while (si.hasNext()) {
            Symbol s = si.next();
            String n = s.getName(true);
            if (n.endsWith("::vftable") && n.contains(pat)) vts.add(s);
        }
        println("vtables: " + vts.size());
        for (Symbol s : vts) {
            out.println("\n===== " + s.getName(true));
            out.println("      @ " + s.getAddress());
            for (int i = 0; i < 20; i++) {
                Address ta;
                try { ta = sp.getAddress(mem.getLong(s.getAddress().add(i*8L))); } catch (Exception e) { break; }
                Function f = fm.getFunctionAt(ta);
                if (f == null) break;
                long sz = f.getBody().getNumAddresses();
                String line = "  [" + i + "] " + f.getName() + " @" + ta + " size=" + sz;
                if (sz <= 48) {
                    DecompileResults r = di.decompileFunction(f, 30, monitor);
                    if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                        String c = r.getDecompiledFunction().getC().replaceAll("\\s+", " ");
                        line += "   >>> " + c;
                    }
                }
                out.println(line);
            }
        }
        out.flush(); out.close();
        di.dispose();
        println("done -> " + outFile);
    }
}
