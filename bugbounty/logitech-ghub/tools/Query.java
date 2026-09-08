// Multi-purpose query script driven by env vars. @category Logi
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.data.*;
import java.io.*;
import java.util.*;

public class Query extends GhidraScript {
    PrintWriter out;
    DecompInterface di;
    FunctionManager fm;
    ReferenceManager refs;

    String dec(Function f) {
        try {
            DecompileResults r = di.decompileFunction(f, 180, monitor);
            if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null)
                return r.getDecompiledFunction().getC();
            return "// decompile failed: " + (r==null?"null":r.getErrorMessage());
        } catch (Exception e) { return "// exception: " + e; }
    }

    Function funcOf(String spec) {
        spec = spec.trim();
        if (spec.isEmpty()) return null;
        if (spec.matches("(0x)?[0-9a-fA-F]{6,}")) {
            Address a = currentProgram.getAddressFactory().getAddress(spec.replaceFirst("^0x",""));
            return fm.getFunctionContaining(a);
        }
        for (Symbol s : currentProgram.getSymbolTable().getGlobalSymbols(spec)) {
            Function f = fm.getFunctionAt(s.getAddress());
            if (f != null) return f;
        }
        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) { Function f = it.next(); if (f.getName().equals(spec)) return f; }
        return null;
    }

    // all addresses that reference a symbol name (incl. thunks / IAT)
    List<Address> refsToName(String name) {
        List<Address> res = new ArrayList<>();
        SymbolIterator si = currentProgram.getSymbolTable().getSymbolIterator(name, true);
        while (si.hasNext()) {
            Symbol s = si.next();
            for (Reference r : refs.getReferencesTo(s.getAddress())) res.add(r.getFromAddress());
        }
        return res;
    }

    void header(String s) { out.println("\n\n/* ======================== " + s + " ======================== */"); }

    public void run() throws Exception {
        String outFile = System.getenv("GH_OUTFILE");
        if (outFile == null) outFile = "/tmp/ghquery.txt";
        out = new PrintWriter(new BufferedWriter(new FileWriter(outFile)));
        di = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        di.setOptions(opts);
        di.openProgram(currentProgram);
        fm = currentProgram.getFunctionManager();
        refs = currentProgram.getReferenceManager();

        String api = System.getenv("GH_API");        // comma list of API names: dump callers
        String decs = System.getenv("GH_DEC");       // comma list of func specs to decompile
        String xrefs = System.getenv("GH_XREF");     // comma list: list callers only
        String strq = System.getenv("GH_STR");       // substring: list matching strings + xrefs
        String symq = System.getenv("GH_SYM");       // substring: list matching symbols

        if (symq != null) for (String q : symq.split(";;")) {
            header("SYMBOLS matching: " + q);
            SymbolIterator si = currentProgram.getSymbolTable().getAllSymbols(true);
            int n=0;
            while (si.hasNext() && n<400) {
                Symbol s = si.next();
                if (s.getName(true).toLowerCase().contains(q.toLowerCase())) { out.println(s.getAddress()+"  "+s.getName(true)+"  ["+s.getSymbolType()+"]"); n++; }
            }
        }

        if (strq != null) for (String q : strq.split(";;")) {
            header("STRINGS matching: " + q);
            DataIterator dit = currentProgram.getListing().getDefinedData(true);
            int n=0;
            while (dit.hasNext() && n<300) {
                Data d = dit.next();
                if (d.getDataType() instanceof StringDataType || d.getDataType() instanceof TerminatedStringDataType
                    || d.getDataType() instanceof UnicodeDataType || d.getDataType() instanceof TerminatedUnicodeDataType
                    || (d.getDataType().getName()!=null && d.getDataType().getName().toLowerCase().contains("string"))) {
                    Object v = d.getValue();
                    if (v == null) continue;
                    String sv = v.toString();
                    if (sv.toLowerCase().contains(q.toLowerCase())) {
                        n++;
                        out.println("\n" + d.getAddress() + "  \"" + sv.replace("\n","\\n") + "\"");
                        for (Reference r : refs.getReferencesTo(d.getAddress())) {
                            Function cf = fm.getFunctionContaining(r.getFromAddress());
                            out.println("    <- " + r.getFromAddress() + (cf!=null? "  in "+cf.getName()+" @"+cf.getEntryPoint() : ""));
                        }
                    }
                }
            }
        }

        if (api != null) for (String name : api.split(",")) {
            name = name.trim(); if (name.isEmpty()) continue;
            header("CALLERS OF " + name);
            Set<Function> callers = new LinkedHashSet<>();
            for (Address a : refsToName(name)) {
                Function f = fm.getFunctionContaining(a);
                if (f == null) continue;
                // skip thunk wrappers -> follow up one level
                if (f.isThunk() || f.getBody().getNumAddresses() < 16) {
                    out.println("// thunk/stub " + f.getName() + " @" + f.getEntryPoint());
                    for (Reference r2 : refs.getReferencesTo(f.getEntryPoint())) {
                        Function g = fm.getFunctionContaining(r2.getFromAddress());
                        if (g != null) callers.add(g);
                    }
                } else callers.add(f);
                out.println("// ref at " + a + (f!=null?" in "+f.getName():""));
            }
            for (Function f : callers) {
                out.println("\n/* ---- " + f.getName() + " @ " + f.getEntryPoint() + " ---- */");
                out.println(dec(f));
            }
        }

        if (xrefs != null) for (String spec : xrefs.split(",")) {
            Function f = funcOf(spec);
            header("CALLERS OF " + spec + (f!=null? " ("+f.getName()+" @"+f.getEntryPoint()+")":" NOT FOUND"));
            if (f == null) continue;
            for (Reference r : refs.getReferencesTo(f.getEntryPoint())) {
                Function c = fm.getFunctionContaining(r.getFromAddress());
                out.println(r.getFromAddress() + "  " + r.getReferenceType() + (c!=null? "  in "+c.getName()+" @"+c.getEntryPoint():""));
            }
        }

        if (decs != null) for (String spec : decs.split(",")) {
            Function f = funcOf(spec);
            header("DECOMPILE " + spec + (f!=null? " -> "+f.getName()+" @"+f.getEntryPoint() : " NOT FOUND"));
            if (f == null) continue;
            out.println("// signature: " + f.getSignature());
            out.println(dec(f));
        }

        String disq = System.getenv("GH_DIS");       // comma list of start:end or funcspec
        if (disq != null) for (String spec : disq.split(",")) {
            header("DISASM " + spec);
            Address start, end;
            if (spec.contains(":")) {
                String[] pp = spec.split(":");
                start = currentProgram.getAddressFactory().getAddress(pp[0]);
                end = currentProgram.getAddressFactory().getAddress(pp[1]);
            } else {
                Function f = funcOf(spec);
                if (f == null) { out.println("NOT FOUND"); continue; }
                start = f.getBody().getMinAddress(); end = f.getBody().getMaxAddress();
            }
            InstructionIterator ii = currentProgram.getListing().getInstructions(start, true);
            while (ii.hasNext()) {
                Instruction in = ii.next();
                if (in.getAddress().compareTo(end) > 0) break;
                StringBuilder sb = new StringBuilder();
                sb.append(in.getAddress()).append("  ").append(in.toString());
                for (Reference r : in.getReferencesFrom()) {
                    Symbol sy = currentProgram.getSymbolTable().getPrimarySymbol(r.getToAddress());
                    if (sy != null) sb.append("   ; ").append(r.getToAddress()).append(" ").append(sy.getName());
                    Data d = currentProgram.getListing().getDataAt(r.getToAddress());
                    if (d != null && d.getValue() != null) sb.append("   = ").append(String.valueOf(d.getValue()).replace("\n","\\n"));
                }
                out.println(sb);
            }
        }

        String rng = System.getenv("GH_RANGE");     // start:end - decompile every function in range
        if (rng != null) for (String spec : rng.split(",")) {
            String[] pp = spec.split(":");
            Address st = currentProgram.getAddressFactory().getAddress(pp[0]);
            Address en = currentProgram.getAddressFactory().getAddress(pp[1]);
            header("RANGE DECOMPILE " + spec);
            FunctionIterator it = fm.getFunctions(st, true);
            int n = 0;
            while (it.hasNext()) {
                Function f = it.next();
                if (f.getEntryPoint().compareTo(en) > 0) break;
                n++;
                out.println("\n/* ---- " + f.getName() + " @ " + f.getEntryPoint() + " ---- */");
                out.println(dec(f));
                if (n % 25 == 0) { out.flush(); println("range " + n + " " + f.getEntryPoint()); }
            }
            println("range total " + n);
        }

        String refto = System.getenv("GH_REFTO");   // comma list of addresses: list refs to them
        if (refto != null) for (String spec : refto.split(",")) {
            Address a = currentProgram.getAddressFactory().getAddress(spec.trim());
            header("REFS TO " + spec);
            for (Reference r : refs.getReferencesTo(a)) {
                Function c = fm.getFunctionContaining(r.getFromAddress());
                out.println(r.getFromAddress() + "  " + r.getReferenceType()
                    + (c!=null? "  in "+c.getName()+" @"+c.getEntryPoint():""));
            }
        }

        String vt = System.getenv("GH_VTABLE");   // addr:count - dump pointer table
        if (vt != null) for (String spec : vt.split(",")) {
            String[] pp = spec.split(":");
            Address a = currentProgram.getAddressFactory().getAddress(pp[0]);
            int cnt = pp.length > 1 ? Integer.parseInt(pp[1]) : 24;
            header("VTABLE " + spec);
            Memory mem = currentProgram.getMemory();
            for (int i = 0; i < cnt; i++) {
                try {
                    long p2 = mem.getLong(a.add(i * 8L));
                    Address t = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(p2);
                    Function f = fm.getFunctionContaining(t);
                    out.println("  [" + i + "] " + t + (f != null ? "  " + f.getName() + " @" + f.getEntryPoint() : ""));
                } catch (Exception e) { out.println("  [" + i + "] <" + e + ">"); }
            }
        }

        out.flush(); out.close();
        di.dispose();
        println("done -> " + outFile);
    }
}
