# OS-Internals Glossary

Living reference for this repo's OS-internals notes. Every dated file links
here instead of re-explaining terms inline. Grows as new sessions add new
territory (memory management, VFS, scheduling, namespaces, ...) — this is
not scoped to any one book.

**Sourcing rule:** Tanenbaum & Bos (*Modern Operating Systems*) is the
reading spine because it's a reasonable map of the territory, but it's a
textbook aimed at teaching undergrads the concepts, not at describing what a
real kernel does. It doesn't get corrected here — it gets *supplemented*.
Where it matters, an entry cites something closer to the metal instead:

- the kernel source itself (`~/linuxsrc/linux`) — most authoritative for
  "what does Linux actually do"
- man pages (`man 2 clone`, `man 7 pthreads`, `man 5 proc`, ...) — most
  authoritative for "what is the process/kernel contract with userspace,"
  and they're already installed locally (`man -w <name>` to find the path)
- `Documentation/` inside the kernel tree — authoritative for intent /
  design rationale that source comments don't always carry
- papers and other books, pulled in by name when a concept deserves more
  than a paragraph (e.g. Drepper's *"The Native POSIX Thread Library for
  Linux"* for **why** NPTL made the 1:1 thread-per-task choice §2.4 of the
  09-04 notes flags as unverified)

---

## Reading kernel C

| Term | What it means |
|---|---|
| `current` | Macro. "The task running right now on this CPU." |
| `p->tgid` | `p` is a pointer to a struct; `->` reads a field out of it. |
| `flags & CLONE_THREAD` | Bitwise AND — checks whether one specific bit is turned on. `flags = A \| B` turns both bits on; `flags & A` tests if `A`'s bit is set. |
| `SYSCALL_DEFINE0(getpid)` | Macro that builds a syscall function. The number = how many arguments it takes. |
| `static` | This function/variable is private to this one `.c` file. |
| `noinline`, `__ref`, `__noreturn` | Compiler hints. Safe to ignore while reading for meaning. |
| `struct foo x = { .a = 1 };` | Make a struct, set field `a` to 1, everything else zeroed. |
| `kmem_cache_zalloc()` | The kernel's "allocate one zeroed object from a pre-sized pool" call — its rough equivalent of `calloc()`, tuned for allocating many same-sized kernel structs fast. |
| `cmpxchg(ptr, old, new)` | Atomic compare-and-swap: "if `*ptr` still equals `old`, set it to `new`, all in one indivisible hardware step; tell me whether it worked." How the kernel lets multiple CPUs race to claim the same object without a lock. |

## Identity: processes, threads, PIDs

| Term | Source | What it means |
|---|---|---|
| task | kernel source, throughout | The kernel's only unit of "a thing that runs." What userspace calls a process and what it calls a thread are both just a `task_struct` — see PID/TGID below. |
| PID vs TGID | `man 2 clone`, `kernel/sys.c` | Confusingly, the kernel's internal `pid` field is the *per-task* ID (what userspace calls a TID and gets from `gettid()`), and `tgid` ("thread group ID") is the ID shared by every task in one userspace "process" — what `getpid()` actually returns. See the 09-04 notes §1.3. |
| thread group | `man 2 clone` | The kernel's name for what userspace calls "a process": one or more tasks sharing a `tgid`, created via `CLONE_THREAD`. |
| refcount | kernel source, throughout | A counter on a shared object: "how many tasks currently hold a pointer to me." Incremented when a pointer is copied (`mmget()`, `get_task_struct()`), decremented when a task drops it; the object is only freed at zero. This is what makes sharing (`CLONE_VM` etc.) memory-safe — nobody frees a struct another task still points at. |
| `mm_struct` | `include/linux/mm_types.h` | A process's address space: the list of mapped regions, the pointer to the top-level page table, memory accounting. `task_struct->mm` points at one. |
| VMA (`vm_area_struct`) | `include/linux/mm_types.h` | One mapped region inside an address space — "the heap," "this shared library," "this stack." An `mm_struct` is essentially a list of VMAs. |
| page table / PTE | `Documentation/mm/process_addrs.rst` | The hardware-walked structure translating a virtual address (what code sees) to a physical one (an actual RAM location). A PTE ("page table entry") is one page's translation plus permission bits (read/write/execute/present). Copy-on-write works by write-protecting PTEs in parent and child, then copying only the page that actually gets written. |
| `cred` (`struct cred`) | `include/linux/cred.h` | A task's identity for permission checks — UID, GID, capabilities. `task_struct->cred` points at one. The standard kernel-exploit finishing move (`commit_creds(prepare_kernel_cred(NULL))`) is just repointing this one field at a root `cred`. |
| namespace | `man 7 namespaces` | A kernel mechanism giving a group of tasks their own private view of something normally global — their own PID numbering, mount table, network stack, etc. Containers are built by combining several. `vnr` in `task_pid_vnr()` etc. = "as numbered inside my own PID namespace." |
| `ptrace` | `man 2 ptrace` | The syscall behind debuggers (`gdb`) and tracers (`strace`) — lets one process inspect/control another's registers, memory, and syscalls. A `ptrace`d task temporarily reports to a different `parent` than its `real_parent` (09-04 notes §1.9). |

## Signals, scheduling, synchronization

| Term | Source | What it means |
|---|---|---|
| RCU (read-copy-update) | `Documentation/RCU/whatisRCU.rst` | Kernel synchronization scheme for data read constantly but rarely written: readers walk it lock-free, and a writer replacing an entry defers freeing the old version until every CPU is guaranteed to be done reading it. Used wherever a list is walked without a lock, e.g. `for_each_process()`. |
| `tasklist_lock` | `kernel/fork.c`, `kernel/exit.c` | The lock protecting the global process/parent/child list structure during creation and reaping — why `copy_process()` and `release_task()` both take it. |
| pidhash / IDR | `kernel/pid.c`, `include/linux/idr.h` | The PID→task lookup structure. Not a flat array indexed by PID (what the textbook draws) — it's an IDR, a sparse tree mapping numbers to pointers, one per PID namespace. |
| BIO | `include/linux/blk_types.h` | The kernel's in-flight block I/O request — one struct per pending disk read/write. A task can sit in `D` state (`TASK_UNINTERRUPTIBLE`) while one is outstanding. |
| PSW (program status word) | Tanenbaum & Bos | The textbook's term (from an IBM-mainframe-flavored OS-teaching tradition) for "the CPU's flags/status register plus the program counter." Not a literal kernel struct field — on x86-64 it maps onto `RIP` + `RFLAGS`, saved in `task_struct->thread` across a context switch. |

## Security-relevant primitives

| Term | Source | What it means |
|---|---|---|
| ASLR | `man 5 proc` (`/proc/sys/kernel/randomize_va_space`) | Address Space Layout Randomization — stack, heap, libraries, and (for a PIE binary) the program's own code get placed at a random address each run, so an attacker can't hard-code addresses. Defeated by any single info leak, since offsets between regions are usually fixed. |
| stack canary / `%fs:0x28` | glibc/ABI, not kernel source | A known value placed between local variables and the saved return address; checked before a function returns. A stack-smashing overflow has to overwrite it on the way to the return address, and a mismatch aborts before the corrupted return address is ever used. Lives in thread-local storage on x86-64 Linux, hence the `fs:[0x28]` load seen in almost every function epilogue. |
| ELF / `PT_INTERP` / auxv | `man 5 elf` | ELF is Linux's executable/library file format. `PT_INTERP` is a field naming the dynamic linker (e.g. `/lib64/ld-linux-x86-64.so.2`) that actually runs first and loads everything else. `auxv` ("auxiliary vector") is a block of kernel-supplied key/value pairs placed on the new stack at exec time — page size, entry point, and an `AT_RANDOM` pointer used to seed the stack canary. |
| kernel-LPE finisher | kernel source, `include/linux/cred.h` | Shorthand for `commit_creds(prepare_kernel_cred(NULL))` — the one-liner that ends a huge fraction of Linux kernel exploits, because privilege in Linux is "whatever `task_struct->cred` points at," and that's one pointer write away from root. |

---

*Add to this file as new sessions surface new vocabulary — don't re-explain
a term inline in a dated notes file if it's already here; link to it
instead.*
