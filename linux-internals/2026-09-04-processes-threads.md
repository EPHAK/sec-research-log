# 2026-09-04 — Processes & Threads

Book: *Modern Operating Systems* 5th ed., Tanenbaum & Bos.
PDF: `/home/ephak/research/books/mos-5th-tanenbaum.pdf`
Kernel source: `/home/ephak/linuxsrc/linux` @ v7.3

**Today: pp. 88–113.** From §2.1.2 (Process Creation) to §2.2.7.
I left off at p.87.

Page mapping: **PDF page = printed page + 29.** My paper copy is the Global
Edition so it might be off by a page — if so, find the section heading
instead.

> These notes were written before the session. Every line number was checked
> against the real source. Things marked `?` are things I have NOT verified —
> those are mine to check.
>
> **Closed out 2026-09-07** (a separate sitting): experiments run, results and
> answers filled in from `# Experiments` down. `?` lines still open on purpose.
>
> **2026-09-08:** added §1.6 (`struct task_struct` — what a process-table
> entry actually holds). Line numbers in that section are against
> v7.3.0-rc2 `include/linux/sched.h`.
>
> **2026-09-09:** added §1.7 (process creation — `kernel_clone` /
> `copy_process` / `execve`), §1.8 (termination & reaping), §1.9
> (hierarchies — groups & sessions). Fills the §2.1.2 / §2.1.3 / §2.1.4
> gaps. Line numbers against v7.3.0-rc2 (`kernel/fork.c`, `fs/exec.c`,
> `kernel/exit.c`).

---

## First: how to read kernel C

A few things show up constantly. Once you know them the code stops looking
scary.

| Thing | What it means |
|---|---|
| `current` | A macro. Means "the task running right now on this CPU." |
| `p->tgid` | `p` is a pointer to a struct. `->` reads a field out of it. |
| `flags & CLONE_THREAD` | Bitwise AND. Checks whether one specific bit is turned on. |
| `SYSCALL_DEFINE0(getpid)` | Macro that builds a syscall function. The `0` = takes zero arguments. |
| `static` | This function is private to this one `.c` file. |
| `noinline`, `__ref`, `__noreturn` | Hints to the compiler. Safe to ignore while reading. |
| `struct foo x = { .a = 1 };` | Make a struct and set field `a` to 1. Everything else = 0. |

The `&` one matters most. Flags are single bits packed into one integer:

```
   CLONE_VM     = 0x00000100   = bit 8
   CLONE_FILES  = 0x00000400   = bit 10
   CLONE_THREAD = 0x00010000   = bit 16

   flags = CLONE_VM | CLONE_FILES     ← OR means "turn both bits on"
   flags & CLONE_THREAD               ← AND means "is that bit on?" (here: no)
```

Terms used later without being re-defined inline (refcount, `mm_struct`,
VMA/PTE, `cred`, namespace, `ptrace`, ASLR, ELF/`PT_INTERP`/auxv, PSW, RCU,
...) live in **[`GLOSSARY.md`](GLOSSARY.md)**, shared across every dated
file in this directory. Check there before assuming a term is undefined.

---

# Part 1 — Processes (pp. 88–97)

## 1.1 Where PID 1 comes from

The book (p.89) says *"the very first process is hard-crafted when the system
is booted."* That sounds vague. It isn't — I can point at the code.

`init/main.c:676`:

```c
static noinline void __ref __noreturn rest_init(void)
{
	struct kernel_clone_args init_args = {
		.flags		= (CLONE_VM | CLONE_UNTRACED),
		.fn		= kernel_init,
	};
	...
	/*
	 * We need to spawn init first so that it obtains pid 1, however
	 * the init task will end up wanting to create kthreads, which, if
	 * we schedule it before we create kthreadd, will OOPS.
	 */
	pid = kernel_clone(&init_args);          // <-- PID 1
	...
	pid = kernel_thread(kthreadd, NULL, NULL, CLONE_FS | CLONE_FILES);  // PID 2
```

**What this code does, line by line:**

- `struct kernel_clone_args init_args = {...}` — fill in a form describing
  the process we want to create. Two fields get set:
  - `.flags` — how much the new task shares with its creator.
  - `.fn = kernel_init` — the function the new task will start running.
    So the new process begins life running a *kernel function*, not a program
    from disk.
- `kernel_clone(&init_args)` — hand that form to the process creator.
  `&` means "the address of", because it wants a pointer. This is the
  kernel's internal version of `fork()`. It returns the new PID.
- `kernel_thread(kthreadd, ...)` — do it again, this time running the
  function `kthreadd`. That becomes PID 2.

**The interesting bit is the comment.** It says *"so that it obtains pid 1."*
Nothing assigns PID 1 to init. init just asks for a PID first, and PIDs are
handed out in order. The kernel deliberately orders these two calls so init
wins the race.

```
          start_kernel()            init/main.c:982
                │
                │  (~40 init calls: memory, scheduler, timers, ...)
                ▼
          rest_init()               init/main.c:676
                │
      ┌─────────┴─────────┐
      ▼                   ▼
   PID 1                PID 2
  kernel_init          kthreadd
      │                   │
      │ execve            │ creates all the [bracketed] kernel threads
      ▼                   │
  /sbin/init         ┌────┴────┬─────────┐
      │              ▼         ▼         ▼
  everything     [kworker] [ksoftirqd] [rcu_...]
  in userspace
```

**Something the book doesn't mention:** the process tree has *two* roots.
§2.1.4 draws one tree with init on top. Really there are two families —
normal programs under PID 1, and kernel threads under PID 2. In `ps` the
kernel ones show up in `[square brackets]`.

**Check it:**
```
ps -p 1 -o pid,comm
ps -p 2 -o pid,comm
ps --ppid 2 | head
```

## 1.2 Booting uses the same fork/exec trick from p.90

p.90 explains that UNIX creates a program in two steps: `fork` makes a copy
of the current process, then `execve` throws away that copy's program and
loads a new one. The book presents this as something shells do.

Booting does the exact same two steps:

```
   kernel_clone()                    kernel_execve()
        │                                  │
        ▼                                  ▼
   ┌─────────┐   running kernel code  ┌──────────┐
   │ PID 1   │ ────────────────────►  │  PID 1   │
   │ =kernel │                        │ =/sbin/  │
   │  _init  │                        │   init   │
   └─────────┘                        └──────────┘
    kernel thread                      normal program
        └──────── same task ───────────────┘
         step 1: fork      step 2: exec
```

Step 2 is `run_init_process()` at `init/main.c:1467`. Its last line:

```c
	return kernel_execve(init_filename, argv_init, envp_init);
```

**What this does:** `kernel_execve` takes three things — the path to a
program (`init_filename`, e.g. `/sbin/init`), its command-line arguments
(`argv_init`), and its environment variables (`envp_init`). It replaces the
current task's program with that file. Same idea as `execve()` from
userspace.

So PID 1 starts as a kernel thread, then **replaces itself with a program
from disk.** That's the same fork-then-exec pattern as a shell running
`sort` — just applied at the boundary between the kernel and normal programs.

Right below it there's a fallback list (`init/main.c:1617`):

```c
	if (!try_to_run_init_process("/sbin/init") ||
	    !try_to_run_init_process("/etc/init") ||
	    !try_to_run_init_process("/bin/init") ||
	    !try_to_run_init_process("/bin/sh"))
		return 0;

	panic("No working init found.  Try passing init= option to kernel. ...");
```

**What this does:** try each path in turn. These functions return 0 on
success, so `!` (logical NOT) turns success into true. `||` stops at the
first one that works. If all four fail, `panic()` — the kernel gives up and
halts.

**Security note — worth remembering.** There's a variable `execute_command`
at line 1599 that gets tried *before* all four of these. It comes from the
`init=` option on the kernel command line.

That means: if I can edit the bootloader line and add `init=/bin/sh`, the
kernel runs a shell as PID 1 instead of the real init. No login, no password
— because I've replaced PID 1 *before* any login code exists to run. This is
the classic physical-access root trick, and it's also why bootloader
passwords and Secure Boot exist. My first concrete example of the boot
process being attack surface.

## 1.3 getpid() does not return what I assumed

`kernel/sys.c:999`:

```c
SYSCALL_DEFINE0(getpid)
{
	return task_tgid_vnr(current);
}

/* Thread ID - the internal kernel "pid" */
SYSCALL_DEFINE0(gettid)
{
	return task_pid_vnr(current);
}
```

**What this does:**

- `SYSCALL_DEFINE0(getpid)` — defines the `getpid` system call. `0` = no
  arguments.
- `current` — the task calling this right now.
- `task_tgid_vnr(current)` — get this task's **tgid** ("thread group ID").
- `task_pid_vnr(current)` — get this task's **pid**.

So `getpid()` gives you the **tgid**, and `gettid()` gives you the **pid**.
That's backwards from what the names suggest. The kernel's own comment
translates it: *"Thread ID — the internal kernel 'pid'."*

| What I call it | What the kernel calls it | Which syscall returns it |
|---|---|---|
| PID (a process) | `tgid` | `getpid()` |
| TID (one thread) | `pid` | `gettid()` |

```
  what I'd call "one process with 3 threads"
  ┌──────────────────────────────────────┐
  │  tgid = 4021                         │   getpid() → 4021 (all three)
  │                                      │
  │   task        task        task       │
  │  pid=4021    pid=4022    pid=4023    │   gettid() → 4021 / 4022 / 4023
  │  (leader)                            │
  └──────────────────────────────────────┘
        ▲
        │ the kernel just sees three tasks
        │ that happen to share a tgid
```

**Why it's like this:** Linux has no separate "process" object. It only has
tasks. A "process" is just *a group of tasks that share a tgid*. The book
teaches processes in §2.1 and threads in §2.2 as two different things. Linux
builds one thing and gets both out of it.

The `vnr` at the end of those function names means "virtual number" — the ID
*as seen from the caller's PID namespace*. That's why PID 1 inside a Docker
container isn't PID 1 on the host. Whole isolation system hiding behind three
letters. `?` — I haven't looked at namespaces yet.

## 1.4 Process states — the book says 3, Linux has more

Fig. 2-2 (p.93) gives three: Running, Ready, Blocked. Now
`include/linux/sched.h:107`:

```c
#define TASK_RUNNING			0x00000000
#define TASK_INTERRUPTIBLE		0x00000001
#define TASK_UNINTERRUPTIBLE		0x00000002
#define __TASK_STOPPED			0x00000004
#define EXIT_DEAD			0x00000010
#define EXIT_ZOMBIE			0x00000020
#define TASK_DEAD			0x00000080
```

**What this is:** just names for numbers. Each one is a single bit
(1, 2, 4, 16, 32, 128), so several can be combined into one value and tested
with `&`.

Two places the book and reality disagree:

```
   BOOK (Fig 2-2)                 LINUX
   ─────────────                  ─────
                                  TASK_RUNNING (0x0)
   ┌─────────┐                    ┌───────────────────────┐
   │ Running │◄──┐                │ means "able to run"   │
   └────┬────┘   │ 3              │                       │
        │ 2      │                │ whether it's ON a CPU │
        ▼        │                │ right now isn't       │
   ┌─────────┐   │                │ stored here at all    │
   │  Ready  │───┘                └───────────────────────┘
   └─────────┘

                                  splits into two:
   ┌─────────┐                    ┌──────────────────────┐
   │ Blocked │  ─────────────►    │ TASK_INTERRUPTIBLE   │ signals can wake it
   └─────────┘                    ├──────────────────────┤
                                  │ TASK_UNINTERRUPTIBLE │ ignores signals
                                  └──────────────────────┘  shows as 'D' in ps
```

**(a) Linux doesn't separate Running from Ready.** Both are `TASK_RUNNING`
(zero). The book's arrows 2 and 3 — the scheduler picking or removing a
process — don't change the state field at all. Whether a task is actually on
a CPU is tracked somewhere else (in the scheduler's run queue), not in the
task's state.

**(b) "Blocked" is two different things in Linux.** And I've already run into
the difference:

- `TASK_INTERRUPTIBLE` — waiting, but a signal can wake it up. Normal.
- `TASK_UNINTERRUPTIBLE` — waiting and ignoring signals. This is `D` state in
  `ps`. It's why a process stuck on a dead network drive survives `kill -9`.

That last one is worth getting right: `kill -9` isn't special. Delivering a
signal works by *waking the task up*. A task in `TASK_UNINTERRUPTIBLE`
refuses to wake up, so there's nothing to deliver to. The signal isn't being
blocked — the task just never gets to the point of noticing it.

`EXIT_ZOMBIE` is the book's §2.1.3 "finished but nobody collected the exit
status yet" process, sitting there as the number 32.

**Check it:** `ps -eo pid,stat,comm | head -30` — look for `S` (sleeping,
most things), try to catch a `D`.

## 1.5 The "process table" is simplified in the book

p.94 says the OS keeps *"a table (an array of structures), called the process
table, with one entry per process."*

Linux doesn't have that array:

```
   BOOK                          LINUX
   ────                          ─────
   process_table[]               a sparse lookup tree, one per namespace
   ┌───┬───┬───┬───┬───┐         (called an "IDR")
   │ 0 │ 1 │ 2 │ 3 │ 4 │              pid_namespace.idr
   └───┴───┴───┴───┴───┘              include/linux/pid_namespace.h:27
   position in array = pid                    │
   one table for whole system           ┌─────┴─────┐
                                        ▼           ▼
                                   task_struct  task_struct
                                   (each one allocated on its own,
                                    linked together in lists)
```

Where things actually are:

- `struct task_struct` — `include/linux/sched.h:835`. One per task,
  allocated individually.
- Walking all of them: `for_each_process()` at
  `include/linux/sched/signal.h:640`.
- Looking up a PID: goes through an IDR (a tree that maps numbers to
  pointers), and there's **one per PID namespace** —
  `struct idr idr;` at `include/linux/pid_namespace.h:27`, filled in at
  `kernel/pid.c:240` and `:262`.

The reason is right there in the name `pid_namespace`. A single global array
can't handle "PID 1 means one thing on the host and a different thing inside
a container." You need a separate lookup table per namespace.

The book's array is a good way to *think* about it. It's just not what's
there.

## 1.6 What a process actually *is*: `struct task_struct`

§2.1.6 (p.95) says the OS keeps, per process, *"important information about
the process' state, including its program counter, stack pointer, memory
allocation, the status of its open files, its accounting and scheduling
information, and everything else about the process that must be saved."*
Fig. 2-4 draws that as a tidy three-column table — about 25 rows, grouped
into *process management*, *memory management*, *file management*.

In Linux that "entry" is one struct, and it's the single most important
data structure in the kernel:

`include/linux/sched.h:835` — and it doesn't close until **line 1690**
(`} __attribute__ ((aligned (64)));`). ~850 lines, hundreds of fields.

**Why I couldn't find it just by scrolling.** Three reasons:

- It's ~850 lines long and a big fraction of every screen is `#ifdef
  CONFIG_...` / `#endif`. The fields are real; most are gated on a build
  option.
- It doesn't open with anything that looks "process-y". The first field
  (`sched.h:841`) is `struct thread_info thread_info;`, itself behind
  `#ifdef CONFIG_THREAD_INFO_IN_TASK`. `pid` doesn't appear until
  **line 1080**.
- The bulk of it is bracketed by two markers — `randomized_struct_fields_start`
  (`:852`) and `..._end` (`:1689`). At build time the layout between those
  can be shuffled, so source order doesn't even map to memory order.

Just jump straight in:

```
grep -n 'struct task_struct {' include/linux/sched.h     # -> 835
```

**Fig. 2-4's rows, mapped onto the real fields** (v7.3, lines in `sched.h`):

| Fig. 2-4 row | `task_struct` field | line |
|---|---|---|
| Registers, program counter, PSW | `struct thread_struct thread` — CPU state, saved on switch | 1683 |
| Stack pointer / kernel stack | `void *stack` | 854 |
| Process state | `unsigned int __state` | 843 |
| Priority, scheduling parameters | `prio` / `static_prio` / `rt_priority`; `struct sched_entity se` | 884, 889 |
| Process ID | `pid_t pid`, `pid_t tgid` | 1080–1081 |
| Parent process | `real_parent`, `parent` | 1094, 1097 |
| (children / siblings) | `struct list_head children`, `sibling` | 1102–1103 |
| Process group / session | inside `struct signal_struct *signal` | 1218 |
| Signals | `signal`, `sighand`, `blocked`, `pending` | 1218–1224 |
| Time started, CPU time used | `start_time`; `utime` / `stime`; `nvcsw` / `nivcsw` | 1151, 1131, 1147 |
| Memory-management column | `struct mm_struct *mm`, `*active_mm` | 980–981 |
| Root dir, working dir | `struct fs_struct *fs` | 1204 |
| File descriptors | `struct files_struct *files` | 1207 |
| User ID, Group ID | `const struct cred *cred`, `*real_cred` | 1176, 1173 |

Everything in Fig. 2-4 is in there. The book isn't wrong — it's drawing 25
rows where Linux has more than a screenful of scheduler fields alone.

**The real structural difference: Linux doesn't inline it all.** Fig. 2-4's
"memory management" and "file management" columns are, in Linux, *pointers
to separate structs*:

```
        struct task_struct   (one per thread)
        ┌───────────────────────────────────────┐
        │ __state  pid  tgid  comm  prio  se ... │  inlined: this task's own
        │                                       │
        │ mm      ──────►  struct mm_struct      │  address space
        │ fs      ──────►  struct fs_struct      │  cwd / root
        │ files   ──────►  struct files_struct   │  the fd table
        │ signal  ──────►  struct signal_struct  │  process-wide signal state
        │ sighand ──────►  struct sighand_struct │  handler table
        │ cred    ──────►  struct cred           │  uid / gid / caps
        │ nsproxy ──────►  struct nsproxy        │  which namespaces
        │ cgroups ──────►  struct css_set        │  which cgroups
        └───────────────────────────────────────┘
```

That indirection *is* the thread mechanism from §2.2. `fork()` allocates
fresh copies of those sub-structs; `pthread_create()` passes `CLONE_VM |
CLONE_FILES | CLONE_FS | CLONE_SIGHAND | CLONE_THREAD`, and the new
`task_struct` just **copies the pointers** — same `mm`, same `files`, same
`signal`. §2.2's "the difference is one `if`" and this are the same fact
from two sides: the `if` decides whether `->signal` is shared; the struct
layout is *why* sharing one pointer is all it takes.

So §1.5 and §1.6 are the two halves of the book's "process table":

- **§1.6 (this) — what one entry holds:** `struct task_struct`.
- **§1.5 — how entries are stored and found:** not `table[pid]`, but each
  one allocated on its own, chained on the `tasks` list (`sched.h:976`),
  looked up by PID through the per-namespace IDR.

**Why `__state` is field #2.** The struct opens with `thread_info` (`:841`),
then `__state` (`:843`), then the marker `randomized_struct_fields_start`
(`:852`). The source comment on that marker: *"Only scheduling-critical
items should be added above here."* What sits before it is at a fixed offset
in the first cache line(s) and is exempt from the build-time layout
randomization that can reorder everything after. `__state` — the
Running/blocked field from §1.4 — is put there because it's read on every
scheduling decision.

**`current` is a `struct task_struct *`.** Every `current->pid`,
`current->mm`, `current->cred` in kernel code — and in every kernel-exploit
write-up — is a reach into this struct for the running task. Which leads to:

**Security notes.**

- The standard kernel-LPE finisher, `commit_creds(prepare_kernel_cred(NULL))`,
  is just getting `current->cred` (`sched.h:1176`) to point at a
  full-privilege `cred`. The whole target is one pointer in this struct.
- `unsigned long stack_canary` lives here too (`sched.h:1085`, under
  `CONFIG_STACKPROTECTOR`) — the *kernel* stack protector, separate from the
  userland `%fs:0x28` one in §2.5, same idea one level down.
- `struct sysv_sem sysvsem` / `struct sysv_shm sysvshm` (`sched.h:1195`) —
  System V IPC state hangs straight off the task. First hook into the IPC
  half of this topic.

**Check it** — without reading 850 lines of `#ifdef`:

```
# real field offsets + sizes for the running kernel's build:
pahole -C task_struct /sys/kernel/btf/vmlinux | less

# many of these fields, per task, as text:
grep -E '^(Name|State|Tgid|Pid|PPid|Uid|Gid|Threads):' /proc/self/status
```

`?` — haven't opened `mm_struct` / `files_struct` / `signal_struct`
themselves yet (next PLAN.md item). `?` — haven't run `pahole` to see how
big `task_struct` really is under a normal config. `?` — is
`thread_info`-first an x86 thing or every arch?

## 1.7 Process creation, the actual path (§2.1.2, pp. 88–90)

§2.1.2 lists **four events** that create a process: system initialization, a
process-creation syscall by a running process, a user request, a batch job.
Then: *"in UNIX, there is only one system call to create a new process:
`fork`"* — which *"creates an exact clone of the calling process"* — and the
child *"usually then executes `execve` or a similar system call."*

§1.1 / §1.2 covered event #1 and the fork→exec *shape* at the boot boundary.
This is the general path any `fork()` / shell command / `posix_spawn` runs.

**"One system call" — actually four, all landing in one place.**
`kernel/fork.c`:

```c
SYSCALL_DEFINE0(fork)                 // fork.c:2847
SYSCALL_DEFINE0(vfork)                // fork.c:2863   CLONE_VFORK | CLONE_VM
SYSCALL_DEFINE5(clone, ...)           // fork.c:2876   glibc pthread_create / posix_spawn
SYSCALL_DEFINE2(clone3, ...)          // fork.c:3048
```

Each fills a `struct kernel_clone_args` and calls **`kernel_clone()`**
(`fork.c:2712`). The book's "one system call" is the UNIX *API* promise; the
kernel has run `clone`/`clone3` underneath for years. `fork` is just `clone`
with an almost-empty flag set (Exp 4 showed it — `SIGCHLD` plus TID
housekeeping, nothing shared).

**`kernel_clone()` skeleton** (`fork.c:2712`):

```
kernel_clone(args)
  ├─ p = copy_process(NULL, trace, NUMA_NO_NODE, args)   // build the task     fork.c:2766
  ├─ pid = get_task_pid(p, PIDTYPE_PID);  nr = pid_vnr(pid)
  ├─ if CLONE_VFORK:  p->vfork_done = &vfork;  init_completion(&vfork)
  ├─ wake_up_new_task(p)                                 // give it to the sched  fork.c:2797
  ├─ if CLONE_VFORK:  wait_for_vfork_done(p, &vfork)     // parent sleeps here    fork.c:2804
  └─ return nr                                           // parent gets child PID
```

Between `copy_process` and `wake_up_new_task` the task fully exists but has
never run.

**`copy_process()` — "exact clone" is a column of `copy_*` calls**
(`fork.c:2012`). The core (`fork.c:2277`–`2316`):

```c
retval = sched_fork(clone_flags, p);      // 2277  priority etc., not on a runqueue yet
retval = copy_files(clone_flags, p, ...); // 2295  fd table
retval = copy_fs(clone_flags, p, ...);    // 2298  cwd / root
retval = copy_sighand(clone_flags, p);    // 2301  handler table
retval = copy_signal(clone_flags, p);     // 2304  signal_struct (process-wide signal state)
retval = copy_mm(clone_flags, p);         // 2307  address space
retval = copy_namespaces(clone_flags, p); // 2310  nsproxy
retval = copy_io(clone_flags, p);         // 2313  io context
retval = copy_thread(p, args);            // 2316  CPU regs + entry point; child will "return 0"
```

Every one has the same shape: **if the matching `CLONE_*` bit is set, bump a
refcount and share the pointer; else allocate a fresh copy.** That's §1.6's
"Linux doesn't inline it all" seen from the creation side. `copy_mm()`
(`fork.c:1568`) is the clearest:

```c
if (clone_flags & CLONE_VM) {
    mmget(oldmm);  mm = oldmm;            // share: a refcount
} else {
    mm = dup_mm(tsk, current->mm);        // copy: new mm_struct + dup_mmap()
}
```

**Copy-on-write lives here.** Book (p.90): *"the child may share all of the
parent's memory... copy-on-write... whenever either wants to modify part of
the memory, that chunk is explicitly copied first."* `dup_mm()`
(`fork.c:1527`) `memcpy`s the `mm_struct`, then `dup_mmap()` walks every VMA
and **write-protects the PTEs in parent and child**. The first write faults,
and the fault handler copies that one page. `fork()` copies *page tables*,
not memory. `?` — `dup_mmap` / `copy_page_range` are in `mm/`, not read yet
(that's the Memory Management session).

**Identity + tree linkage** — the block §2.2 quotes (`fork.c:2382`; §2.2's
`:2381` has drifted by one):

```c
p->pid = pid_nr(pid);
if (clone_flags & CLONE_THREAD) { p->group_leader = current->group_leader; p->tgid = current->tgid; }
else                            { p->group_leader = p;                     p->tgid = p->pid;         }
```

then under `tasklist_lock` (`fork.c:2455`–`2554`):

```c
if (clone_flags & (CLONE_PARENT|CLONE_THREAD))  p->real_parent = current->real_parent;  // 2459
else                                            p->real_parent = current;               // 2466
...
list_add_tail(&p->sibling, &p->real_parent->children);  // 2536  parent's child list
list_add_tail_rcu(&p->tasks, &init_task.tasks);         // 2537  global process list (leaders only)
attach_pid(p, PIDTYPE_PID);                             // 2551  pidhash / IDR
```

That last group is the other half of §1.5 — *where* a task gets threaded
onto `for_each_process`'s list and the PID-lookup structure.

**`vfork` is not a fossil.** `CLONE_VFORK | CLONE_VM`: the child shares the
parent's address space and the parent is **suspended** until the child
`execve`s or `_exit`s (confirmed in `man 2 vfork`, word for word). It skips
`dup_mmap` entirely.

**Correction (2026-09-11):** I'd written "`posix_spawn` in glibc is built on
[`vfork`]" — checked `man 3 posix_spawn` and that's not accurate for a
system running anything recent. Since **glibc 2.24**, `posix_spawn()` calls
`clone(2)` directly with `CLONE_VM | CLONE_VFORK` — the same *effect* as
`vfork` (shared address space, parent suspended) but not a call to the
`vfork()` function at all. This box is on glibc 2.43 (`ldd --version`), so
that's what actually runs here. Even the *pre*-2.24 behavior wasn't a flat
"built on vfork": it only used `vfork()` when there were no pre-exec
housekeeping steps requested (no `file_actions`, none of `SETSIGMASK` /
`SETSIGDEF` / `SETSCHEDPARAM` / `SETSCHEDULER` / `SETPGROUP` / `RESETIDS`);
otherwise it fell back to plain `fork()`. The accurate statement: `vfork`'s
*mechanism* (share the address space, suspend the parent) is what
`posix_spawn` is built to reuse — not literally a call to `vfork()`.

---

**The exec half** (`fs/exec.c`). `SYSCALL_DEFINE3(execve)` (`exec.c:2012`) →
`do_execveat_common()` (`exec.c:1877`):

```
do_execveat_common()                         exec.c:1877
  ├─ alloc struct linux_binprm  (the "binary parameters" scratchpad)
  ├─ count + copy argv/envp into the new stack
  └─ bprm_execve(bprm)                        exec.c:1823
       ├─ prepare_bprm_creds / check_unsafe_exec     // setuid decisions
       └─ exec_binprm(bprm)                   exec.c:1774
            └─ loop, max 5:  search_binary_handler(bprm)   exec.c:1740
                 └─ list_for_each_entry(fmt, &formats, ...) fmt->load_binary(bprm)
                      // binfmt_elf, binfmt_script (#!), binfmt_misc, ...
```

`search_binary_handler()` walks the registered format handlers.
`binfmt_script` handles `#!` — it rewrites `bprm->file` to the interpreter
and the loop runs again (hence the `depth > 5` → `-ELOOP` cap at
`exec.c:1788`: a `#!` pointing at a `#!` pointing at...). `binfmt_elf`
handles ELF.

**Point of no return: `begin_new_exec()`** (`exec.c:1124`), which the ELF
loader calls back into. After `bprm->point_of_no_return = true`
(`exec.c:1149`) a failure kills the process with SIGSEGV instead of
returning an error — the old program is already gone. It runs:

- `de_thread(me)` (`exec.c:1152`) — **kill every other thread in the group.**
  `execve` from a multithreaded process leaves exactly one task, now the
  group leader. (Ties to §2.2: exec collapses the thread group.)
- `unshare_files()` — private fd table.
- `set_mm_exe_file()` (`exec.c:1172`) — `/proc/self/exe` now points at the
  new binary.
- `exec_mmap()` (`exec.c:1185`, fn at `:843`) — **swap in a new `mm_struct`,
  drop the old one.** The address space from `fork` is discarded right here.
- `unshare_sighand()` (`exec.c:1206`) — private handler table; handlers reset
  to default (SIG_IGN survives).
- later `setup_new_exec()` (`exec.c:1361`) — commit the new `cred` (setuid
  takes effect here), new stack, `PF_RANDOMIZE` for ASLR.

`fork` gives the child copies of everything; `execve` throws most of them
away and installs fresh ones. The gap between the two is where the shell
does `dup2()` for redirection (book, p.90).

**Check it:**

```
strace -f -e trace=clone,clone3,execve,execveat -qq /bin/true   # one clone, one execve
bash -c 'echo shell=$$; exec sleep 60' &   # "exec" -> the sleep keeps the shell's PID
pmap $! | tail -1                            # its address space is sleep's, not bash's
```

`?` — haven't opened `binfmt_elf.c` / `load_elf_binary` (how segments get
mapped, `PT_INTERP` / `ld.so`, the initial stack with `auxv`). `?` —
`copy_thread` is arch code (`arch/x86/kernel/process.c`) — how the child is
rigged to "return 0" not traced yet.

## 1.8 Process termination & reaping (§2.1.3, pp. 90–91)

§2.1.3 gives **four ways** a process ends: normal exit (voluntary), error
exit (voluntary), fatal error — bad instruction, bad memory, divide-by-zero
(involuntary), killed by another process (involuntary). The first two are
`exit()`; the last two arrive as **signals**. All funnel into one place.

**libc `exit(3)` ≠ `SYSCALL_DEFINE1(exit)`.** C's `exit(3)` runs atexit
handlers then calls `_exit(2)` = `exit_group(2)`, ending the **whole thread
group**. The bare `exit(2)` syscall ends **one thread**. `kernel/exit.c`:

```c
SYSCALL_DEFINE1(exit, int, error_code)        // exit.c:1116  -> do_exit()        one task
SYSCALL_DEFINE1(exit_group, int, error_code)  // exit.c:1160  -> do_group_exit()  the process
```

`do_group_exit()` (`exit.c:1126`) sets `signal->group_exit_code`, flags
`SIGNAL_GROUP_EXIT`, calls `zap_other_threads()` (`exit.c:1146`) to send
every sibling a fatal signal, then `do_exit()`. A fatal signal (SIGSEGV,
SIGKILL, uncaught SIGTERM) reaches the same `do_group_exit()` from the
signal-delivery path — that's the book's "fatal error" and "killed by
another process".

**`do_exit()` — the teardown, in order** (`exit.c:928`):

```c
exit_signals(tsk);            // 950   sets PF_EXITING
tsk->exit_code = code;        // 977
exit_mm();                    // 996   drop the address space (mmput; free if last user)
exit_sem(tsk); exit_shm(tsk); // 1001  detach SysV IPC
exit_files(tsk);              // 1003  close the fd table
exit_fs(tsk);                 // 1004  drop cwd / root
exit_thread(tsk);             // 1009  arch cleanup
exit_notify(tsk, group_dead); // 1020  reparent children, tell the parent, become a zombie
do_task_dead();               // 1051  __state = TASK_DEAD; final schedule() — never returns
```

**The exit code is packed.** `SYSCALL_DEFINE1(exit)` does
`do_exit((error_code & 0xff) << 8)` — your low byte becomes bits 8–15 of
what `wait()` reports; a killing signal goes in the low 7 bits. That's what
`WEXITSTATUS` / `WTERMSIG` unpack.

**`exit_notify()` — zombie + reparenting** (`exit.c:770`):

```c
forget_original_parent(tsk, &dead);              // 777  hand my children to a new reaper
tsk->exit_state = EXIT_ZOMBIE;                    // 782  book's "finished, not yet collected"
autoreap = ... do_notify_parent(tsk, tsk->exit_signal);   // 787  SIGCHLD to the parent
if (autoreap) tsk->exit_state = EXIT_DEAD;        // 798  parent ignores SIGCHLD -> skip zombie
```

A task becomes `EXIT_ZOMBIE` (the number 32 from §1.4) the moment teardown
finishes. It holds nothing but its `task_struct` and exit status — `mm`,
files, fds already gone — until the parent `wait()`s.

**Reparenting — where orphans go** (`find_new_reaper()`, `exit.c:669`):

1. another live thread in the *same* group, if any;
2. else the nearest ancestor marked **child-subreaper**
   (`prctl(PR_SET_CHILD_SUBREAPER)` — how `systemd --user`, `tini`,
   container inits keep their descendants);
3. else the pid namespace's `child_reaper` — **PID 1**.

This is the book's *"processes in UNIX cannot disinherit their children"*
(p.92) made precise: the walk always terminates at PID 1, and PID 1 is
`SIGNAL_UNKILLABLE` (`fork.c:2523`) partly so it's always there to reap.

**`wait4()` — collection.** `SYSCALL_DEFINE4(wait4)` (`exit.c:1938`) →
`kernel_wait4` → `do_wait()` (`exit.c:1743`) → per matching child,
`wait_task_zombie()` (`exit.c:1206`):

```c
// exit.c:1230 — target state isn't always EXIT_DEAD:
state = (ptrace_reparented(p) && thread_group_leader(p)) ? EXIT_TRACE : EXIT_DEAD;
if (cmpxchg(&p->exit_state, EXIT_ZOMBIE, state) != EXIT_ZOMBIE)  // 1232  atomically claim it
    return 0;                                                    // another waiter won
wo->wo_stat = status;                                            // packed code back to caller
release_task(p);                                                 // 1313  task_struct freed
```

**Correction (2026-09-11):** I'd originally hardcoded `EXIT_DEAD` as the
second `cmpxchg` argument — wrong, it's a variable. If `p` is a
ptrace'd thread-group leader (`ptrace_reparented()` — §1.9's "`parent` !=
`real_parent`" case), the target is `EXIT_TRACE` instead, so the debugger
gets a chance to see the exit state before the task is actually freed.
Non-traced tasks (the overwhelming majority) still land on `EXIT_DEAD`
exactly as I'd written, so the diagram two blocks down is still correct for
that common case — just not the whole story.

`release_task()` (`exit.c:248`) unhooks it from the pidhash (the PID→task
lookup structure — §1.5's IDR), sibling list
and thread list; `__exit_signal` folds its CPU-time counters into the
parent's `signal_struct` — that's Fig. 2-4's *"Children's CPU time"* — and
drops the last ref.

```
   running ──do_exit()──► EXIT_ZOMBIE ──parent wait()s──► EXIT_DEAD ──release_task()──► gone
                              │
                    SIGCHLD sent to parent here; if the parent ignores
                    SIGCHLD / set SA_NOCLDWAIT, autoreap skips to EXIT_DEAD
```

**Check it:**

```
perl -e 'fork or exit 0; sleep 30' & sleep 1
ps -eo pid,ppid,stat,comm | awk '$3 ~ /Z/'                # STAT has Z, comm <defunct>
Z=$(ps -eo pid,stat --no-headers | awk '$2~/Z/{print $1; exit}')
grep -E 'State|VmRSS|Threads' /proc/$Z/status             # State Z; no VmRSS (mm gone)
strace -f -e trace=wait4,waitid -p "$(pgrep -n bash)"     # then run a command in that shell
```

`?` — the `get_signal()` path (`kernel/signal.c`) that turns a SIGSEGV into
`do_group_exit` not read yet (Q4 touched only the wake side). `?` —
`do_task_dead()` and how a `TASK_DEAD` task's stack is reclaimed (RCU /
`delayed_put_task_struct`).

## 1.9 Process hierarchies: parents, groups, sessions (§2.1.4, pp. 91–92)

§2.1.4: a process *"has only one parent (but zero, one, two, or more
children)"*, descendants form a tree, and *"a process and all of its
children and further descendants together form a process group"* — Ctrl-C
hits the whole group. UNIX's tree is single-rooted at `init`; Windows *"has
no concept of a process hierarchy."*

**Two parents, not one** (`sched.h:1094`, `:1097`):

- `real_parent` — who actually forked me.
- `parent` — who gets `SIGCHLD` and `wait()`s for me. Normally the same.

They diverge under **ptrace**: `strace` / `gdb` becomes `parent` while
`real_parent` stays the shell. The `ptrace_reparented()` checks all over
`exit.c` are handling exactly this. (Fig. 2-4's one "Parent process" row =
two pointers.)

**The tree is two lists per node** (`sched.h:1102`–`1103`):

```c
struct list_head children;   // head of MY list of kids
struct list_head sibling;    // MY link in my parent's children list

list_for_each_entry(child, &current->children, sibling) { ... }
```

The global "every process" list is *separate* — `tasks`, head at
`init_task`, walked by `for_each_process()` (`include/linux/sched/signal.h:640`,
still the line §1.5 cites). It holds one entry per **thread-group leader**;
non-leader threads hang off `signal->thread_head`. Tree ≠ flat list —
different links in the same struct.

**Groups and sessions are just two more PID types.** `enum pid_type`
(`include/linux/pid_types.h`):

```c
PIDTYPE_PID,   PIDTYPE_TGID,   PIDTYPE_PGID,   PIDTYPE_SID
```

A task sits on up to four PID hash lists at once (`pid_links[PIDTYPE_MAX]`,
`sched.h:1117`). `PIDTYPE_PGID` = process group, `PIDTYPE_SID` = session;
the leader pids are cached in the shared `signal_struct`
(`task_pgrp()` / `task_session()` = `task->signal->pids[...]`,
`sched/signal.h:690`).

- `setpgid(2)` (`kernel/sys.c:1114`) — move a task into a process group.
- `setsid(2)` (`kernel/sys.c:1303`) — new session, become leader, drop the
  controlling terminal. Step one of **becoming a daemon** (the book's
  "daemons" from §2.1.2).

At fork the child **inherits** parent's group and session (`copy_process`,
`fork.c:2515`–`2516`). So "everything started in this window" shares a pgrp
by default — which is why one Ctrl-C hits all of it: the tty driver sends
SIGINT to the **foreground process group**, not to a single process.

```
   session  (SID = PID of the shell that ran setsid; owns the controlling tty)
   ├── process group A   "vim"              ← foreground: gets Ctrl-C
   │     └── vim
   └── process group B   "sort | uniq -c"   ← background
         ├── sort
         └── uniq
```

**Orphaned process groups.** `exit_notify` → `kill_orphaned_pgrp()`
(`exit.c:780`): when a group becomes orphaned (no member has a parent in a
different group in the same session) and holds a stopped process, the kernel
sends the whole group `SIGHUP` + `SIGCONT`. That's "closing the terminal
kills the background jobs" — and what `nohup` / `disown` / `setsid` dodge.

**vs Windows:** §1.1's "two roots" is the Linux nuance — the userspace tree
is single-rooted at PID 1 as the book says, but PID 2 (`kthreadd`) roots a
second tree of kernel threads that belongs to no session or process group
at all.

**Check it:**

```
ps -eo pid,ppid,pgid,sid,tpgid,stat,comm        # pgid + sid = the two PID types
ps -o pid,pgid,sid,comm --forest
setsid sleep 300 & ps -o pid,ppid,pgid,sid,comm -p $!   # sid==pid, ppid->1 : a daemon
sleep 100 | sleep 100 &   # then: fg, Ctrl-C -> SIGINT to the whole foreground pgrp
grep -E 'NSpid|NStgid' /proc/self/status        # namespace-local ids (the vnr from §1.3)
```

`?` — `PIDTYPE_TGID` vs `PIDTYPE_PID` (both a "process" identity) — haven't
read `kernel/pid.c` for why TGID needed its own hash. `?` — job-control
stop/cont (`SIGTSTP`, `__TASK_STOPPED` from §1.4) not traced.

---

# Part 2 — Threads (pp. 97–113)

## 2.1 The book warns me about this

p.102: *"First we will look at the classical thread model; after that we will
examine the Linux thread model, **which blurs the line between processes and
threads**."*

It does. And the blurring is eight lines of code.

## 2.2 The difference between a process and a thread is one `if`

`kernel/fork.c:2381`:

```c
	p->pid = pid_nr(pid);
	if (clone_flags & CLONE_THREAD) {
		p->group_leader = current->group_leader;
		p->tgid = current->tgid;
	} else {
		p->group_leader = p;
		p->tgid = p->pid;
	}
```

**Line by line:**

- `p` — the brand new task being built.
- `p->pid = pid_nr(pid);` — give it its own ID number. **Every** new task
  gets one, thread or not.
- `if (clone_flags & CLONE_THREAD)` — did the caller ask for a thread?
  (Check whether that one bit is set.)
- If **yes**:
  - `p->group_leader = current->group_leader;` — point at the same leader as
    whoever created me.
  - `p->tgid = current->tgid;` — copy their tgid. Now `getpid()` returns the
    same number for both of us, so we look like one process.
- If **no**:
  - `p->group_leader = p;` — I'm my own leader.
  - `p->tgid = p->pid;` — my tgid is just my own pid. I'm a new process.

That's the whole thing.

```
   every new task gets its own pid
                │
                ▼
      was CLONE_THREAD asked for?
       ┌────────┴────────┐
      YES               NO
       │                 │
       ▼                 ▼
  join the caller's   start my own group
  group               group_leader = me
  tgid = caller's     tgid = my own pid
  tgid                     │
       │                   │
       ▼                   ▼
  "a new thread"      "a new process"
```

**So a thread and a process are the same object.** Both `fork()` and
`pthread_create()` end up in the same function (`copy_process`). They just
pass different flags. The two categories the book teaches are one code path
with an `if` in it.

Related, `include/linux/sched/signal.h:711`:

```c
bool same_thread_group(struct task_struct *p1, struct task_struct *p2)
{
	return p1->signal == p2->signal;
}
```

**What this does:** takes two tasks, returns true if they're "in the same
process." And the test is just: *do these two point at the same
`signal_struct`?* One pointer comparison. That's all "same process" means
here.

## 2.2a Correction (2026-09-11): "one `if`" undersells it

Went back to this after a chat rubber-ducking session flagged it. §2.2 is
correct about *what* the `if` does — decides tgid/group_leader — but wrong to
call that "the difference." It's the last link in a chain the kernel actively
enforces, with real consequences outside `copy_process()` too. Verified
each of these against `~/linuxsrc/linux` myself, not taken on faith:

**(a) The flags aren't independent — `copy_process()` itself refuses bad
combos.** `kernel/fork.c:2039`:

```c
/*
 * Thread groups must share signals as well, and detached threads
 * can only be started up within the thread group.
 */
if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))
	return ERR_PTR(-EINVAL);

/*
 * Shared signal handlers imply shared VM. By way of the above,
 * thread groups also imply shared VM. Blocking this case allows
 * for various simplifications in other code.
 */
if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))
	return ERR_PTR(-EINVAL);
```

So it's not "pick `CLONE_THREAD` independently of the rest." Ask for
`CLONE_THREAD` and you're forced into `CLONE_SIGHAND`, which forces
`CLONE_VM`:

```
   CLONE_THREAD  ──requires──►  CLONE_SIGHAND  ──requires──►  CLONE_VM
   "join the group"             "share signal table"          "share address space"
```

The kernel's own comment even says why: *"thread groups also imply shared
VM. Blocking this case allows for various simplifications in other code."*
§2.2's version made tgid assignment look like one isolated choice. It's the
end of a forced chain.

**(b) The reverse direction is guarded too — `unshare()`.**
`kernel/fork.c:3161`, `check_unshare_flags()`:

```c
if (unshare_flags & (CLONE_THREAD | CLONE_SIGHAND | CLONE_VM)) {
	if (!thread_group_empty(current))
		return -EINVAL;
}
```

**What this does:** if I'm trying to *leave* my thread group (or split off my
signal handlers / address space) while other threads of mine are still
alive, that's `-EINVAL`. `thread_group_empty()` — despite the name — means
"do I have no *other* threads," i.e. am I alone in my own group. You can't
half-detach out from under siblings that are still running. Something
§2.2 never looked at, because it only reads the *creation* path
(`copy_process`), not the teardown/reconfiguration path.

**(c) Exit/reaping asymmetry — and my first pass at this got the mechanism
wrong.** Exp 4's `clone3` trace shows `exit_signal=0` for the thread vs
`SIGCHLD` for `fork()`, and I originally read that as "the kernel sees
`exit_signal=0` and skips notifying the parent." Checked it — that's not
what happens. `copy_process()` **ignores the caller's `exit_signal` argument
entirely** when `CLONE_THREAD` is set and hard-codes a sentinel instead,
`kernel/fork.c:2461`:

```c
if (clone_flags & CLONE_THREAD)
	p->exit_signal = -1;
```

And at actual exit, `kernel/exit.c:788`:

```c
} else if (thread_group_leader(tsk)) {
	autoreap = thread_group_empty(tsk) &&
		   do_notify_parent(tsk, tsk->exit_signal);
} else {
	autoreap = true;
	/* untraced sub-thread */
	do_notify_pidfd(tsk);
```

**What this does:** `do_notify_parent()` — the call that sends the exit
signal — is only ever reached from the `thread_group_leader(tsk)` branch. A
non-leader thread falls into the `else`: it's marked `autoreap = true` and
`do_notify_parent` is never called, full stop. Its `exit_signal` field (the
`-1` from above) isn't even read here. So "a thread's death isn't reported
as a child exit" isn't caused by a `0`/`-1` value telling the notify path
"don't send anything" — the notify path is structurally skipped for
non-leaders regardless of what's in that field. The `exit_signal=0` visible
in the `clone3` strace is just glibc's own syscall argument; the kernel
throws it away for `CLONE_THREAD` tasks and the field plays no role in why
threads don't generate a waitable zombie.

**(d) `de_thread()` on `execve` — a structural consequence of being bound
together.** `fs/exec.c:922`:

```c
static int de_thread(struct task_struct *tsk)
{
	...
	if (thread_group_empty(tsk))
		goto no_thread_group;

	/*
	 * Kill all other threads in the thread group.
	 */
	...
	sig->notify_count = zap_other_threads(tsk);
	...
	while (sig->notify_count) {
		__set_current_state(TASK_KILLABLE);
		...
		schedule();
	}
```

**What this does:** when any thread in a group calls `execve`, the kernel
first kills every *other* thread in that group (`zap_other_threads`) and
waits for them to actually die before loading the new program. `execve`
collapses a whole thread group down to one task. That behavior only exists
*because* `CLONE_THREAD` tasks are bound into one group in the first
place — it's downstream of the `if`, not visible in it.

**Cross-checked against `man 2 clone`** (userspace's actual contract, not
just kernel source comments) — it confirms all of the above and adds
something the source comments don't: this was a rule added *progressively*
over kernel history, not always true. Quoting it directly:

> Since Linux 2.5.35, the flags mask must also include CLONE_SIGHAND if
> CLONE_THREAD is specified (and note that, since Linux 2.6.0, CLONE_SIGHAND
> also requires CLONE_VM to be included).
>
> A new thread created with CLONE_THREAD has the same parent process as the
> process that made the clone call [...] When a CLONE_THREAD thread
> terminates, the thread that created it is not sent a SIGCHLD (or other
> termination) signal; nor can the status of such a thread be obtained
> using wait(2).

That second paragraph is (c) above, stated directly in the userspace
contract — good independent confirmation that "non-leader threads don't
notify a parent" is the intended, documented behavior, not a side effect I
misread out of the source.

**Corrected version of §2.2's closing line:** thread-group membership isn't
one independent bit flipped at creation. It's a chain of enforced flag
dependencies (`VM → SIGHAND → THREAD`) at creation, guarded again on the way
*out* (`unshare`), with real structural consequences at exit (reaping) and
exec (`de_thread`). The `if` at `fork.c:2381` is real and is where the label
gets assigned — it's just the last step, not the whole mechanism.

## 2.3 Fig. 2-11's two columns are really just flags

p.104 has a table: things shared by all threads (address space, open files,
signals…) vs things each thread has its own of (registers, stack).

In Linux those are literally flags you pass in:

| Fig. 2-11 calls it shared | Flag | Where (`include/uapi/linux/sched.h`) |
|---|---|---|
| Address space | `CLONE_VM` | `:11` — 0x00000100 |
| Open files | `CLONE_FILES` | `:13` — 0x00000400 |
| Signals & handlers | `CLONE_SIGHAND` | `:14` — 0x00000800 |
| Current directory | `CLONE_FS` | `:12` — 0x00000200 |
| (being one process) | `CLONE_THREAD` | `:19` — 0x00010000 |
| Per-thread storage | `CLONE_SETTLS` | `:22` — 0x00080000 |

```
   pthread_create()          fork()
   asks for:                 asks for:
   VM|FS|FILES|              (almost nothing)
   SIGHAND|THREAD|SETTLS
        │                        │
        ▼                        ▼
   ┌─────────────────┐    ┌──────────────┐   ┌──────────────┐
   │  shared memory  │    │  own memory  │   │  own memory  │
   │  shared files   │    │  own files   │   │  own files   │
   │  shared signals │    │  own signals │   │  own signals │
   │                 │    └──────────────┘   └──────────────┘
   │  task   task    │       parent             child
   └─────────────────┘
     one "process"
```

**The part the book's table hides:** those two columns aren't fixed. They're
a menu. Fig. 2-11 makes "shared vs private" sound like a fact about what
threads *are*. In Linux it's an argument you choose per call. You could share
memory but not be one process. You could share open files but not memory.
"Thread" and "process" are just the two combinations people use most.

Containers are built out of more flags in this same family (`CLONE_NEW*`).
`?` — haven't read those yet.

## 2.4 §2.2.4 vs §2.2.5 — Linux already picked a side

Pages 107–112 weigh two designs:

```
   §2.2.4 user-level (Fig 2-15a)     §2.2.5 kernel-level (Fig 2-15b)
   ┌───────────────────────┐         ┌───────────────────────┐
   │  T1  T2  T3           │  user   │  T1    T2    T3       │  user
   │   \  |  /             │         │   │     │     │       │
   │  run-time library     │         │   │     │     │       │
   ├───────────────────────┤         ├───┼─────┼─────┼───────┤
   │  kernel sees: 1 task  │  kernel │   ▼     ▼     ▼       │  kernel
   └───────────────────────┘         │  task  task  task     │
   switching is fast, but            └───────────────────────┘
   one blocking syscall              kernel schedules each one,
   freezes all three                 syscalls cost more

```

Linux is firmly (b). There's no such thing as a user-level thread as far as
the kernel is concerned — every pthread is a real `task_struct` that the
scheduler handles on its own. The per-process "thread table" in Fig. 2-15(a)
doesn't exist here.

`?` — I think glibc does strict 1:1 (one pthread = exactly one task, no
juggling), which would mean §2.2.6's "hybrid" design is a path Linux didn't
take. But that's a *glibc* thing, not in this source tree, so don't trust
this line until I check it.

## 2.5 The errno problem leads somewhere I recognize

§2.2.7 (p.113) worries about `errno`. Thread 1 makes a syscall that fails,
which sets the global `errno`. Before thread 1 reads it, the scheduler
switches to thread 2, which makes its own failing call and overwrites
`errno`. Thread 1 wakes up and reads the wrong value.

The fix is **thread-local storage (TLS)**: each thread gets its own private
copy of certain variables, even though all threads share one address space.

```
        one shared address space (that's CLONE_VM)
   ┌───────────────────────────────────────────────┐
   │  code   globals   heap                        │  ← really shared
   │                                               │
   │   ┌─────────────┐   ┌─────────────┐           │
   │   │ TLS block   │   │ TLS block   │           │  ← one per thread
   │   │  errno      │   │  errno      │           │
   │   │  canary     │   │  canary     │           │
   │   └─────────────┘   └─────────────┘           │
   │         ▲                 ▲                   │
   │    %fs points here   %fs points here          │
   │      (thread 1)        (thread 2)             │
   └───────────────────────────────────────────────┘
```

Each thread's `%fs` register points at its own block. `errno` isn't really a
global — it's "whatever is at some offset from `%fs`". Same name in the
source, different address per thread. Setting this up is what `CLONE_SETTLS`
(`sched.h:22`) does at thread creation.

**And this is the bit I actually care about:** on x86-64, the stack canary
lives in that same block, at `%fs:0x28`.

So the `mov rax, qword ptr fs:[0x28]` I've seen in a hundred function
prologues in Ghidra isn't a random magic address. It's TLS — the exact same
mechanism invented so threads don't clobber each other's `errno`. That's also
why each thread has a different canary value.

`?` — this is a glibc/ABI detail, not in the kernel tree. Verify it:
```
gdb ./anything
> break main
> run
> p/x $fs_base
> x/gx $fs_base + 0x28        # should be the canary
```
then compare with the `fs:[0x28]` load in the prologue.

---

# Experiments

Ran 2026-09-07 on the box itself (Fedora 44). Source line refs are the same
local clone as the rest of this file — `~/linuxsrc/linux` @ v7.3-rc1; nothing
touched here differs from what the running kernel does. C programs at the
bottom of this section.

## Exp 1 — the two roots of the process tree

```
$ ps -p 1 -o pid,comm          $ ps -p 2 -o pid,comm       $ ps --ppid 2 -o pid,comm | head
  PID COMMAND                     PID COMMAND                 PID COMMAND
    1 systemd                       2 kthreadd                  3 pool_workqueue_release
                                                               4 kworker/R-rcu_gp
                                                               5 kworker/R-sync_wq
                                                               ...
```

Observed: exactly the split from §1.1. PID 1 is `systemd`, PID 2 is
`kthreadd`, and *everything* under PID 2 is a `[bracketed]` kernel worker.
Two families, not one tree. The book's single-rooted §2.1.4 diagram is the
userspace half only.

## Exp 2 — pid vs tgid, made visible

```
$ grep -E '^(Pid|Tgid|Threads):' /proc/self/status
Tgid:    23171
Pid:     23171         <- single-threaded reader: Pid == Tgid
Threads: 1
```

```
$ ./threader
main   getpid()=23172 gettid()=23172
thread getpid()=23172 gettid()=23173
```

Observed: the two threads report the **same `getpid()` (23172 = the tgid)**
and **different `gettid()` (23172 / 23173 = the per-task pid)**. This is
§1.3's table, live: `getpid → tgid`, `gettid → pid`.

```
$ ./sleeper &                 # 1 process, 4 pthreads
$ ps -L -p <pid> -o pid,tid,lwp,nlwp,stat,comm
  PID    TID   LWP NLWP STAT COMMAND
23210  23210 23210    4 Sl   sleeper
23210  23212 23212    4 Sl   sleeper
23210  23213 23213    4 Sl   sleeper
23210  23214 23214    4 Sl   sleeper
$ ls /proc/23210/task
23210  23212  23213  23214
```

Observed: one `PID`, four `TID`s, `Threads: 4`, and `/proc/<pid>/task/` has
one dir per task. The kernel really is just holding four `task_struct`s that
share a tgid — there's no separate "process" object anywhere in this view.

## Exp 3 — states in the wild

```
$ ps -eo stat --no-headers | cut -c1 | sort | uniq -c | sort -rn
    294 S        # interruptible sleep — almost everything
    112 I        # <-- see below
      1 R        # the ps process itself
```

`ps` letters seen: `Ss` (sleep + session leader), `Sl` (sleep +
multithreaded), `I<` (idle + negative nice).

**New find the pre-notes missed:** that `I` is `TASK_IDLE`, and it is *not*
in the `sched.h:107` list I copied at §1.4. It's defined further down:

```
include/linux/sched.h:141:  #define TASK_IDLE  (TASK_UNINTERRUPTIBLE | TASK_NOLOAD)
include/linux/sched.h:121:  #define TASK_NOLOAD 0x00000400
```

So an idle kernel worker is `TASK_UNINTERRUPTIBLE` (won't take signals) with
`TASK_NOLOAD` bolted on so it doesn't count toward the load average. §1.4's
"the book says 3, Linux has more" undercounts — I found a 4th kind just by
reading `ps` output. All 112 of those `[kworker/...]` sit in it.

**Caught a `D`:** direct I/O is the way in.

```
$ dd if=/dev/zero of=blob bs=512k count=2000 oflag=direct &   # then hammer /proc/<pid>/stat
  ... R R R R R ... D ... R ...
  (a fast /proc/<pid>/stat sampler: ~87000 reads, exactly 1 landed on 'D')
```

Observed: `dd` with `oflag=direct` really does drop into `D`
(`TASK_UNINTERRUPTIBLE`) while a BIO (the kernel's in-flight block I/O
request — one struct per pending disk read/write) is outstanding — but on
NVMe it's *so*
brief you catch it maybe 1 sample in ~90k. Which is the whole point of §1.4:
`D` is normal and microscopic; it only becomes a problem when something
external (dead NFS mount, stuck disk) makes the task *stay* there.

## Exp 4 — the flag difference, seen directly

```
$ strace -f -e trace=clone,clone3,execve ./forker
execve("./forker", ...) = 0
clone(child_stack=NULL,
      flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD,
      child_tidptr=0x...) = 23330
```

```
$ strace -f -e trace=clone,clone3,execve ./threader
execve("./threader", ...) = 0
clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD
             |CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID,
        ...,  exit_signal=0,  stack=0x..., tls=0x...})
```

Observed: same syscall family both times. `fork()` → `clone` with **no
sharing flags** (just `SIGCHLD` so the parent gets notified, plus TID
housekeeping). `pthread_create()` → `clone3` with the **entire sharing menu**
— `CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS`. That flag list *is* the
difference between "process" and "thread" (see §2.2a(c) for why the
`exit_signal=0` field itself isn't the reason threads don't get reaped like
children). Nothing
else.

## The programs

```c
/* forker.c */                          /* threader.c  (cc ... -lpthread) */
#include <stdio.h>                       #define _GNU_SOURCE
#include <unistd.h>                       #include <stdio.h>
#include <sys/wait.h>                     #include <pthread.h>
int main(void){                           #include <unistd.h>
  if (fork()==0){                         #include <sys/syscall.h>
    printf("child pid=%d\n",getpid());    static void *worker(void *a){
    _exit(0);                               printf("thread getpid()=%ld gettid()=%ld\n",
  }                                                (long)getpid(),(long)syscall(SYS_gettid));
  printf("parent pid=%d\n",getpid());      return NULL;
  wait(NULL);                             }
}                                         int main(void){
                                            printf("main   getpid()=%ld gettid()=%ld\n",
                                                   (long)getpid(),(long)syscall(SYS_gettid));
                                            pthread_t t;
                                            pthread_create(&t,NULL,worker,NULL);
                                            pthread_join(t,NULL);
                                          }
```

(`sleeper.c` = `threader` but with 3 workers that `pause()`; the CLONE_FILES
demo for Q6 is written out under that answer.)

# Questions to answer in writing

This is the real work. The notes above are just setup.

**1. `rest_init()` makes PID 1 before PID 2, but the comment says init wants
kthreads. What actually breaks if you swap the order?**

Two separate orderings are doing two separate jobs, and it's easy to conflate
them.

- *Creation order* (`kernel_clone(init)` then `kernel_thread(kthreadd)`) only
  exists so init grabs pid 1. PIDs are handed out first-come. Swap these two
  calls and init becomes pid 2 — cosmetic-ish, but a lot of userspace and the
  kernel itself special-case `pid == 1` (it's the reaper, it can't be killed
  by normal signals, `/sbin/init`), so "cosmetic" is generous.
- *The thing the comment is actually about* is a **run order**, enforced
  separately: `kernel_init` (pid 1) calls `wait_for_completion(&kthreadd_done)`
  at `init/main.c:1558` — **before** it even calls `kernel_init_freeable()`
  (line 1560), not inside it as I first wrote. `kthreadd` calls
  `complete(&kthreadd_done)` once it's up (`init/main.c:719`). So pid 1 is
  *created* first but is *parked* — at the very top of `kernel_init()`, before
  any of the freeable-init work — until pid 2 is alive.
  (Corrected 2026-09-11 — the wait is a gate in front of `kernel_init_freeable`,
  not a step inside it.)

What breaks if pid 1 runs its kthread-using code before kthreadd exists:
`kthread_create_on_node()` builds a request and hands it to kthreadd by
adding it to `kthread_create_list` and waking `kthreadd`. With no kthreadd
task there is nothing to wake and nothing to service the list — the creator
blocks forever, or derefs through a not-yet-set pointer. The comment's word
is "OOPS." The `kthreadd_done` completion is the guard that makes the
create-init-first ordering safe.

**2. If `getpid()` returns tgid, what does it return in a program with only
one thread — and why does that make the naming almost make sense?**

In a single-threaded program the process is one task, that task is its own
group leader, and `copy_process()` took the `else` branch at `fork.c:2384`:
`p->tgid = p->pid`. So **tgid == pid**, and `getpid()` and `gettid()` return
the same number. Seen in Exp 2: `main getpid()=23172 gettid()=23172` before
the second thread exists.

That's why the name isn't a lie for most code: the overwhelming majority of
processes have one thread, and for them "getpid returns the process id" is
just true. The name only starts misleading you the moment you call
`pthread_create` — and by then you're expected to know `gettid` exists.

**3. Fig. 2-2 has four arrows. Which ones don't show up in Linux's state
field at all, and where does that info live instead?**

Fig. 2-2's arrows: (1) running→blocked, (2) running→ready (preempted),
(3) ready→running (dispatched), (4) blocked→ready (woken).

- **Arrows 2 and 3 never touch `task->__state`.** A runnable task is
  `TASK_RUNNING` (0) whether it's currently on a CPU or just waiting its
  turn. Being preempted or dispatched doesn't change that field.
- **Arrows 1 and 4 do.** Blocking runs `set_current_state(TASK_INTERRUPTIBLE
  / TASK_UNINTERRUPTIBLE)`; waking runs `try_to_wake_up()` which sets it back
  to `TASK_RUNNING`.

Where "is it actually on a CPU / is it runnable" really lives: the
scheduler's runqueue. `task_struct::on_cpu` (running right now on some CPU),
`task_struct::on_rq` / `sched_entity::on_rq` (queued as runnable), and
membership in a per-CPU `struct rq`. §1.4 already said this — the experiment
just confirms the state field genuinely has nothing to distinguish "Running"
from "Ready": both were the same `S`→`R` blob in `ps`, and the `R` count was
1 (only the sampler itself was mid-`read`).

**4. In one sentence, using how signals get delivered: why can't `kill -9`
kill a `D`-state process?**

Delivering SIGKILL means flagging it pending and **waking the target** so
that on its way back toward user mode it runs `get_signal()` and dies — a
task in `TASK_UNINTERRUPTIBLE` (`D`) will not wake for that, so it never
reaches the code that looks at pending signals, and the kill just sits
pending until the task leaves `D` on its own.

**5. `same_thread_group()` compares `signal` pointers instead of comparing
tgids. Why that field?**

Guess (before looking): because sharing that struct *is* what being one
process means, so pointer identity is the definition and tgid is a
derived label.

After looking — `copy_signal()` in `kernel/fork.c`: if `CLONE_THREAD` is set
it returns early **without allocating** a `signal_struct`; the new task keeps
`current->signal` (refcount++). Without `CLONE_THREAD` a fresh one is
`kmem_cache_zalloc`'d — the kernel's "allocate one zeroed object from a
pre-sized pool" call, its rough equivalent of `calloc()`. So
`p1->signal == p2->signal` is *exactly* the
`CLONE_THREAD` relation, by construction.

`->signal` (not `->sighand`) is the right field because it's the group-wide
box: shared pending signals for the whole process, `group_exit_code` /
`group_stop_count`, the live-thread count, shared rlimits, controlling tty,
per-process timers. `->sighand` is just the handler table (also shared for
threads, via `CLONE_SIGHAND`, but that's a separate flag you *could* set
without `CLONE_THREAD`). And a pointer compare is one instruction that can't
be confused by PID-namespace remapping the way comparing two `tgid` integers
across namespaces could get subtle.

**6. Which flag would give me two tasks that share file descriptors but
*not* memory — and is that a process or a thread?**

`CLONE_FILES` **without** `CLONE_VM` (and without `CLONE_THREAD`). Proven:

```c
/* clone(child, stk, CLONE_FILES|SIGCHLD, &fd);  child does: close(fd); */
CLONE_FILES : after child close(fd), parent fcntl(fd) = -1  -> fd GONE in parent too (shared table)
fork()      : after child close(fd), parent fcntl(fd) =  0  -> still open (private copy of the table)
```

(Note: this had to test with `close()`, not `lseek()` — plain `fork()`
already shares the open *file description*, so the byte offset moves either
way. What `CLONE_FILES` adds is sharing the descriptor *table*: `close` /
`open` / `dup` in one task are visible in the other.)

And it's a **process**, not a thread:

```c
/* clone(child, stk, CLONE_FILES|SIGCHLD, 0);  -- no CLONE_THREAD */
parent: getpid()=23460 gettid()=23460
 child : getpid()=23461 gettid()=23461   -> its own tgid
```

Own tgid, own address space, own `signal_struct` — a distinct process that
happens to share one resource. This is §2.3's point made concrete: "shared
vs private" is per-flag, not a fixed property of "thread." You can pick any
subset.

# My own notes

Done 2026-09-07. This was the half that was missing — the 09-04 file was all
prep, no session.

What actually landed for me, doing it instead of reading it:

- **`getpid()`/`gettid()` stopped being a "backwards naming" trivia fact.**
  Seeing `main` and `thread` print the *same* `getpid()` and *different*
  `gettid()` in three lines of output made it obvious: the number that stays
  constant across a thread spawn is the process identity, and Linux just
  happens to store that in a field it named `tgid` and expose it through a
  syscall it named `getpid`. The names describe the API contract, not the
  data structure.

- **The clone flag lists are the whole lecture.** §2.2.4 vs §2.2.5, Fig 2-11's
  two columns, "the Linux model blurs the line" — all of it collapses into
  one `strace` diff: `SIGCHLD` alone vs
  `VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS`. If I'd opened `strace` first I
  might not have needed most of §2.2.

- **`D` is real but tiny.** I half-expected `oflag=direct` to just park `dd`
  in `D` for a second. Instead: 1 hit in ~87k samples. The pathology isn't
  "a task entered `D`" — that happens constantly — it's "a task can't
  *leave*." Reframed how I think about hung processes.

- **The book undercounts and so did I.** §1.4 says "the book says 3, Linux
  has more" and lists 7 from `sched.h:107`. Then `ps` showed 112 processes in
  a state (`I` / `TASK_IDLE`) that isn't in that list — it's 20-odd lines
  further down in the same header. Lesson: grep the whole file, not the first
  block that looks like the answer.

Open threads I'm deliberately *not* chasing today (they're the `?` lines
above — namespaces/`vnr`, the glibc 1:1 claim, the `fs:[0x28]` canary/TLS
ABI check). Next up per PLAN.md is the process-creation source dive:
`task_struct` (`sched.h:835`) → `copy_process()` (`fork.c:2012`) → `execve`.
