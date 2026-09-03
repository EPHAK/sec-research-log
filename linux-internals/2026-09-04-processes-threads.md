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

```bash
# 1. the two roots of the process tree
ps -p 1 -o pid,comm ; ps -p 2 -o pid,comm ; ps --ppid 2 | head

# 2. pid vs tgid, visible
ps -eLf | head -20                              # PID column vs LWP column
cat /proc/self/status | grep -E 'Pid|Tgid|Threads'

# 3. states in the wild
ps -eo pid,stat,comm | head -30

# 4. the flag difference, seen directly
strace -f -e trace=clone,clone3,execve ./forker    2>&1 | grep clone
strace -f -e trace=clone,clone3,execve ./threader  2>&1 | grep clone
#   same syscall both times. only the flags differ. that IS the distinction.
```

Two tiny programs to write: one calling `fork()`, one calling
`pthread_create()`. The programs don't matter — the flags in the strace
output do.

# Questions to answer in writing

This is the real work. The notes above are just setup.

1. `rest_init()` makes PID 1 before PID 2, but the comment says init wants
   kthreads. What actually breaks if you swap the order?
2. If `getpid()` returns tgid, what does it return in a program with only one
   thread — and why does that make the naming almost make sense?
3. Fig. 2-2 has four arrows. Which ones don't show up in Linux's state field
   at all, and where does that info live instead?
4. In one sentence, using how signals get delivered: why can't `kill -9` kill
   a `D`-state process?
5. `same_thread_group()` compares `signal` pointers instead of comparing
   tgids. Why that field? (Guess first, then go look.)
6. Fig. 2-11 says open files are per-process. Which flag would give me two
   tasks that share file descriptors but *not* memory — and is that a process
   or a thread?

# My own notes

_(below here — during/after. raw is fine. wrong is fine.)_
