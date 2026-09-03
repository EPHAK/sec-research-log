# 2026-09-04 — Processes & Threads

Book: *Modern Operating Systems* 5th ed., Tanenbaum & Bos.
Local PDF: `/home/ephak/research/books/mos-5th-tanenbaum.pdf`
Source: `/home/ephak/linuxsrc/linux` @ v7.3 ("Baby Opossum Posse")

**Today: pp. 88–113.** §2.1.2 Process Creation → §2.2.7.
Left off at p.87 (Fig. 2-1, end of §2.1.1).

Page mapping: **PDF page = printed page + 29.** My physical copy is the
Global Edition so it may drift a page or two — re-anchor by section heading.

> These notes were drafted before the session. Everything with a line number
> was checked against the tree. Read with the source open, argue with it,
> cross things out. A note I didn't verify myself is worth less than one I
> did — the `?` markers below are the ones I still owe.

---

# Part 1 — Processes (pp. 88–97)

## 1.1 Where PID 1 actually comes from

Tanenbaum, p.89: *"the very first process is hard-crafted when the system is
booted."* That's the one sentence in the section that sounds like a dodge.
It isn't — the hand-crafting has an address.

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

The comment says the quiet part out loud: *"so that it obtains pid 1."*
Nobody assigns PID 1. init just gets to the allocator first, and the kernel
orders the calls to make sure of it.

```
          start_kernel()            init/main.c:982
                │
                │  (~40 subsystem init calls: mm, sched, timers, ...)
                ▼
          rest_init()               init/main.c:676
                │
      ┌─────────┴─────────┐
      ▼                   ▼
   PID 1                PID 2
  kernel_init          kthreadd
      │                   │
      │ execve            │ spawns all [bracketed] kernel threads
      ▼                   │
  /sbin/init         ┌────┴────┬─────────┐
      │              ▼         ▼         ▼
  everything     [kworker] [ksoftirqd] [rcu_...]
  in userspace
```

**The bit the book doesn't say:** the process tree has *two* roots, not one.
§2.1.4 draws one hierarchy with init at the top. Real Linux has userspace
under PID 1 and every kernel thread under PID 2. `ps` shows the second
family in `[brackets]`.

The ordering constraint in that comment is a real bug they hit — spawn them
the other way round and it OOPSes. Worth understanding why (see questions).

**Check:**
```
ps -p 1 -o pid,comm
ps -p 2 -o pid,comm
ps --ppid 2 | head
```

## 1.2 Boot is the fork/exec two-step from p.90

p.90 makes a point of UNIX splitting creation in two: `fork` clones, `execve`
replaces the image, and the gap between them is where the shell rewires fds.
Tanenbaum frames this as a userspace idiom.

Boot does the identical dance across the kernel/userland boundary:

```
   kernel_clone()                    kernel_execve()
        │                                  │
        ▼                                  ▼
   ┌─────────┐   runs kernel code    ┌──────────┐
   │ PID 1   │ ────────────────────► │  PID 1   │
   │ =kernel │                       │ =/sbin/  │
   │  _init  │                       │   init   │
   └─────────┘                       └──────────┘
    kernel thread                     userspace process
        └──────── same task_struct ────────┘
              (the fork half)   (the exec half)
```

The exec half is `run_init_process()`, `init/main.c:1467`, ending in:

```c
	return kernel_execve(init_filename, argv_init, envp_init);
```

So PID 1 is born as a kernel thread and then **execve's itself into
userspace**. Same primitive as my shell forking `sort`, applied to the most
important boundary in the system. That's a nicer piece of design economy
than the book lets on.

The fallback chain right below (`init/main.c:1617`):

```c
	if (!try_to_run_init_process("/sbin/init") ||
	    !try_to_run_init_process("/etc/init") ||
	    !try_to_run_init_process("/bin/init") ||
	    !try_to_run_init_process("/bin/sh"))
		return 0;

	panic("No working init found.  Try passing init= option to kernel. ...");
```

**Security note — file this.** `execute_command` (line 1599) comes from the
`init=` kernel cmdline parameter and is tried **before** all four defaults.
`init=/bin/sh` at the bootloader is the classic physical-access root shell:
no password prompt, because I've replaced PID 1 before any authentication
code exists to run. Attacker-controlled input is checked first, by design.
This is why bootloader passwords and Secure Boot exist, and it's my first
concrete "the boot chain is attack surface" data point.

## 1.3 getpid() doesn't return what I thought

`kernel/sys.c:999` — the whole reason to trace a small syscall:

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

`getpid()` returns the **tgid**. `gettid()` returns the **pid**. The kernel's
own comment does the translation: *"Thread ID — the internal kernel 'pid'."*

The vocabulary is inverted between the two worlds:

| What I say | What the kernel calls it | Syscall |
|---|---|---|
| PID — the process | `tgid` | `getpid()` |
| TID — one thread | `pid` | `gettid()` |

```
  what I call "a process with 3 threads"
  ┌──────────────────────────────────────┐
  │  tgid = 4021                         │   getpid() → 4021 for all three
  │                                      │
  │   task        task        task       │
  │  pid=4021    pid=4022    pid=4023    │   gettid() → 4021 / 4022 / 4023
  │  (leader)                            │
  └──────────────────────────────────────┘
        ▲
        │ to the kernel these are just three tasks
        │ that happen to share a tgid
```

To Linux there is no "process" object. There are only tasks. A process is
*a set of tasks sharing a tgid*. Tanenbaum spends §2.1 on processes and §2.2
on threads as two concepts; Linux implements one thing and derives both.

The `vnr` suffix = "virtual number", i.e. resolved relative to the caller's
PID namespace. That's why PID 1 inside a container isn't PID 1 on the host.
One suffix, an entire isolation subsystem behind it.

## 1.4 Process states: book says 3, reality has more

Fig. 2-2 (p.93) gives Running / Ready / Blocked. `include/linux/sched.h:107`:

```c
#define TASK_RUNNING			0x00000000
#define TASK_INTERRUPTIBLE		0x00000001
#define TASK_UNINTERRUPTIBLE		0x00000002
#define __TASK_STOPPED			0x00000004
#define EXIT_DEAD			0x00000010
#define EXIT_ZOMBIE			0x00000020
#define TASK_DEAD			0x00000080
```

Two mismatches. Catching mismatches is the actual skill here, so:

```
   BOOK (Fig 2-2)                 LINUX
   ─────────────                  ─────
                                  TASK_RUNNING (0x0)
   ┌─────────┐                    ┌───────────────────────┐
   │ Running │◄──┐                │ runnable.             │
   └────┬────┘   │ 3              │ am I on a CPU *right  │
        │ 2      │                │ now*? not stored here │
        ▼        │                │ — that's a runqueue   │
   ┌─────────┐   │                │ property              │
   │  Ready  │───┘                └───────────────────────┘
   └─────────┘
                                  splits in two:
   ┌─────────┐                    ┌──────────────────────┐
   │ Blocked │  ─────────────►    │ TASK_INTERRUPTIBLE   │ signals wake it
   └─────────┘                    ├──────────────────────┤
                                  │ TASK_UNINTERRUPTIBLE │ deaf to signals
                                  └──────────────────────┘  = 'D' in ps
```

**(a) Linux doesn't distinguish Running from Ready at all.** Both are
`TASK_RUNNING` = 0x0. The book's transitions 2 and 3 (scheduler picks /
deposes) change *nothing* in the state field. Whether a runnable task is
executing is a property of a CPU's runqueue, not of the task. The state
machine in Fig. 2-2 is a model, and this is exactly where model and
implementation part ways.

**(b) "Blocked" splits in two**, and I've already met the split in the wild:
`TASK_UNINTERRUPTIBLE` is `D` state — the process stuck on dead NFS or a
dying disk that survives `kill -9`. Not because SIGKILL is special-cased
away, but because signal delivery works by *making a task runnable*, and this
task refuses to become runnable. `kill -9` isn't magic; it's a signal, and a
signal needs a task willing to wake up.

Also: these are **bit flags** (0x1, 0x2, 0x4, 0x10…), not an enum. States get
masked and combined. `EXIT_ZOMBIE` is §2.1.3's terminated-but-unreaped
process, sitting there as a number.

**Check:** `ps -eo pid,stat,comm | head -30` — find an `S`, try to catch a `D`.

## 1.5 The "process table" is a lie-to-children

p.94: the OS keeps *"a table (an array of structures), called the process
table, with one entry per process."*

Linux has no such array:

```
   BOOK                          LINUX
   ────                          ─────
   process_table[]               per-namespace IDR (sparse id→ptr tree)
   ┌───┬───┬───┬───┬───┐              pid_namespace.idr
   │ 0 │ 1 │ 2 │ 3 │ 4 │              include/linux/pid_namespace.h:27
   └───┴───┴───┴───┴───┘                     │
   index == pid                        ┌─────┴─────┐
   one global table                    ▼           ▼
                                  task_struct  task_struct
                                  (individually allocated,
                                   threaded onto lists)
```

- `struct task_struct` — `include/linux/sched.h:835`, allocated individually.
- Iterated via `for_each_process()` — `include/linux/sched/signal.h:640`.
- PID lookup goes through an **IDR** held *per PID namespace*:
  `struct idr idr;` at `include/linux/pid_namespace.h:27`, allocated from at
  `kernel/pid.c:240` and `:262`.

The reason is in the struct name: `pid_namespace`. A flat global array
can't express *"PID 1 means different things to different observers."*
The book's array is the right mental model and the wrong implementation.

Fig. 2-4 (p.95) lists what a process-table entry "typically" holds. Later
exercise: open `task_struct` and find Tanenbaum's fields in it — then count
how many hundreds of fields aren't on his list. That's the honest scale gap
between model and machine.

---

# Part 2 — Threads (pp. 97–113)

## 2.1 The book flags this itself

p.102: *"First we will look at the classical thread model; after that we will
examine the Linux thread model, **which blurs the line between processes and
threads**."*

It does, and I found exactly where the line gets blurred — it's eight lines.

## 2.2 The entire process/thread distinction, in one `if`

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

That's it. That's the whole thing.

```
   every new task gets its own pid
                │
                ▼
      CLONE_THREAD set?
       ┌────────┴────────┐
      YES               NO
       │                 │
       ▼                 ▼
  join caller's     start my own group
  thread group      group_leader = me
  tgid = caller's   tgid = my own pid
  tgid
       │                 │
       ▼                 ▼
  "a new thread"    "a new process"
```

**A thread and a process are the same object, created by the same function,
differing by one flag.** `fork()` and `pthread_create()` both land in
`copy_process()`; they just pass different `clone_flags`. Everything the
book presents as two categories is one code path with a branch in it.

And `same_thread_group()` (`include/linux/sched/signal.h:711`) is:

```c
	return p1->signal == p2->signal;
```

"Same process" = *the two tasks point at the same `signal_struct`.* A pointer
comparison. That's the whole ontology.

## 2.3 Fig. 2-11's two columns are just CLONE flags

p.104 splits things into per-process (shared) and per-thread (private):

| Fig. 2-11 says shared | Linux flag | `include/uapi/linux/sched.h` |
|---|---|---|
| Address space | `CLONE_VM` | `:11` — 0x00000100 |
| Open files | `CLONE_FILES` | `:13` — 0x00000400 |
| Signals & handlers | `CLONE_SIGHAND` | `:14` — 0x00000800 |
| (cwd, root dir) | `CLONE_FS` | `:12` — 0x00000200 |
| — thread grouping — | `CLONE_THREAD` | `:19` — 0x00010000 |
| Per-thread: stack/TLS | `CLONE_SETTLS` | `:22` — 0x00080000 |

```
   pthread_create()          fork()
   CLONE_VM|FS|FILES|        (almost no
   SIGHAND|THREAD|SETTLS      flags set)
        │                        │
        ▼                        ▼
   ┌─────────────────┐    ┌──────────────┐   ┌──────────────┐
   │  shared mm      │    │  own mm      │   │  own mm      │
   │  shared fds     │    │  own fds     │   │  own fds     │
   │  shared signals │    │  own signals │   │  own signals │
   │                 │    └──────────────┘   └──────────────┘
   │  task   task    │       parent             child
   └─────────────────┘
    one "process"
```

Here's the thing the book's two-column table hides: **those columns aren't
fixed.** They're a menu. Fig. 2-11 presents "shared vs private" as a property
of what threads *are*; in Linux it's a per-call argument. I can ask for
shared memory *without* a shared thread group. I can share file descriptors
but not address space. The classical model is one popular point in a space
of combinations.

That's also why containers are built out of these — same mechanism, more
flags (the `CLONE_NEW*` family, which I haven't looked at yet). `?` — come
back for those.

## 2.4 §2.2.4 vs §2.2.5 — Linux already picked

The book spends pp.107–112 weighing user-level threads (fast switches, no
kernel involvement, but one blocking syscall stalls everyone) against
kernel-level threads (kernel schedules each one, syscalls cost more).

```
   §2.2.4 user-level (Fig 2-15a)     §2.2.5 kernel-level (Fig 2-15b)
   ┌───────────────────────┐         ┌───────────────────────┐
   │  T1  T2  T3           │  user   │  T1    T2    T3       │  user
   │   \  |  /             │         │   │     │     │       │
   │  run-time system      │         │   │     │     │       │
   ├───────────────────────┤         ├───┼─────┼─────┼───────┤
   │  kernel sees: 1 task  │  kernel │   ▼     ▼     ▼       │  kernel
   └───────────────────────┘         │  task  task  task     │
   one blocking syscall              └───────────────────────┘
   freezes all three                 kernel schedules each
```

Linux is (b), and hard. There is no in-kernel notion of a user-level thread
at all — every pthread is a full `task_struct`, scheduled independently. The
per-process "thread table" of Fig. 2-15(a) doesn't exist here.

`?` — I believe glibc's NPTL is strictly 1:1 (one pthread = one task, no
multiplexing), which makes §2.2.6's hybrid model a road Linux didn't take.
That's a *userspace* claim though, not something in this tree, so verify it
rather than trusting the note.

## 2.5 The `errno` problem → TLS → the stack canary

§2.2.7 (p.113) worries about `errno`: thread 1 makes a failing syscall,
scheduler switches, thread 2 clobbers the global `errno`, thread 1 reads
garbage. Tanenbaum uses it to argue globals and threads don't mix.

The fix is **thread-local storage**, and this is where the chapter suddenly
connects to everything I already know from pwn:

```
        one address space (CLONE_VM — shared)
   ┌───────────────────────────────────────────────┐
   │  .text   .data   heap                         │  ← genuinely shared
   │                                               │
   │   ┌─────────────┐   ┌─────────────┐           │
   │   │ TLS block   │   │ TLS block   │           │  ← per-thread,
   │   │  errno      │   │  errno      │           │    same address space,
   │   │  canary     │   │  canary     │           │    different addresses
   │   └─────────────┘   └─────────────┘           │
   │         ▲                 ▲                   │
   │      %fs (T1)          %fs (T2)               │
   └───────────────────────────────────────────────┘
```

Each thread gets its own TLS block; `%fs` points at its own. `errno` is a
`__thread` variable, so `errno` is really `*(fs_base + offset)` — same
symbol, different address per thread. That's `CLONE_SETTLS`
(`sched.h:22`) doing its job at clone time.

**And the stack canary lives in that same block, at `%fs:0x28` on x86-64.**
Which retroactively explains something I've done a hundred times without
thinking: the reason a canary leak is *per-thread*, the reason the canary is
fetched from `fs:0x28` in every prologue I've ever stared at in Ghidra.
It's not a magic location — it's TLS, the same mechanism invented to stop
threads clobbering each other's `errno`.

`?` — glibc/ABI detail, not in this tree. Verify in gdb:
```
gdb ./anything
> break main
> run
> p/x $fs_base
> x/gx $fs_base + 0x28        # canary
```
and compare against the `mov rax, qword ptr fs:[0x28]` in the prologue.

---

# Experiments

```bash
# 1. two roots of the process tree
ps -p 1 -o pid,comm ; ps -p 2 -o pid,comm ; ps --ppid 2 | head

# 2. pid vs tgid, made visible
ps -eLf | head -20            # PID column vs LWP column
cat /proc/self/status | grep -E 'Pid|Tgid|Threads'

# 3. states in the wild
ps -eo pid,stat,comm | head -30

# 4. the flag difference, observed
strace -f -e trace=clone,clone3,execve ./forker    2>&1 | grep clone
strace -f -e trace=clone,clone3,execve ./threader  2>&1 | grep clone
#   ^ same syscall, different flags. that's the whole distinction.
```

Two 5-line programs to write: one `fork()`, one `pthread_create()`. The
point is the `clone_flags` in the strace output, not the programs.

# Questions to answer in writing

These are the actual work — the notes above are just setup.

1. `rest_init()` creates PID 1 before PID 2, but the comment says init *wants*
   kthreads. What breaks in the other order?
2. If `getpid()` returns tgid, what does it return in a single-threaded
   program — and why does that make the naming almost defensible?
3. Fig. 2-2 has four transitions. Which ones are invisible in Linux's state
   field, and where does that information actually live?
4. In one sentence, using how signals are delivered: why can't `kill -9` kill
   a `D`-state process?
5. `same_thread_group()` compares `signal` pointers, not tgids. Why that
   field and not `tgid`? (Guess, then go look.)
6. Fig. 2-11 says open files are per-process. Which flag would give me two
   tasks that share file descriptors but *not* address space, and is that a
   process or a thread?

# My own notes

_(below this line — during/after. raw is fine. wrong is fine.)_
