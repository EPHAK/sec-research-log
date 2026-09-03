# 2026-09-04 — Processes & Threads

## Book (Modern Operating Systems, 5th ed. — Tanenbaum & Bos)

Local copy: `/home/ephak/research/books/mos-5th-tanenbaum.pdf` (1185pp)

**Start at printed p.88 — §2.1.2 Process Creation.** (Left off at p.87,
Fig. 2-1, end of §2.1.1 The Process Model.)

Page mapping: **PDF page = printed page + 29.** So printed 88 = PDF 117.
Physical copy is the Global Edition, so it may drift a page or two —
re-anchor by section heading if it does.

- Continue through §2.1.2 Process Creation → §2.1.3 Process Termination →
  §2.1.4 Process Hierarchies → §2.1.5 Process States.
- Stop reading the moment a concept makes you go "how does Linux actually do
  this" — don't finish the section first, go look immediately.

Note: §2.1.2's first listed cause of process creation is *system
initialization* — that's literally `start_kernel()`, so the source reading
below picks up exactly where the book leaves off.

(Also on disk, for later: *Operating Systems Design and Implementation*
3rd ed. at `/home/ephak/research/books/osdi-3rd-tanenbaum.pdf`. Not for
tomorrow, but flagging it exists.)

## kernel-internals.org — read alongside the source, not instead of it

These pages exist specifically for what tomorrow is trying to do:
- `syscalls/syscall-entry/` and `syscalls/syscall-define/` — syscall entry
  and dispatch mechanics, directly relevant to tracing `getpid()`.
- `kernel/early-boot/` — narrative walkthrough of `start_kernel()`.
- `mm/fork/` and `sched/sched-fork/` — "what happens when you fork()" and
  the scheduler's side of it. Queued for the later process-creation session,
  not tomorrow, but worth knowing it's there.

## Real source, first pass (`/home/ephak/linuxsrc/linux`, tag v7.3)

Not diving into `task_struct`/`copy_process` yet — that struct is one of the
largest and most historically-accreted in the whole tree, a rough first
thing to open cold. Doing two smaller, more orienting reads instead:

1. **`init/main.c` → `start_kernel()`.** Read it top to bottom. It's close
   to a linear list of "now bring up memory, now the scheduler, now the
   timer, now mount root" — gives a map of how the kernel's pieces fit
   together before understanding any one piece deeply.
2. **Trace `getpid()` end to end**, since it's small enough to hold in your
   head: `kernel/sys.c:999` — `SYSCALL_DEFINE0(getpid)`. Follow it from the
   syscall entry to what it actually touches. This is the generalizable
   move — same thing you'd do chasing an unfamiliar function later.

`task_struct` (`sched.h:835`), `copy_process()` (`fork.c:2012`), and
`execve` (`fs/exec.c`) are queued for a later session once there's more
navigation muscle — see `PLAN.md`.

## Hands-on (do these, don't just read)

```
ps -eLf                     # processes vs threads (LWP column)
cat /proc/self/status       # a live task_struct's userspace view
cat /proc/self/status | grep Threads
strace -f -e trace=clone,fork,vfork,execve ./some_program
```

Write a 5-line C program that calls `fork()` and one that calls
`pthread_create()`, run both under `strace -f`, compare what syscalls each
one actually makes.

---

# Notes

Written ahead of time, from the book pages and the actual source in
`/home/ephak/linuxsrc/linux` (v7.3). Every line number below was checked
against that tree — if something doesn't match what you see, the tree moved,
trust the tree.

Read this *with* the book open, not instead of it. The book gives the model;
this is where the model meets the machine.

---

## 1. "The very first process is hard-crafted when the system is booted"

That's Tanenbaum, p.89, and it's the one sentence in the whole section that
sounds like hand-waving. It isn't. Here's the hand-crafting, in
`init/main.c:676`:

```c
static noinline void __ref __noreturn rest_init(void)
{
	struct kernel_clone_args init_args = {
		.flags		= (CLONE_VM | CLONE_UNTRACED),
		.fn		= kernel_init,
		.fn_arg		= NULL,
	};
	...
	/*
	 * We need to spawn init first so that it obtains pid 1, however
	 * the init task will end up wanting to create kthreads, which, if
	 * we schedule it before we create kthreadd, will OOPS.
	 */
	pid = kernel_clone(&init_args);
```

Things worth sitting with:

- The kernel comment **says the quiet part out loud**: "so that it obtains
  pid 1". PID 1 isn't assigned by decree — init just happens to be first in
  line at the PID allocator. It's a race the kernel wins on purpose.
- Immediately after, `init/main.c:705` spawns **PID 2**:
  `kernel_thread(kthreadd, NULL, NULL, CLONE_FS | CLONE_FILES)`. Every
  kernel thread you see in `ps` wrapped in `[brackets]` descends from this.
  So the process hierarchy in §2.1.4 has *two* roots, not one — userspace
  under PID 1, kernel threads under PID 2.
- The ordering constraint in that comment is a real bug they hit: spawn
  them in the wrong order and it OOPSes. That's the kind of detail no
  textbook has room for.

**Check it yourself tomorrow:**
```
ps -p 1 -o pid,comm
ps -p 2 -o pid,comm
ps --ppid 2 | head        # kthreadd's children
```

## 2. Boot *is* the fork/exec two-step from p.90

The book (p.90) makes a point that UNIX splits process creation in two:
`fork` clones, then `execve` replaces the image, and the gap between them is
where the shell rewires stdin/stdout. Tanenbaum presents this as a userspace
idiom.

Boot does exactly the same dance:

1. **The fork half** — `kernel_clone(&init_args)` above creates PID 1 running
   `kernel_init` (a *kernel* function; there's no userspace program yet).
2. **The exec half** — `kernel_init` → `kernel_init_freeable()` → eventually
   `run_init_process()` at `init/main.c:1467`, whose last line is:
   ```c
   return kernel_execve(init_filename, argv_init, envp_init);
   ```

So PID 1 is born as a kernel thread and then *execve's itself into
userspace*. Same primitive as your shell forking `sort`, applied to the
boundary between kernel and userland. That's a genuinely nice piece of
design economy and it's invisible from the book alone.

The fallback chain right below it (`init/main.c:1617`) is worth reading for
its bluntness:

```c
	if (!try_to_run_init_process("/sbin/init") ||
	    !try_to_run_init_process("/etc/init") ||
	    !try_to_run_init_process("/bin/init") ||
	    !try_to_run_init_process("/bin/sh"))
		return 0;

	panic("No working init found.  Try passing init= option to kernel. ...");
```

**Security-relevant, file this away:** `execute_command` (line 1599) comes
from the `init=` kernel command line parameter, and it's tried *before* all
of those. `init=/bin/sh` at the bootloader is the classic
physical-access root shell — no password, because you've replaced PID 1
before any authentication exists. This is why bootloader passwords and
Secure Boot matter, and it's your first concrete "the boot chain is an
attack surface" data point. Note the ordering: attacker-controlled input
wins over every default.

## 3. getpid() — where the book's process/thread split actually lives

This is the payoff of tracing a small syscall. `kernel/sys.c:999`:

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

Stare at that until it's annoying. `getpid()` — the thing you'd swear
returns "the process ID" — returns the **tgid** (thread *group* id).
`gettid()` returns the **pid**. The kernel's own comment translates it:
*"Thread ID — the internal kernel 'pid'"*.

So the vocabulary is inverted between the two worlds:

| You say | Kernel calls it | Returned by |
|---|---|---|
| PID (the process) | `tgid` | `getpid()` |
| TID (one thread) | `pid` | `gettid()` |

Why it's like this: to Linux there is no separate "process" object. There
are only tasks. A "process" is just *a group of tasks that share a tgid*.
Tanenbaum spends §2.1 on processes and §2.2 on threads as two concepts;
Linux implements one thing and derives both. When you get to §2.2 tomorrow
or the day after, this is the sentence to keep in your head: **the book's
process/thread distinction is, in Linux, a single field.**

Also note `vnr` = "virtual number" — namespace-relative. Both calls resolve
the ID *as seen from the caller's PID namespace*, which is why PID 1 inside
a container is not PID 1 on the host. That's containers, and you'll come
back to it in the isolation chapters. One suffix, whole subsystem behind it.

**Check it yourself:**
```
getpid | gettid   # in a threaded program, these differ for non-main threads
ps -eLf           # PID vs LWP columns — LWP is the kernel's pid
```

## 4. Process states — the book says three, Linux has more

Fig. 2-2 (p.93) gives Running / Ready / Blocked. Now
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

Two mismatches worth catching, because catching mismatches is the actual
skill:

**(a) Linux doesn't distinguish Running from Ready.** Both are
`TASK_RUNNING` (0x0). The book's Fig. 2-2 transitions 2 and 3 — scheduler
picks/deposes a process — don't change the state field *at all* in Linux.
Whether a `TASK_RUNNING` task is executing right now is not a property of
the task; it's a property of some CPU's runqueue. The textbook's state
machine is a model, and this is exactly the kind of place the model and the
implementation part ways.

**(b) The book's single "Blocked" splits in two**, and the split is one
you've already met in the wild:
- `TASK_INTERRUPTIBLE` — blocked, but a signal can yank it out. Normal.
- `TASK_UNINTERRUPTIBLE` — blocked and *deaf to signals*. This is `D` state
  in `ps`. It's why a process stuck on dead NFS or a failing disk survives
  `kill -9`: SIGKILL is delivered by making a task runnable, and this task
  refuses to become runnable. `kill -9` isn't magic; it's a signal, and
  signals need a task willing to wake up.

Also: those are **bit flags**, not an enum — `0x1, 0x2, 0x4, 0x10...`. States
get combined and masked. Ask yourself why that's necessary; the answer is
about the transitions, and it's a decent thing to chase if you have energy.

`EXIT_ZOMBIE` is §2.1.3's terminated-but-not-reaped process, sitting in the
state field with a number on it.

**Check it yourself:**
```
ps -eo pid,stat,comm | head -30    # R, S, D, Z, T in the STAT column
```
Find an `S` (interruptible sleep — most things), and see if you can catch a
`D`.

## 5. §2.1.6's "process table" is a lie-to-children

The book says (p.94): the OS maintains "a table (an array of structures),
called the **process table**, with one entry per process."

Linux has no such array. What it has:

- `struct task_struct` (`include/linux/sched.h:835`) — the per-task
  structure, allocated individually, not slotted into a global array.
- Tasks are threaded onto lists — `for_each_process()` is defined at
  `include/linux/sched/signal.h:640`.
- PID → task lookup goes through an **IDR** (an ID-to-pointer radix tree)
  held per PID namespace: `struct idr idr;` at
  `include/linux/pid_namespace.h:27`, allocated from in `kernel/pid.c:240`
  and `:262`.

Which is to say: a per-namespace sparse map, not a table. The book's flat
array is the right *mental* model and the wrong *implementation*, and the
reason is sitting in that struct name — `pid_namespace`. A flat global array
can't express "PID 1 means different things to different observers."

Fig. 2-4 (p.95) lists the fields a process-table entry "typically" has.
Worth doing as a 10-minute exercise later: open `task_struct` and find
Tanenbaum's fields in it — then notice how many hundreds of fields *aren't*
in his list. That's the honest scale difference between the model and the
thing, and it's a better introduction to that struct than opening it cold.

---

## What to actually do tomorrow

1. Read pp.88–97 (§2.1.2 → §2.1.7). ~40 min.
2. Re-read this file with the source open next to it. Verify at least three
   of the line numbers above yourself — not because I'd lie, but because
   "go check the claim in the tree" is the muscle.
3. Run the five check-it-yourself blocks. They take about ten minutes total.
4. Write your own answers below. Raw. Wrong is fine — wrong and written
   beats right and vague.

## Questions to answer in writing (this is the actual work)

- Why does `rest_init()` create PID 1 *before* PID 2 when the comment says
  init wants kthreads? What breaks in the other order?
- If `getpid()` returns tgid, what does `getpid()` return inside a
  single-threaded program, and why does that make the naming almost defensible?
- The book's Fig. 2-2 has 4 transitions. Which of them are *not* visible in
  Linux's state field, and where does that information live instead?
- `kill -9` can't kill a `D`-state process. Given how signals are delivered,
  explain why in one sentence.
- Where would you look first if you wanted to know whether `init=` can be
  passed after boot? (You can't — but *how would you establish that* from
  the source?)

## My own notes

_(yours — below this line, during/after)_

