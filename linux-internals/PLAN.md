# Plan (loose — not a syllabus)

Order is decided at the end of each session based on what's actually
interesting, not a fixed table of contents. This is just what's queued
right now.

- [x] 2026-09-04 — Processes & Threads: book chapter + `start_kernel()` +
      trace `getpid()` end to end (see dated file). Reading done 09-04;
      experiments + written questions closed out 09-07 in the same file.
- [x] 2026-09-08 — `struct task_struct` anatomy (§1.6 in the 09-04 file):
      `sched.h:835`, Fig. 2-4 mapped to real fields, the pointer-to-sub-struct
      split.
- [x] 2026-09-09 — Process lifecycle deep dive, added to the 09-04 file.
      §1.7 creation (`kernel_clone` → `copy_process` → the `copy_*` calls →
      COW via `copy_mm` / `dup_mm`; `execve` → `bprm_execve` →
      `search_binary_handler` → `begin_new_exec` / `de_thread` / `exec_mmap`),
      §1.8 termination & reaping (`do_exit` → `exit_notify` → `EXIT_ZOMBIE`;
      `find_new_reaper`; `wait_task_zombie` → `EXIT_DEAD` → `release_task`),
      §1.9 hierarchies (`real_parent`/`parent`, `children`/`sibling`,
      `PIDTYPE_PGID`/`PIDTYPE_SID`, `setsid`, orphaned-pgrp SIGHUP).
      Covers the §2.1.2 / §2.1.3 / §2.1.4 gaps. Still open: `binfmt_elf` /
      `load_elf_binary` (ELF mapping, `ld.so`, `auxv`); `copy_thread` arch
      code (how the child returns 0); the `get_signal()` path that turns
      SIGSEGV into `do_group_exit`; job-control stop/cont.
- [ ] `dup_mmap` / `copy_page_range` COW mechanics — folds into the mm session.
- [ ] Memory Management → Linux VM (mm/, page tables, `mm_struct`)
- [ ] File Systems → Linux VFS (`struct file`, dentries, inodes)
- [ ] (rest TBD — pick it when we get there, not before)

Rule: when the book triggers a "how does Linux actually do this," go look
immediately, even mid-chapter. Don't wait to finish the section.
