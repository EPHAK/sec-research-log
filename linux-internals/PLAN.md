# Plan (loose — not a syllabus)

Order is decided at the end of each session based on what's actually
interesting, not a fixed table of contents. This is just what's queued
right now.

- [x] 2026-09-04 — Processes & Threads: book chapter + `start_kernel()` +
      trace `getpid()` end to end (see dated file). Reading done 09-04;
      experiments + written questions closed out 09-07 in the same file.
- [ ] Process creation deep dive — `task_struct` (`sched.h:835`),
      `copy_process()` (`fork.c:2012`), `execve` (`fs/exec.c`). Do this
      *after* getting comfortable navigating the tree, not as the first
      thing opened cold.
- [ ] Memory Management → Linux VM (mm/, page tables, `mm_struct`)
- [ ] File Systems → Linux VFS (`struct file`, dentries, inodes)
- [ ] (rest TBD — pick it when we get there, not before)

Rule: when the book triggers a "how does Linux actually do this," go look
immediately, even mid-chapter. Don't wait to finish the section.
