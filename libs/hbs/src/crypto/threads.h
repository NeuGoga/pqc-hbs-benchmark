#pragma once

/* Process-wide cap for libhbs OpenMP teams.

   HBS_THREADS=N           use N threads
   HBS_THREADS=all|max|0   every logical CPU (the old "99%" behaviour)
   unset + OMP_NUM_THREADS honor that instead
   otherwise               physical cores, minus one when the CPU has no SMT
                           so a core stays free for the OS and the GUI
*/
int hbs_thread_budget();

/* min(budget, work), at least 1. */
int hbs_threads_for(int work);
