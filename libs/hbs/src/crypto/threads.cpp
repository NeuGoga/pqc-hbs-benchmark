#include "crypto/threads.h"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

#if defined(__linux__)
#include <fstream>
#include <set>
#include <utility>
#endif

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace {

void prefer_passive_wait() {
  static std::once_flag once;
  std::call_once(once, [] {
    /* Read by libgomp on the first parallel region, so this still lands
       if nothing else has entered OpenMP yet. Idle workers then sleep
       instead of spinning the core at the barrier. */
    if (!std::getenv("OMP_WAIT_POLICY")) {
#ifdef _WIN32
      _putenv("OMP_WAIT_POLICY=PASSIVE");
#else
      setenv("OMP_WAIT_POLICY", "PASSIVE", 0);
#endif
    }
#ifndef _WIN32
    if (!std::getenv("GOMP_SPINCOUNT"))
      setenv("GOMP_SPINCOUNT", "0", 0);
#endif
  });
}

int detect_physical() {
#if defined(_WIN32)
  DWORD bytes = 0;
  if (GetLogicalProcessorInformation(nullptr, &bytes) ||
      GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes == 0)
    return 0;
  std::string buf(bytes, '\0');
  auto *info =
      reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION>(buf.data());
  if (!GetLogicalProcessorInformation(info, &bytes))
    return 0;
  int n = 0;
  int count = (int)(bytes / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION));
  for (int i = 0; i < count; ++i)
    if (info[i].Relationship == RelationProcessorCore)
      ++n;
  return n;
#elif defined(__linux__)
  std::ifstream in("/proc/cpuinfo");
  if (!in)
    return 0;
  std::set<std::pair<int, int>> cores;
  int phys = -1, core = -1;
  std::string line;
  auto flush = [&] {
    if (core >= 0)
      cores.insert({phys < 0 ? 0 : phys, core});
    phys = -1;
    core = -1;
  };
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    if (line.empty()) {
      flush();
      continue;
    }
    auto colon = line.find(':');
    if (colon == std::string::npos)
      continue;
    std::string key = line.substr(0, colon);
    while (!key.empty() && (key.back() == ' ' || key.back() == '\t'))
      key.pop_back();
    std::string val = line.substr(colon + 1);
    while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
      val.erase(val.begin());
    if (key == "physical id")
      phys = std::atoi(val.c_str());
    else if (key == "core id")
      core = std::atoi(val.c_str());
  }
  flush();
  return cores.empty() ? 0 : (int)cores.size();
#else
  return 0;
#endif
}

std::atomic<int> g_budget{-1};

int choose_budget() {
  int logical = (int)std::thread::hardware_concurrency();
  if (logical < 1)
    logical = 1;

  if (const char *e = std::getenv("HBS_THREADS")) {
    if (std::strcmp(e, "all") == 0 || std::strcmp(e, "max") == 0 ||
        std::strcmp(e, "0") == 0)
      return logical;
    int n = std::atoi(e);
    if (n < 1)
      n = 1;
    if (n > logical)
      n = logical;
    return n;
  }

  if (const char *o = std::getenv("OMP_NUM_THREADS")) {
    /* First number only: "4,2" means 4 at the outermost level. */
    int n = std::atoi(o);
    if (n < 1)
      n = 1;
    if (n > logical)
      n = logical;
    return n;
  }

  int physical = detect_physical();
  if (physical < 1 || physical > logical)
    physical = logical;
  int n = physical;
  /* No SMT: using every core pegs the machine and starves the GUI.
     With SMT, physical cores already sit near half the logical meter
     and Keccak barely benefits from the extra siblings. */
  if (physical >= logical && n > 1)
    --n;
  if (n < 1)
    n = 1;
  return n;
}

} // namespace

int hbs_thread_budget() {
  prefer_passive_wait();
  int cur = g_budget.load(std::memory_order_acquire);
  if (cur > 0)
    return cur;
  int chosen = choose_budget();
  int expected = -1;
  if (!g_budget.compare_exchange_strong(expected, chosen))
    return g_budget.load(std::memory_order_acquire);
  return chosen;
}

int hbs_threads_for(int work) {
  if (work <= 1)
    return 1;
  int b = hbs_thread_budget();
  if (b > work)
    b = work;
  if (b < 1)
    b = 1;
  return b;
}
