#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <io.h>
#define hbs_popen _popen
#define hbs_pclose _pclose
#define hbs_isatty _isatty
#define hbs_fileno _fileno
#else
#include <unistd.h>
#define hbs_popen popen
#define hbs_pclose pclose
#define hbs_isatty isatty
#define hbs_fileno fileno
#endif

/* Terminal UI. Built with the C++ standard library only, so it still runs
   when Qt is not installed and (on Windows) when the Win32 window is not
   the one you want. It drives the same benchmark executable as the other
   front ends. */

static std::string worker_path() {
#ifdef _WIN32
  return "benchmark.exe";
#else
  return "./benchmark";
#endif
}

static std::string capture(const std::string &cmd) {
  std::string out;
  FILE *pipe = hbs_popen(cmd.c_str(), "r");
  if (!pipe)
    return out;
  char buf[512];
  while (std::fgets(buf, sizeof(buf), pipe))
    out += buf;
  hbs_pclose(pipe);
  return out;
}

struct Scheme {
  std::string name;
  std::string kind;
  int pk = 0;
  int sk = 0;
  int sig = 0;
};

static int kind_code(const std::string &kind) {
  if (kind == "custom")
    return 2;
  if (kind == "oqs_stateful")
    return 1;
  return 0;
}

static std::vector<Scheme> load_schemes() {
  std::vector<Scheme> out;
  std::istringstream in(capture(worker_path() + " --list 2>&1"));
  std::string line;
  bool header = true;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    if (line.empty())
      continue;
    if (header) {
      header = false;
      continue;
    }
    std::vector<std::string> col;
    std::string cur;
    for (char c : line) {
      if (c == ',') {
        col.push_back(cur);
        cur.clear();
      } else
        cur.push_back(c);
    }
    col.push_back(cur);
    if (col.size() < 7)
      continue;
    Scheme s;
    s.name = col[0];
    s.kind = col[1];
    s.pk = std::atoi(col[4].c_str());
    s.sk = std::atoi(col[5].c_str());
    s.sig = std::atoi(col[6].c_str());
    out.push_back(s);
  }
  return out;
}

static void set_threads(int n) {
  if (n <= 0)
    return;
  std::string v = std::to_string(n);
#ifdef _WIN32
  _putenv_s("HBS_THREADS", v.c_str());
  _putenv_s("OMP_NUM_THREADS", v.c_str());
  _putenv_s("OMP_DYNAMIC", "FALSE");
  _putenv_s("OMP_WAIT_POLICY", "PASSIVE");
#else
  setenv("HBS_THREADS", v.c_str(), 1);
  setenv("OMP_NUM_THREADS", v.c_str(), 1);
  setenv("OMP_DYNAMIC", "FALSE", 1);
  setenv("OMP_WAIT_POLICY", "PASSIVE", 1);
#endif
}

static int run_one(const Scheme &s, int iterations, int threads) {
  set_threads(threads);
  const std::string thr = threads > 0 ? " " + std::to_string(threads) : "";
  const std::string base = worker_path() + " \"" + s.name + "\" " +
                           std::to_string(kind_code(s.kind));
  const char *phases[] = {"keygen", "sign", "verify"};
  const int modes[] = {0, 1, 2};
  const int iters[] = {1, iterations, iterations};
  std::cout << s.name << "  pk " << s.pk << "  sk " << s.sk << "  sig " << s.sig
            << "\n";
  for (int i = 0; i < 3; i++) {
    std::string cmd = base + " " + std::to_string(modes[i]) + " " +
                      std::to_string(iters[i]) + " 1" + thr + " 2>&1";
    std::cout << "  " << phases[i] << " ... " << std::flush;
    std::string out = capture(cmd);
    if (out.find("SKIP:") != std::string::npos ||
        out.find("FAIL:") != std::string::npos) {
      std::cout << out;
      return 1;
    }
    std::string last;
    std::istringstream rows(out);
    std::string row;
    while (std::getline(rows, row)) {
      if (!row.empty() && row.back() == '\r')
        row.pop_back();
      if (row.empty() || row.rfind("PROGRESS", 0) == 0 ||
          row.rfind("libhbs ", 0) == 0)
        continue;
      last = row;
    }
    std::cout << last << "\n";
  }
  return 0;
}

static void usage() {
  std::cout
      << "hbs-tui            interactive (Qt/Win32 not required)\n"
      << "hbs-tui --list     schemes the benchmark binary knows\n"
      << "hbs-tui run <name> <iterations> [threads]\n"
      << "threads 0 = automatic cap. A positive number is also passed to\n"
      << "the worker as HBS_THREADS and OMP_NUM_THREADS.\n";
}

int main(int argc, char **argv) {
  auto schemes = load_schemes();
  if (argc >= 2 && std::string(argv[1]) == "--list") {
    for (size_t i = 0; i < schemes.size(); i++)
      std::cout << i << "  " << schemes[i].name << "  " << schemes[i].kind
                << "\n";
    return schemes.empty() ? 1 : 0;
  }
  if (argc >= 2 && std::string(argv[1]) == "run") {
    if (argc < 4) {
      usage();
      return 2;
    }
    std::string name = argv[2];
    int iterations = std::atoi(argv[3]);
    int threads = argc >= 5 ? std::atoi(argv[4]) : 0;
    if (iterations < 1)
      iterations = 1;
    for (const auto &s : schemes)
      if (s.name == name)
        return run_one(s, iterations, threads);
    std::cerr << "unknown scheme " << name << "\n";
    return 1;
  }
  if (argc >= 2) {
    usage();
    return 2;
  }
  if (schemes.empty()) {
    std::cerr << "benchmark --list returned nothing. Build ./benchmark first "
                 "and run hbs-tui from that directory.\n";
    return 1;
  }
  std::cout << "HBS bench\n"
            << "Front end: terminal. Qt is used when it is installed; "
               "Windows falls back to Win32; this UI needs neither.\n\n";
  for (size_t i = 0; i < schemes.size(); i++)
    std::cout << "  " << i << "  " << schemes[i].name << "\n";
  if (!hbs_isatty(hbs_fileno(stdin))) {
    usage();
    return 0;
  }
  std::cout << "scheme index, iterations, threads (0 = auto): " << std::flush;
  int index = 0, iterations = 1, threads = 0;
  if (!(std::cin >> index >> iterations >> threads))
    return 2;
  if (index < 0 || (size_t)index >= schemes.size()) {
    std::cerr << "bad index\n";
    return 1;
  }
  if (iterations < 1)
    iterations = 1;
  return run_one(schemes[(size_t)index], iterations, threads);
}
