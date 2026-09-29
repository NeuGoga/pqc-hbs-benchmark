#ifdef _WIN32
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>

#include <algorithm>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(                                                               \
    linker,                                                                    \
    "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace {

enum {
  IDC_TYPE = 101,
  IDC_SCHEMES = 102,
  IDC_ITERS = 103,
  IDC_ADD = 104,
  IDC_QUEUE = 105,
  IDC_REMOVE = 106,
  IDC_RUN = 107,
  IDC_CANCEL = 108,
  IDC_PROGRESS = 109,
  IDC_PHASE = 110,
  IDC_RESULTS = 111,
  IDC_EXPORT = 112,
  IDC_LOG = 113,
  IDC_STATUS = 114,
  IDC_LBL_TYPE = 115,
  IDC_LBL_SCHEME = 116,
  IDC_LBL_ITERS = 117
};

const UINT WM_WORKER_LINE = WM_APP + 1;
const UINT WM_WORKER_DONE = WM_APP + 2;

struct Scheme {
  std::wstring name;
  std::string type;
  std::string family;
  bool stateful = false;
  int workerType = 2;
  long long pk = 0, sk = 0, sig = 0;
};

struct QueueItem {
  Scheme scheme;
  int iterations = 8;
};

struct RunResult {
  std::wstring name;
  std::wstring status;
  std::wstring pk, sk, sig;
  std::wstring keygenUs, signUs, verifyUs;
  std::wstring keygenMem, signMem, verifyMem;
};

HWND g_wnd = nullptr;
HWND g_type = nullptr, g_schemes = nullptr, g_iters = nullptr;
HWND g_add = nullptr, g_remove = nullptr, g_run = nullptr, g_cancel = nullptr,
     g_export = nullptr;
HWND g_queue = nullptr, g_results = nullptr, g_progress = nullptr;
HWND g_phase = nullptr, g_status = nullptr, g_log = nullptr;
HFONT g_font = nullptr;

std::vector<Scheme> g_schemes_all;
std::vector<QueueItem> g_queue_items;
std::vector<RunResult> g_results_items;

bool g_busy = false;
bool g_cancel = false;
int g_queue_index = -1;
int g_step = 0;
RunResult g_current;
std::string g_stdout_acc;
HANDLE g_job_proc = nullptr;

std::wstring utf8_to_wide(const std::string &s) {
  if (s.empty())
    return {};
  int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
  std::wstring w(n, 0);
  MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
  return w;
}

std::string wide_to_utf8(const std::wstring &w) {
  if (w.empty())
    return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0,
                              nullptr, nullptr);
  std::string s(n, 0);
  WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n,
                      nullptr, nullptr);
  return s;
}

std::wstring exe_dir() {
  wchar_t buf[MAX_PATH];
  GetModuleFileNameW(nullptr, buf, MAX_PATH);
  std::wstring p(buf);
  size_t slash = p.find_last_of(L"\\/");
  return slash == std::wstring::npos ? L"." : p.substr(0, slash);
}

std::wstring worker_path() { return exe_dir() + L"\\benchmark.exe"; }

void log_line(const std::wstring &line) {
  int len = GetWindowTextLengthW(g_log);
  SendMessageW(g_log, EM_SETSEL, len, len);
  std::wstring t = line + L"\r\n";
  SendMessageW(g_log, EM_REPLACESEL, FALSE, (LPARAM)t.c_str());
}

void set_status(const std::wstring &s) { SetWindowTextW(g_status, s.c_str()); }

void set_phase(const std::wstring &s) { SetWindowTextW(g_phase, s.c_str()); }

int type_code(const std::string &t) {
  if (t == "oqs_stateless")
    return 0;
  if (t == "oqs_stateful")
    return 1;
  return 2;
}

std::string selected_type() {
  int i = (int)SendMessageW(g_type, CB_GETCURSEL, 0, 0);
  if (i == 0)
    return "custom";
  if (i == 1)
    return "oqs_stateless";
  return "oqs_stateful";
}

void lv_add_col(HWND lv, int i, const wchar_t *title, int w) {
  LVCOLUMNW c{};
  c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
  c.pszText = const_cast<wchar_t *>(title);
  c.cx = w;
  c.iSubItem = i;
  ListView_InsertColumn(lv, i, &c);
}

void lv_set(HWND lv, int row, int col, const std::wstring &text) {
  LVITEMW it{};
  it.mask = LVIF_TEXT;
  it.iItem = row;
  it.iSubItem = col;
  it.pszText = const_cast<wchar_t *>(text.c_str());
  if (col == 0)
    ListView_InsertItem(lv, &it);
  else
    ListView_SetItem(lv, &it);
}

void refill_schemes() {
  SendMessageW(g_schemes, LB_RESETCONTENT, 0, 0);
  std::string want = selected_type();
  int n = 0;
  for (const auto &s : g_schemes_all) {
    if (s.type != want)
      continue;
    SendMessageW(g_schemes, LB_ADDSTRING, 0, (LPARAM)s.name.c_str());
    ++n;
  }
  if (n == 0) {
    const wchar_t *msg = want.rfind("oqs", 0) == 0
                             ? L"(none — liboqs was not linked in this build)"
                             : L"(none — libhbs was not linked in this build)";
    SendMessageW(g_schemes, LB_ADDSTRING, 0, (LPARAM)msg);
  }
}

struct ProcResult {
  DWORD code = 1;
  std::string out;
  std::string err;
};

bool run_process_capture(const std::wstring &cmd, ProcResult &res,
                         bool stream_progress) {
  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  HANDLE outR = nullptr, outW = nullptr, errR = nullptr, errW = nullptr;
  if (!CreatePipe(&outR, &outW, &sa, 0) || !CreatePipe(&errR, &errW, &sa, 0))
    return false;
  SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(errR, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdOutput = outW;
  si.hStdError = errW;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

  PROCESS_INFORMATION pi{};
  std::wstring mutable_cmd = cmd;
  std::wstring cwd = exe_dir();
  BOOL ok = CreateProcessW(nullptr, mutable_cmd.data(), nullptr, nullptr, TRUE,
                           CREATE_NO_WINDOW, nullptr, cwd.c_str(), &si, &pi);
  CloseHandle(outW);
  CloseHandle(errW);
  if (!ok) {
    CloseHandle(outR);
    CloseHandle(errR);
    return false;
  }
  g_job_proc = pi.hProcess;

  auto drain = [&](HANDLE h, std::string &acc, bool progress) {
    char buf[1024];
    DWORD n = 0;
    while (PeekNamedPipe(h, nullptr, 0, nullptr, &n, nullptr) && n) {
      DWORD got = 0;
      if (!ReadFile(h, buf, sizeof(buf) - 1, &got, nullptr) || got == 0)
        break;
      acc.append(buf, got);
      if (progress) {
        size_t pos;
        while ((pos = acc.find('\n')) != std::string::npos) {
          std::string line = acc.substr(0, pos);
          acc.erase(0, pos + 1);
          if (!line.empty() && line.back() == '\r')
            line.pop_back();
          if (g_wnd) {
            auto *heap = new std::string(std::move(line));
            PostMessageW(g_wnd, WM_WORKER_LINE, 0, (LPARAM)heap);
          }
        }
      }
    }
  };

  std::string err_acc;
  for (;;) {
    drain(outR, res.out, false);
    drain(errR, err_acc, stream_progress);
    if (WaitForSingleObject(pi.hProcess, 40) == WAIT_OBJECT_0) {
      drain(outR, res.out, false);
      drain(errR, err_acc, stream_progress);
      break;
    }
    if (g_cancel) {
      TerminateProcess(pi.hProcess, 9);
      WaitForSingleObject(pi.hProcess, 2000);
      break;
    }
  }
  GetExitCodeProcess(pi.hProcess, &res.code);
  if (!stream_progress)
    res.err = err_acc;
  CloseHandle(outR);
  CloseHandle(errR);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  g_job_proc = nullptr;
  return true;
}

void load_schemes() {
  g_schemes_all.clear();
  std::wstring cmd = L"\"" + worker_path() + L"\" --list";
  ProcResult r;
  if (!run_process_capture(cmd, r, false)) {
    set_status(L"Worker not found. Keep benchmark.exe next to hbs-bench.exe.");
    log_line(L"Could not start " + worker_path());
    refill_schemes();
    return;
  }
  if (!r.err.empty())
    log_line(utf8_to_wide(r.err));
  std::istringstream in(r.out);
  std::string line;
  std::getline(in, line); // header
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    if (line.empty())
      continue;
    std::vector<std::string> c;
    std::string tok;
    std::istringstream ls(line);
    while (std::getline(ls, tok, ','))
      c.push_back(tok);
    if (c.size() < 7)
      continue;
    Scheme s;
    s.name = utf8_to_wide(c[0]);
    s.type = c[1];
    s.family = c[2];
    s.stateful = c[3] == "1";
    s.workerType = type_code(s.type);
    s.pk = std::stoll(c[4].empty() ? "0" : c[4]);
    s.sk = std::stoll(c[5].empty() ? "0" : c[5]);
    s.sig = std::stoll(c[6].empty() ? "0" : c[6]);
    g_schemes_all.push_back(s);
  }
  set_status(std::to_wstring(g_schemes_all.size()) +
             L" scheme(s) discovered from worker.");
  refill_schemes();
}

void refresh_queue() {
  ListView_DeleteAllItems(g_queue);
  for (int i = 0; i < (int)g_queue_items.size(); ++i) {
    lv_set(g_queue, i, 0, g_queue_items[i].scheme.name);
    lv_set(g_queue, i, 1, utf8_to_wide(g_queue_items[i].scheme.type));
    lv_set(g_queue, i, 2, std::to_wstring(g_queue_items[i].iterations));
  }
}

void append_result_row(const RunResult &r) {
  int row = ListView_GetItemCount(g_results);
  lv_set(g_results, row, 0, r.name);
  lv_set(g_results, row, 1, r.status);
  lv_set(g_results, row, 2, r.pk);
  lv_set(g_results, row, 3, r.sk);
  lv_set(g_results, row, 4, r.sig);
  lv_set(g_results, row, 5, r.keygenUs);
  lv_set(g_results, row, 6, r.signUs);
  lv_set(g_results, row, 7, r.verifyUs);
}

void set_busy(bool busy) {
  g_busy = busy;
  EnableWindow(g_add, !busy);
  EnableWindow(g_remove, !busy);
  EnableWindow(g_run, !busy);
  EnableWindow(g_type, !busy);
  EnableWindow(g_schemes, !busy);
  EnableWindow(g_iters, !busy);
  EnableWindow(g_cancel, busy);
}

std::vector<std::string> split_csv(const std::string &s) {
  std::vector<std::string> c;
  std::string tok;
  std::istringstream ls(s);
  while (std::getline(ls, tok, ','))
    c.push_back(tok);
  return c;
}

struct JobArgs {
  std::wstring cmd;
};

DWORD WINAPI job_thread(LPVOID p) {
  auto *args = static_cast<JobArgs *>(p);
  ProcResult r;
  run_process_capture(args->cmd, r, true);
  auto *out = new std::string(r.out);
  PostMessageW(g_wnd, WM_WORKER_DONE, (WPARAM)r.code, (LPARAM)out);
  delete args;
  return 0;
}

void start_worker(const std::wstring &cmd) {
  g_stdout_acc.clear();
  auto *args = new JobArgs{cmd};
  HANDLE th = CreateThread(nullptr, 0, job_thread, args, 0, nullptr);
  if (th)
    CloseHandle(th);
}

std::wstring quoted(const std::wstring &s) { return L"\"" + s + L"\""; }

void start_step() {
  if (g_cancel || g_queue_index >= (int)g_queue_items.size()) {
    set_busy(false);
    set_phase(g_cancel ? L"Cancelled" : L"Done");
    SendMessageW(g_progress, PBM_SETRANGE, 0, MAKELPARAM(0, 1));
    SendMessageW(g_progress, PBM_SETPOS, 1, 0);
    return;
  }
  const QueueItem &q = g_queue_items[g_queue_index];
  std::wstring cmd = quoted(worker_path()) + L" " + quoted(q.scheme.name) +
                     L" " + std::to_wstring(q.scheme.workerType) + L" " +
                     std::to_wstring(g_step) + L" ";
  if (g_step == 0)
    cmd += L"1 1";
  else
    cmd += std::to_wstring(q.iterations) + L" 1";
  if (g_step == 0)
    set_phase(q.scheme.name + L"  keygen");
  start_worker(cmd);
}

void finish_current() {
  g_results_items.push_back(g_current);
  append_result_row(g_current);
}

void on_worker_done(DWORD code, std::string out) {
  while (!out.empty() && (out.back() == '\n' || out.back() == '\r'))
    out.pop_back();
  bool skipped = out.rfind("SKIP", 0) == 0 || code == 2;
  bool failed = code != 0 && !skipped;

  auto csv = split_csv(out);

  if (g_step == 0) {
    if (skipped || failed) {
      g_current.status = skipped ? L"skipped" : L"keygen failed";
      log_line(g_current.name + L" " + g_current.status);
      finish_current();
      ++g_queue_index;
      g_step = 0;
      start_step();
      return;
    }
    if (csv.size() >= 5) {
      g_current.keygenUs = utf8_to_wide(csv[0]);
      g_current.keygenMem = utf8_to_wide(csv[1]);
      g_current.pk = utf8_to_wide(csv[2]);
      g_current.sk = utf8_to_wide(csv[3]);
      g_current.sig = utf8_to_wide(csv[4]);
    }
    g_step = 1;
    start_step();
    return;
  }
  if (g_step == 1) {
    if (skipped || failed) {
      g_current.status = skipped ? L"sign skipped" : L"sign failed";
      finish_current();
      ++g_queue_index;
      g_step = 0;
      start_step();
      return;
    }
    if (csv.size() >= 2) {
      g_current.signUs = utf8_to_wide(csv[0]);
      g_current.signMem = utf8_to_wide(csv[1]);
    }
    g_step = 2;
    start_step();
    return;
  }
  if (skipped || failed)
    g_current.status = skipped ? L"verify skipped" : L"verify failed";
  else {
    g_current.status = L"ok";
    if (csv.size() >= 2) {
      g_current.verifyUs = utf8_to_wide(csv[0]);
      g_current.verifyMem = utf8_to_wide(csv[1]);
    }
  }
  finish_current();
  ++g_queue_index;
  g_step = 0;
  if (g_queue_index < (int)g_queue_items.size()) {
    g_current = {};
    g_current.name = g_queue_items[g_queue_index].scheme.name;
    g_current.status = L"running";
    g_current.pk = std::to_wstring(g_queue_items[g_queue_index].scheme.pk);
    g_current.sk = std::to_wstring(g_queue_items[g_queue_index].scheme.sk);
    g_current.sig = std::to_wstring(g_queue_items[g_queue_index].scheme.sig);
  }
  start_step();
}

void add_to_queue() {
  int sel = (int)SendMessageW(g_schemes, LB_GETCURSEL, 0, 0);
  if (sel < 0)
    return;
  wchar_t name[256]{};
  SendMessageW(g_schemes, LB_GETTEXT, sel, (LPARAM)name);
  std::wstring wname(name);
  if (wname.rfind(L"(none", 0) == 0)
    return;
  wchar_t iters_buf[32]{};
  GetWindowTextW(g_iters, iters_buf, 32);
  int iters = _wtoi(iters_buf);
  if (iters < 1)
    iters = 1;
  for (const auto &s : g_schemes_all) {
    if (s.name != wname)
      continue;
    if (s.stateful && iters > 16) {
      MessageBoxW(g_wnd,
                  L"Stateful schemes consume one-time keys. Iterations were "
                  L"capped at 16.",
                  L"HBS Bench", MB_OK | MB_ICONWARNING);
      iters = 16;
    }
    g_queue_items.push_back({s, iters});
    refresh_queue();
    return;
  }
}

void remove_queue() {
  int sel = ListView_GetNextItem(g_queue, -1, LVNI_SELECTED);
  if (sel < 0 || sel >= (int)g_queue_items.size())
    return;
  g_queue_items.erase(g_queue_items.begin() + sel);
  refresh_queue();
}

void run_queue() {
  if (g_queue_items.empty()) {
    MessageBoxW(g_wnd, L"Add at least one scheme.", L"HBS Bench",
                MB_OK | MB_ICONINFORMATION);
    return;
  }
  g_cancel = false;
  g_queue_index = 0;
  g_step = 0;
  g_results_items.clear();
  ListView_DeleteAllItems(g_results);
  g_current = {};
  g_current.name = g_queue_items[0].scheme.name;
  g_current.status = L"running";
  set_busy(true);
  start_step();
}

void export_csv() {
  if (g_results_items.empty())
    return;
  wchar_t file[MAX_PATH] = L"results.csv";
  OPENFILENAMEW ofn{};
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = g_wnd;
  ofn.lpstrFilter = L"CSV (*.csv)\0*.csv\0All\0*.*\0";
  ofn.lpstrFile = file;
  ofn.nMaxFile = MAX_PATH;
  ofn.Flags = OFN_OVERWRITEPROMPT;
  ofn.lpstrDefExt = L"csv";
  if (!GetSaveFileNameW(&ofn))
    return;
  std::ofstream f(wide_to_utf8(file));
  if (!f) {
    MessageBoxW(g_wnd, L"Could not write file.", L"Export",
                MB_OK | MB_ICONWARNING);
    return;
  }
  f << "Algorithm,Status,PK Size (B),SK Size (B),Sig Size (B),Keygen Time "
       "(us),Sign Time (us),Verify Time (us),Keygen Peak Mem (KB),Sign Peak "
       "Mem (KB)\n";
  for (const auto &r : g_results_items) {
    f << wide_to_utf8(r.name) << "," << wide_to_utf8(r.status) << ","
      << wide_to_utf8(r.pk) << "," << wide_to_utf8(r.sk) << ","
      << wide_to_utf8(r.sig) << "," << wide_to_utf8(r.keygenUs) << ","
      << wide_to_utf8(r.signUs) << "," << wide_to_utf8(r.verifyUs) << ","
      << wide_to_utf8(r.keygenMem) << "," << wide_to_utf8(r.signMem) << "\n";
  }
}

void layout(int w, int h) {
  const int pad = 12;
  const int left = 280;
  int y = pad;
  MoveWindow(g_status, pad, y, left - pad, 36, TRUE);
  y += 40;
  MoveWindow(GetDlgItem(g_wnd, IDC_LBL_TYPE), pad, y, 80, 18, TRUE);
  MoveWindow(g_type, pad + 80, y - 2, left - pad - 80, 22, TRUE);
  y += 28;
  MoveWindow(GetDlgItem(g_wnd, IDC_LBL_SCHEME), pad, y, left - pad, 18, TRUE);
  y += 20;
  int scheme_h = (std::max)(80, h / 3);
  MoveWindow(g_schemes, pad, y, left - pad, scheme_h, TRUE);
  y += scheme_h + 8;
  MoveWindow(GetDlgItem(g_wnd, IDC_LBL_ITERS), pad, y, 80, 18, TRUE);
  MoveWindow(g_iters, pad + 80, y - 2, 80, 22, TRUE);
  y += 32;
  MoveWindow(g_add, pad, y, left - pad, 28, TRUE);

  int rx = left + pad;
  int rw = w - rx - pad;
  int log_h = 110;
  int top_h = h - log_h - pad * 2;
  int qh = top_h / 3;
  int y2 = pad;
  MoveWindow(g_queue, rx, y2, rw, qh - 40, TRUE);
  y2 += qh - 36;
  int bw = 90;
  MoveWindow(g_remove, rx, y2, bw, 26, TRUE);
  MoveWindow(g_cancel, rx + rw - bw * 2 - 8, y2, bw, 26, TRUE);
  MoveWindow(g_run, rx + rw - bw, y2, bw, 26, TRUE);
  y2 += 34;
  MoveWindow(g_phase, rx, y2, rw, 18, TRUE);
  y2 += 20;
  MoveWindow(g_progress, rx, y2, rw, 20, TRUE);
  y2 += 28;
  int res_h = (std::max)(80, top_h - y2 - 36);
  MoveWindow(g_results, rx, y2, rw, res_h, TRUE);
  MoveWindow(g_export, rx + rw - 110, y2 + res_h + 6, 110, 26, TRUE);
  MoveWindow(g_log, pad, h - log_h - pad, w - pad * 2, log_h, TRUE);
}

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
  switch (m) {
  case WM_CREATE: {
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_LISTVIEW_CLASSES |
                                              ICC_BAR_CLASSES |
                                              ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);
    g_font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    auto mk = [&](LPCWSTR cls, LPCWSTR text, DWORD style, int id) {
      HWND c = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, 0,
                               0, 10, 10, h, (HMENU)(intptr_t)id,
                               GetModuleHandleW(nullptr), nullptr);
      SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
      return c;
    };
    mk(L"STATIC", L"Type", 0, IDC_LBL_TYPE);
    g_type = mk(L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_VSCROLL, IDC_TYPE);
    mk(L"STATIC", L"Scheme", 0, IDC_LBL_SCHEME);
    g_schemes =
        mk(L"LISTBOX", L"", WS_BORDER | WS_VSCROLL | LBS_NOTIFY, IDC_SCHEMES);
    mk(L"STATIC", L"Iterations", 0, IDC_LBL_ITERS);
    g_iters = mk(L"EDIT", L"8", WS_BORDER | ES_NUMBER, IDC_ITERS);
    g_add = mk(L"BUTTON", L"Add to queue", BS_PUSHBUTTON, IDC_ADD);
    g_queue = mk(WC_LISTVIEWW, L"", WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
                 IDC_QUEUE);
    g_remove = mk(L"BUTTON", L"Remove", 0, IDC_REMOVE);
    g_run = mk(L"BUTTON", L"Run queue", 0, IDC_RUN);
    g_cancel = mk(L"BUTTON", L"Cancel", WS_DISABLED, IDC_CANCEL);
    g_phase = mk(L"STATIC", L"Idle", 0, IDC_PHASE);
    g_progress = mk(PROGRESS_CLASSW, L"", 0, IDC_PROGRESS);
    g_results = mk(WC_LISTVIEWW, L"", WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
                   IDC_RESULTS);
    g_export = mk(L"BUTTON", L"Export CSV", 0, IDC_EXPORT);
    g_status = mk(L"STATIC", L"", 0, IDC_STATUS);
    g_log = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                            WS_CHILD | WS_VISIBLE | ES_MULTILINE |
                                ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                            0, 0, 10, 10, h, (HMENU)IDC_LOG,
                            GetModuleHandleW(nullptr), nullptr);
    SendMessageW(g_log, WM_SETFONT, (WPARAM)g_font, TRUE);

    ListView_SetExtendedListViewStyle(g_queue,
                                      LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    ListView_SetExtendedListViewStyle(g_results,
                                      LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    lv_add_col(g_queue, 0, L"Scheme", 180);
    lv_add_col(g_queue, 1, L"Type", 110);
    lv_add_col(g_queue, 2, L"Iters", 60);
    const wchar_t *rh[] = {L"Algorithm", L"Status",  L"PK",       L"SK", L"Sig",
                           L"Keygen us", L"Sign us", L"Verify us"};
    const int rw[] = {160, 90, 60, 60, 70, 90, 80, 80};
    for (int i = 0; i < 8; ++i)
      lv_add_col(g_results, i, rh[i], rw[i]);

    SendMessageW(g_type, CB_ADDSTRING, 0, (LPARAM)L"Custom (libhbs)");
    SendMessageW(g_type, CB_ADDSTRING, 0, (LPARAM)L"OQS stateless");
    SendMessageW(g_type, CB_ADDSTRING, 0, (LPARAM)L"OQS stateful");
    SendMessageW(g_type, CB_SETCURSEL, 0, 0);
    SendMessageW(g_progress, PBM_SETRANGE, 0, MAKELPARAM(0, 1));
    load_schemes();
    return 0;
  }
  case WM_SIZE:
    layout(LOWORD(l), HIWORD(l));
    return 0;
  case WM_COMMAND:
    switch (LOWORD(w)) {
    case IDC_TYPE:
      if (HIWORD(w) == CBN_SELCHANGE)
        refill_schemes();
      break;
    case IDC_ADD:
      add_to_queue();
      break;
    case IDC_REMOVE:
      remove_queue();
      break;
    case IDC_RUN:
      run_queue();
      break;
    case IDC_CANCEL:
      g_cancel = true;
      if (g_job_proc)
        TerminateProcess(g_job_proc, 9);
      break;
    case IDC_EXPORT:
      export_csv();
      break;
    }
    return 0;
  case WM_WORKER_LINE: {
    auto *line = reinterpret_cast<std::string *>(l);
    std::string s = *line;
    delete line;
    if (s.rfind("PROGRESS ", 0) == 0) {
      std::istringstream is(s);
      std::string tag, phase;
      int i = 0, n = 1;
      is >> tag >> phase >> i >> n;
      if (n < 1)
        n = 1;
      SendMessageW(g_progress, PBM_SETRANGE, 0, MAKELPARAM(0, n));
      SendMessageW(g_progress, PBM_SETPOS, i, 0);
      set_phase(g_current.name + L"  " + utf8_to_wide(phase) + L"  " +
                std::to_wstring(i) + L" / " + std::to_wstring(n));
    } else if (!s.empty())
      log_line(utf8_to_wide(s));
    return 0;
  }
  case WM_WORKER_DONE: {
    auto *out = reinterpret_cast<std::string *>(l);
    std::string s = *out;
    delete out;
    on_worker_done((DWORD)w, s);
    return 0;
  }
  case WM_DESTROY:
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProcW(h, m, w, l);
}

} // namespace

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int show) {
  WNDCLASSW wc{};
  wc.lpfnWndProc = WndProc;
  wc.hInstance = inst;
  wc.lpszClassName = L"HbsBenchWnd";
  wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
  wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  RegisterClassW(&wc);
  g_wnd = CreateWindowExW(
      0, wc.lpszClassName, L"HBS Bench", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
      CW_USEDEFAULT, CW_USEDEFAULT, 1100, 720, nullptr, nullptr, inst, nullptr);
  ShowWindow(g_wnd, show);
  MSG msg;
  while (GetMessageW(&msg, nullptr, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  return (int)msg.wParam;
}
#else
int main() { return 1; }
#endif
