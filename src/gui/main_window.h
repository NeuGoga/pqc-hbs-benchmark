#pragma once

#include <QMainWindow>
#include <QProcess>
#include <QVector>

class QComboBox;
class QListWidget;
class QSpinBox;
class QPushButton;
class QTableWidget;
class QProgressBar;
class QLabel;
class QPlainTextEdit;
class QFile;

struct SchemeRow {
  QString name;
  QString type; // custom | oqs_stateless | oqs_stateful
  QString family;
  bool stateful = false;
  int workerType = 2;
  qint64 pk = 0;
  qint64 sk = 0;
  qint64 sig = 0;
};

struct QueueItem {
  SchemeRow scheme;
  int iterations = 8;
};

struct RunResult {
  QString name;
  QString status;
  QString keygenUs;
  QString signUs;
  QString verifyUs;
  QString keygenMem;
  QString signMem;
  QString verifyMem;
  QString pk;
  QString sk;
  QString sig;
};

class MainWindow : public QMainWindow {
  Q_OBJECT

public:
  explicit MainWindow(QWidget *parent = nullptr);

private slots:
  void onTypeChanged();
  void addToQueue();
  void removeSelectedQueue();
  void runQueue();
  void exportCsv();
  void cancelRun();

private:
  void buildUi();
  void loadSchemes();
  void refillSchemeList();
  void logLine(const QString &line);
  void setBusy(bool busy);
  void runNext();
  void startWorker(const QStringList &args);
  void onWorkerStdout();
  void onWorkerStderr();
  void onWorkerFinished(int code, QProcess::ExitStatus st);
  void finishCurrentRow();
  int typeCode(const QString &type) const;
  QString workerPath() const;

  QComboBox *typeBox_ = nullptr;
  QListWidget *schemeList_ = nullptr;
  QSpinBox *itersBox_ = nullptr;
  QPushButton *addBtn_ = nullptr;
  QPushButton *removeBtn_ = nullptr;
  QPushButton *runBtn_ = nullptr;
  QPushButton *cancelBtn_ = nullptr;
  QPushButton *exportBtn_ = nullptr;
  QTableWidget *queueTable_ = nullptr;
  QTableWidget *resultTable_ = nullptr;
  QProgressBar *bar_ = nullptr;
  QLabel *phaseLabel_ = nullptr;
  QLabel *statusLabel_ = nullptr;
  QPlainTextEdit *log_ = nullptr;

  QVector<SchemeRow> schemes_;
  QVector<QueueItem> queue_;
  QVector<RunResult> results_;

  QProcess *proc_ = nullptr;
  QString stdoutBuf_;
  QString stderrBuf_;
  bool running_ = false;
  bool cancel_ = false;
  int queueIndex_ = -1;
  int step_ = 0; // 0 keygen, 1 sign, 2 verify
  RunResult current_;
  QString lastStdout_;
};
