#include "main_window.h"

#include <QComboBox>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QListWidget>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QSpinBox>
#include <QSplitter>
#include <QTableWidget>
#include <QVBoxLayout>

static QStringList splitCsv(const QString &line) {
  return line.trimmed().split(',');
}

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
  setWindowTitle("HBS Bench");
  resize(1100, 720);
  buildUi();
  loadSchemes();
}

void MainWindow::buildUi() {
  auto *central = new QWidget(this);
  setCentralWidget(central);
  auto *root = new QVBoxLayout(central);
  root->setContentsMargins(12, 12, 12, 12);
  root->setSpacing(10);

  auto *split = new QSplitter(Qt::Horizontal, central);

  auto *left = new QWidget;
  auto *leftLay = new QVBoxLayout(left);
  leftLay->setContentsMargins(0, 0, 0, 0);

  auto *catalog = new QGroupBox("Catalog", left);
  auto *catLay = new QFormLayout(catalog);

  typeBox_ = new QComboBox(catalog);
  typeBox_->addItem("Custom (libhbs)", "custom");
  typeBox_->addItem("OQS stateless", "oqs_stateless");
  typeBox_->addItem("OQS stateful", "oqs_stateful");
  connect(typeBox_, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
          &MainWindow::onTypeChanged);

  schemeList_ = new QListWidget(catalog);
  schemeList_->setMinimumHeight(180);

  itersBox_ = new QSpinBox(catalog);
  itersBox_->setRange(1, 100000);
  itersBox_->setValue(8);

  addBtn_ = new QPushButton("Add to queue", catalog);
  connect(addBtn_, &QPushButton::clicked, this, &MainWindow::addToQueue);

  catLay->addRow("Type", typeBox_);
  catLay->addRow("Scheme", schemeList_);
  catLay->addRow("Iterations", itersBox_);
  catLay->addRow(addBtn_);
  leftLay->addWidget(catalog);

  statusLabel_ = new QLabel(left);
  statusLabel_->setWordWrap(true);
  leftLay->addWidget(statusLabel_);
  leftLay->addStretch(1);

  auto *right = new QWidget;
  auto *rightLay = new QVBoxLayout(right);
  rightLay->setContentsMargins(0, 0, 0, 0);

  auto *queueBox = new QGroupBox("Queue", right);
  auto *qLay = new QVBoxLayout(queueBox);
  queueTable_ = new QTableWidget(0, 3, queueBox);
  queueTable_->setHorizontalHeaderLabels({"Scheme", "Type", "Iters"});
  queueTable_->horizontalHeader()->setStretchLastSection(true);
  queueTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
  queueTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  qLay->addWidget(queueTable_);
  auto *qBtns = new QHBoxLayout;
  removeBtn_ = new QPushButton("Remove", queueBox);
  runBtn_ = new QPushButton("Run queue", queueBox);
  cancelBtn_ = new QPushButton("Cancel", queueBox);
  cancelBtn_->setEnabled(false);
  connect(removeBtn_, &QPushButton::clicked, this,
          &MainWindow::removeSelectedQueue);
  connect(runBtn_, &QPushButton::clicked, this, &MainWindow::runQueue);
  connect(cancelBtn_, &QPushButton::clicked, this, &MainWindow::cancelRun);
  qBtns->addWidget(removeBtn_);
  qBtns->addStretch(1);
  qBtns->addWidget(cancelBtn_);
  qBtns->addWidget(runBtn_);
  qLay->addLayout(qBtns);
  rightLay->addWidget(queueBox);

  auto *live = new QGroupBox("Live", right);
  auto *liveLay = new QVBoxLayout(live);
  phaseLabel_ = new QLabel("Idle", live);
  bar_ = new QProgressBar(live);
  bar_->setRange(0, 1);
  bar_->setValue(0);
  bar_->setFormat("%v / %m");
  bar_->setTextVisible(true);
  liveLay->addWidget(phaseLabel_);
  liveLay->addWidget(bar_);
  rightLay->addWidget(live);

  auto *resBox = new QGroupBox("Results", right);
  auto *rLay = new QVBoxLayout(resBox);
  resultTable_ = new QTableWidget(0, 10, resBox);
  resultTable_->setHorizontalHeaderLabels(
      {"Algorithm", "Status", "PK", "SK", "Sig", "Keygen us", "Sign us",
       "Verify us", "Keygen KB", "Sign KB"});
  resultTable_->horizontalHeader()->setStretchLastSection(true);
  resultTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  rLay->addWidget(resultTable_);
  exportBtn_ = new QPushButton("Export CSV", resBox);
  connect(exportBtn_, &QPushButton::clicked, this, &MainWindow::exportCsv);
  rLay->addWidget(exportBtn_, 0, Qt::AlignRight);
  rightLay->addWidget(resBox, 1);

  split->addWidget(left);
  split->addWidget(right);
  split->setStretchFactor(0, 0);
  split->setStretchFactor(1, 1);
  split->setSizes({320, 760});
  root->addWidget(split, 1);

  log_ = new QPlainTextEdit(central);
  log_->setReadOnly(true);
  log_->setMaximumHeight(120);
  log_->setPlaceholderText("Log");
  root->addWidget(log_);

  proc_ = new QProcess(this);
  proc_->setProcessChannelMode(QProcess::SeparateChannels);
  proc_->setWorkingDirectory(QDir::currentPath());
  connect(proc_, &QProcess::readyReadStandardOutput, this,
          &MainWindow::onWorkerStdout);
  connect(proc_, &QProcess::readyReadStandardError, this,
          &MainWindow::onWorkerStderr);
  connect(proc_, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
          this, &MainWindow::onWorkerFinished);
}

QString MainWindow::workerPath() const {
  const QString name =
#ifdef Q_OS_WIN
      "benchmark.exe";
#else
      "benchmark";
#endif
  const QDir appDir(QCoreApplication::applicationDirPath());
  if (appDir.exists(name))
    return appDir.filePath(name);
  if (QFileInfo::exists(name))
    return QFileInfo(name).absoluteFilePath();
  return name;
}

int MainWindow::typeCode(const QString &type) const {
  if (type == "oqs_stateless")
    return 0;
  if (type == "oqs_stateful")
    return 1;
  return 2;
}

void MainWindow::logLine(const QString &line) { log_->appendPlainText(line); }

void MainWindow::loadSchemes() {
  schemes_.clear();
  const QString path = workerPath();
  QProcess list;
  list.setProcessChannelMode(QProcess::SeparateChannels);
  list.start(path, QStringList() << "--list");
  if (!list.waitForStarted(3000)) {
    statusLabel_->setText(
        "Worker not found. Build `benchmark` and keep it next to this app.");
    logLine("Could not start " + path);
    refillSchemeList();
    return;
  }
  if (!list.waitForFinished(15000)) {
    list.kill();
    statusLabel_->setText("Worker --list timed out.");
    refillSchemeList();
    return;
  }
  const QString out = QString::fromUtf8(list.readAllStandardOutput());
  const QString err = QString::fromUtf8(list.readAllStandardError());
  if (!err.trimmed().isEmpty())
    logLine(err.trimmed());

  const QStringList lines = out.split('\n');
  for (int i = 1; i < lines.size(); ++i) {
    const QString line = lines[i].trimmed();
    if (line.isEmpty())
      continue;
    const QStringList c = splitCsv(line);
    if (c.size() < 7)
      continue;
    SchemeRow s;
    s.name = c[0];
    s.type = c[1];
    s.family = c[2];
    s.stateful = c[3] == "1";
    s.workerType = typeCode(s.type);
    s.pk = c[4].toLongLong();
    s.sk = c[5].toLongLong();
    s.sig = c[6].toLongLong();
    schemes_.push_back(s);
  }
  statusLabel_->setText(
      QString("%1 scheme(s) discovered from worker.").arg(schemes_.size()));
  refillSchemeList();
}

void MainWindow::refillSchemeList() {
  schemeList_->clear();
  const QString want = typeBox_->currentData().toString();
  int n = 0;
  for (const auto &s : schemes_) {
    if (s.type != want)
      continue;
    auto *item = new QListWidgetItem(s.name, schemeList_);
    QString tip = QString("%1  pk=%2  sk=%3  sig=%4")
                      .arg(s.family)
                      .arg(s.pk)
                      .arg(s.sk)
                      .arg(s.sig);
    if (s.stateful)
      tip += "  (stateful: one-time keys, keep iterations below remaining "
             "signatures)";
    item->setToolTip(tip);
    ++n;
  }
  if (n == 0) {
    if (want.startsWith("oqs"))
      schemeList_->addItem("(none — liboqs was not linked in this build)");
    else
      schemeList_->addItem("(none — libhbs was not linked in this build)");
    schemeList_->item(0)->setFlags(Qt::NoItemFlags);
  }
}

void MainWindow::onTypeChanged() {
  refillSchemeList();
  const QString want = typeBox_->currentData().toString();
  if (want == "oqs_stateful")
    itersBox_->setValue(qMin(itersBox_->value(), 16));
}

void MainWindow::addToQueue() {
  auto *item = schemeList_->currentItem();
  if (!item || !(item->flags() & Qt::ItemIsEnabled))
    return;
  const QString name = item->text();
  for (const auto &s : schemes_) {
    if (s.name != name)
      continue;
    QueueItem q;
    q.scheme = s;
    q.iterations = itersBox_->value();
    if (s.stateful && q.iterations > 16) {
      QMessageBox::warning(
          this, "Stateful scheme",
          "This scheme consumes one-time keys. Iterations were capped at 16.");
      q.iterations = 16;
    }
    queue_.push_back(q);
    const int row = queueTable_->rowCount();
    queueTable_->insertRow(row);
    queueTable_->setItem(row, 0, new QTableWidgetItem(s.name));
    queueTable_->setItem(row, 1, new QTableWidgetItem(s.type));
    queueTable_->setItem(row, 2,
                         new QTableWidgetItem(QString::number(q.iterations)));
    return;
  }
}

void MainWindow::removeSelectedQueue() {
  const int row = queueTable_->currentRow();
  if (row < 0 || row >= queue_.size())
    return;
  queue_.erase(queue_.begin() + row);
  queueTable_->removeRow(row);
}

void MainWindow::setBusy(bool busy) {
  running_ = busy;
  addBtn_->setEnabled(!busy);
  removeBtn_->setEnabled(!busy);
  runBtn_->setEnabled(!busy);
  typeBox_->setEnabled(!busy);
  schemeList_->setEnabled(!busy);
  itersBox_->setEnabled(!busy);
  cancelBtn_->setEnabled(busy);
}

void MainWindow::runQueue() {
  if (queue_.isEmpty()) {
    QMessageBox::information(this, "Queue", "Add at least one scheme.");
    return;
  }
  cancel_ = false;
  queueIndex_ = 0;
  results_.clear();
  resultTable_->setRowCount(0);
  setBusy(true);
  runNext();
}

void MainWindow::cancelRun() {
  cancel_ = true;
  if (proc_->state() != QProcess::NotRunning)
    proc_->kill();
}

void MainWindow::runNext() {
  if (cancel_ || queueIndex_ >= queue_.size()) {
    setBusy(false);
    phaseLabel_->setText(cancel_ ? "Cancelled" : "Done");
    bar_->setRange(0, 1);
    bar_->setValue(1);
    return;
  }
  const QueueItem &q = queue_[queueIndex_];
  current_ = RunResult();
  current_.name = q.scheme.name;
  current_.status = "running";
  current_.pk = QString::number(q.scheme.pk);
  current_.sk = QString::number(q.scheme.sk);
  current_.sig = QString::number(q.scheme.sig);
  step_ = 0;
  phaseLabel_->setText(QString("%1  keygen").arg(q.scheme.name));
  bar_->setRange(0, 1);
  bar_->setValue(0);
  startWorker(QStringList()
              << q.scheme.name << QString::number(q.scheme.workerType) << "0"
              << "1"
              << "1");
}

void MainWindow::startWorker(const QStringList &args) {
  stdoutBuf_.clear();
  stderrBuf_.clear();
  lastStdout_.clear();
  proc_->start(workerPath(), args);
}

void MainWindow::onWorkerStdout() {
  stdoutBuf_ += QString::fromUtf8(proc_->readAllStandardOutput());
}

void MainWindow::onWorkerStderr() {
  stderrBuf_ += QString::fromUtf8(proc_->readAllStandardError());
  int nl;
  while ((nl = stderrBuf_.indexOf('\n')) >= 0) {
    QString line = stderrBuf_.left(nl).trimmed();
    stderrBuf_ = stderrBuf_.mid(nl + 1);
    if (line.startsWith("PROGRESS ")) {
      const QStringList p = line.split(' ');
      if (p.size() >= 4) {
        const QString phase = p[1];
        const int i = p[2].toInt();
        const int n = qMax(1, p[3].toInt());
        bar_->setRange(0, n);
        bar_->setValue(i);
        phaseLabel_->setText(
            QString("%1  %2  %3 / %4").arg(current_.name, phase).arg(i).arg(n));
      }
    } else if (line.startsWith("SKIP:")) {
      logLine(line);
    } else if (!line.isEmpty()) {
      logLine(line);
    }
  }
}

void MainWindow::onWorkerFinished(int code, QProcess::ExitStatus st) {
  lastStdout_ = stdoutBuf_.trimmed();
  const bool skipped = lastStdout_.startsWith("SKIP") || code == 2;
  const bool failed = st != QProcess::NormalExit || (code != 0 && !skipped);

  auto takeCsv = [&]() { return splitCsv(lastStdout_); };

  if (step_ == 0) {
    if (skipped) {
      current_.status = "skipped";
      logLine(current_.name + " skipped");
      finishCurrentRow();
      ++queueIndex_;
      runNext();
      return;
    }
    if (failed) {
      current_.status = "keygen failed";
      logLine(current_.name + " keygen failed");
      finishCurrentRow();
      ++queueIndex_;
      runNext();
      return;
    }
    const QStringList c = takeCsv();
    if (c.size() >= 5) {
      current_.keygenUs = c[0];
      current_.keygenMem = c[1];
      current_.pk = c[2];
      current_.sk = c[3];
      current_.sig = c[4];
    }
    step_ = 1;
    const QueueItem &q = queue_[queueIndex_];
    startWorker(QStringList()
                << q.scheme.name << QString::number(q.scheme.workerType) << "1"
                << QString::number(q.iterations) << "1");
    return;
  }

  if (step_ == 1) {
    if (skipped || failed) {
      current_.status = skipped ? "sign skipped" : "sign failed";
      finishCurrentRow();
      ++queueIndex_;
      runNext();
      return;
    }
    const QStringList c = takeCsv();
    if (c.size() >= 2) {
      current_.signUs = c[0];
      current_.signMem = c[1];
    }
    step_ = 2;
    const QueueItem &q = queue_[queueIndex_];
    startWorker(QStringList()
                << q.scheme.name << QString::number(q.scheme.workerType) << "2"
                << QString::number(q.iterations) << "1");
    return;
  }

  if (skipped || failed)
    current_.status = skipped ? "verify skipped" : "verify failed";
  else {
    current_.status = "ok";
    const QStringList c = takeCsv();
    if (c.size() >= 2) {
      current_.verifyUs = c[0];
      current_.verifyMem = c[1];
    }
  }
  finishCurrentRow();
  ++queueIndex_;
  runNext();
}

void MainWindow::finishCurrentRow() {
  results_.push_back(current_);
  const int row = resultTable_->rowCount();
  resultTable_->insertRow(row);
  const QStringList cells = {
      current_.name,      current_.status,   current_.pk,     current_.sk,
      current_.sig,       current_.keygenUs, current_.signUs, current_.verifyUs,
      current_.keygenMem, current_.signMem};
  for (int i = 0; i < cells.size(); ++i)
    resultTable_->setItem(row, i, new QTableWidgetItem(cells[i]));
}

void MainWindow::exportCsv() {
  if (results_.isEmpty())
    return;
  const QString path = QFileDialog::getSaveFileName(
      this, "Export CSV", "results.csv", "CSV (*.csv)");
  if (path.isEmpty())
    return;
  QFile f(path);
  if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
    QMessageBox::warning(this, "Export", "Could not write file.");
    return;
  }
  f.write("Algorithm,Status,PK Size (B),SK Size (B),Sig Size (B),Keygen Time "
          "(us),Sign Time (us),Verify Time (us),Keygen Peak Mem (KB),Sign Peak "
          "Mem (KB)\n");
  for (const auto &r : results_) {
    const QString line =
        QStringList{r.name,     r.status, r.pk,       r.sk,        r.sig,
                    r.keygenUs, r.signUs, r.verifyUs, r.keygenMem, r.signMem}
            .join(',') +
        "\n";
    f.write(line.toUtf8());
  }
}
