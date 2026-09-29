#include "main_window.h"

#include <QApplication>

int main(int argc, char *argv[]) {
  QApplication app(argc, argv);
  app.setApplicationName("HBS Bench");
  app.setOrganizationName("pqc-hbs-benchmark");

  MainWindow w;
  w.show();
  return app.exec();
}
