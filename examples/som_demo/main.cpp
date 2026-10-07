#include <QApplication>
#include <cstdlib>
#include <filesystem>
#include <iostream>

#include "mainwindow.h"

int main(int argc, char* argv[]) {
  QApplication application(argc, argv);

  if (argc != 2) {
    std::cerr << "Usage: som_demo <data-directory>\n";
    return EXIT_FAILURE;
  }

  MainWindow window{std::filesystem::path{argv[1]}};

  window.show();

  return application.exec();
}