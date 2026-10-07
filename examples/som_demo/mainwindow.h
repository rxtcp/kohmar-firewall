#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QCloseEvent>
#include <QMainWindow>
#include <QMessageBox>
#include <QSystemTrayIcon>
#include <filesystem>

#include "detectors/som/samplesom.h"
#include "detectors/som/selforganizedmap.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow {
  Q_OBJECT

 public:
  explicit MainWindow(std::filesystem::path dataDirectory,
                      QWidget* parent = nullptr);

  ~MainWindow() override;

 private slots:
  void on_pushButton_clicked();
  void on_table_cellClicked(int row, int column);
  void on_pushButton_2_clicked();
  void on_table_cellActivated(int row, int column);

 private:
  void loadToRecognizeVector();

  Ui::MainWindow* ui;
  std::filesystem::path dataDirectory_;

  QList<SampleSom*> list;
  SelfOrganizedMap* som = nullptr;
  SampleSom* toRecognize = nullptr;

  int N;
  int M;
  int dimension;
  int Iters;
  double Radius;
  double G;
  double lambda;
  double eta;
};

#endif  // MAINWINDOW_H
