#include "mainwindow.h"

#include <QBrush>
#include <utility>

#include "detectors/som/samplesom.h"
#include "detectors/som/selforganizedmap.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(std::filesystem::path dataDirectory, QWidget *parent)
    : QMainWindow(parent),
      ui(new Ui::MainWindow),
      dataDirectory_(std::move(dataDirectory)) {
  ui->setupUi(this);

  /*createActions();
createTrayIcon();

connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
        this, SLOT(iconActivated(QSystemTrayIcon::ActivationReason)));

trayIcon->show();*/

  N = 15, M = 15;
  Iters = 150;
  Radius = 4;
  G = 5;
  lambda = 15;
  eta = 0.1;

  for (int i = 0; i < N; i++) {
    ui->table->insertRow(i);
    ui->table->setRowHeight(i, 30);
  }

  for (int i = 0; i < M; i++) {
    ui->table->insertColumn(i);
    ui->table->setColumnWidth(i, 30);
  }
  const auto samplesPath = dataDirectory_ / "flow.samples";

  list = SampleSom::loadFromFile(QString::fromStdString(samplesPath.string()));

  if (list.isEmpty()) {
    qCritical() << "SOM training samples were not loaded:"
                << QString::fromStdString(samplesPath.string());
    return;
  }

  dimension = list.first()->getDimension();
  loadToRecognizeVector();

  som = new SelfOrganizedMap(N, M, dimension, Iters, Radius, G, lambda, eta, 0);

  //------------------------------------------------------------------------------------------
  QTableWidgetItem *item = NULL;

  for (int i = 0; i < N; i++) {
    for (int j = 0; j < M; j++) {
      ui->listWidget->addItem(
          QString::number(som->getNeuron(i, j)->getKoeff(0)));

      item = new QTableWidgetItem();
      // item->setText("sfg");
      ui->table->setItem(i, j, item);
    }
  }
}

MainWindow::~MainWindow() {
  delete ui;
  // trayIcon->setVisible(false);
  // delete trayIcon;
}

void MainWindow::on_pushButton_clicked() {
  QString str;
  QMessageBox msgBox;
  QColor color;
  // msgBox.setText(QString::number(ui->table->rowCount()));
  // msgBox.exec();

  // QTableWidgetItem * item = new QTableWidgetItem();
  // item->setText("sfg");
  // ui->table->setItem(0,0,item);

  ui->listWidget_2->clear();

  som->learn(&list);

  for (int i = 0; i < N; i++) {
    for (int j = 0; j < M; j++) {
      str = QString::number(som->getNeuron(i, j)->getKoeff(0));
      ui->listWidget_2->addItem(
          QString::number(som->getNeuron(i, j)->getKoeff(0)));

      color.setRgbF(1.0, 0, 0, som->getNeuron(i, j)->getAnomaly() / 100);
      ui->table->item(i, j)->setBackground(QBrush{color});
    }
  }
}

void MainWindow::on_table_cellClicked(int row, int column) {
  QMessageBox msgBox;
  msgBox.setText(QString::number(som->getNeuron(row, column)->getAnomaly()));
  msgBox.exec();
}

void MainWindow::loadToRecognizeVector() {
  const auto recognizePath = dataDirectory_ / "toRecognize.dat";

  QFile file(QString::fromStdString(recognizePath.string()));

  if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
    qWarning() << "Cannot open recognition sample:" << file.fileName();
    return;
  }

  toRecognize = new SampleSom(dimension);

  QTextStream stream(&file);

  for (int i = 0; i < dimension; i++)
    toRecognize->setKoeff(i, stream.readLine().toDouble());

  file.close();
}

void MainWindow::on_pushButton_2_clicked() {
  int winner = som->recognize(toRecognize);

  int i, j;

  i = winner / N;
  j = winner - i * N;

  Neuron *res = som->getNeuron(i, j);

  ui->listWidget_3->clear();
  ui->listWidget_3->addItem("WINNER:");
  ui->listWidget_3->addItem("Anomaly = " + QString::number(res->getAnomaly()));
  ui->listWidget_3->addItem("Koeffs:");

  for (int k = 0; k < dimension; k++)
    ui->listWidget_3->addItem(QString::number(res->getKoeff(k)));

  ui->table->item(i, j)->setText("w");
}

/*void MainWindow::setVisible(bool visible)
{
    minimizeAction->setEnabled(visible);
    maximizeAction->setEnabled(!isMaximized());
    restoreAction->setEnabled(isMaximized() || !visible);
    setVisible(visible);
}*/

/*void MainWindow::closeEvent(QCloseEvent *event)
{
    if (trayIcon->isVisible()) {
        QMessageBox::information(this, tr("Systray"),
                                 tr("The program will keep running in the "
                                    "system tray. To terminate the program, "
                                    "choose <b>Quit</b> in the context menu "
                                    "of the system tray entry."));
        hide();
        event->ignore();
    }
}
*/
/*void MainWindow::iconActivated(QSystemTrayIcon::ActivationReason reason)
{
    switch (reason) {
    case QSystemTrayIcon::Trigger:
    default:
        ;
    }
}
*/
/*void MainWindow::createActions()
{
    minimizeAction = new QAction(tr("Mi&nimize"), this);
    connect(minimizeAction, SIGNAL(triggered()), this, SLOT(hide()));

    maximizeAction = new QAction(tr("Ma&ximize"), this);
    connect(maximizeAction, SIGNAL(triggered()), this, SLOT(showMaximized()));

    restoreAction = new QAction(tr("&Restore"), this);
    connect(restoreAction, SIGNAL(triggered()), this, SLOT(showNormal()));

    quitAction = new QAction(tr("&Quit"), this);
    connect(quitAction, SIGNAL(triggered()), qApp, SLOT(quit()));
}
*/
/*void MainWindow::createTrayIcon()
{
    trayIconMenu = new QMenu(this);
    trayIconMenu->addAction(minimizeAction);
    trayIconMenu->addAction(maximizeAction);
    trayIconMenu->addAction(restoreAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(quitAction);

    QIcon icon(":/icons/firewall.png");
    trayIcon = new QSystemTrayIcon(this);
    trayIcon->setIcon(icon);
    trayIcon->setContextMenu(trayIconMenu);
}
*/

void MainWindow::on_table_cellActivated(int row, int column) {}
