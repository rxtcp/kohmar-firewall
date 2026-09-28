#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <stdio.h>
#include <string.h>

#include <QGridLayout>
#include <QMainWindow>
#include <QMessageBox>
#include <memory>

#include "anomalies/anomaly_frame.h"
#include "anomalies/anomaly_reader_flow.h"
#include "anomalies/anomaly_reader_tcp.h"
#include "engine/packsreceiver.h"
#include "engine/structs.h"
#include "kernel_client/netlinkmanager.h"
#include "learning/learning_flow_dialog.h"
#include "learning/learning_tcp_dialog.h"
#include "rules/rulesform.h"
#include "settings/ads_settings_dialog.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow {
  Q_OBJECT

 public:
  explicit MainWindow(QWidget *parent, NetLinkManager &netlinkManager,
                      PacksReceiver &packsReceiver);

  ~MainWindow() override;

 private slots:

  void showRulesForm();

  void learnTcp();

  void learnFlow();

  void showSettings();

  void run_pause_firewall();

  void showAbout();

  void on_pushButtonFalseAlarm_clicked();

  void on_pushButtonFalseAlarmFlow_clicked();

  void on_tableWidgetSOM_cellClicked(int row, int column);

 private:
  std::unique_ptr<Ui::MainWindow> ui;

  // Списки пока остаются в старом представлении,
  // потому что изменение Rule-ownership является отдельным рефакторингом.
  QList<Rule *> *user_rules = nullptr;
  QList<Rule *> *ads_rules = nullptr;

  NetLinkManager &netlinkManager;
  PacksReceiver &packsReceiver;

  void loadRulesToKernel();
  void stopAnomalyReaders() noexcept;

  bool isLearnTcp;
  bool run_pause;

  AnomalyReaderTcp *tcp_anomaly_reader = nullptr;
  AnomalyReaderFlow *flow_anomaly_reader = nullptr;

  AnomalyTcpFrame *tcp_anomaly_frame;
  AnomalyTcpFrame *flow_anomaly_frame;
  QGridLayout *tcp_layout;

  UnixSemaphore *sem_dynamic_rules;
  UnixSemaphore *sem_settings_tcp;

  int tcp_depth;
  int tcp_anomaly_limit;
  int tcp_drop_ports;
  bool tcp_gen_rules;

  int flow_packs_max_count;
  int flow_min_count_packs_in_conn;
  int flow_anomaly_limit;
  int flow_drop_ports;
  bool flow_gen_rules;

  int id_rule_dynamic;
};

#endif  // MAINWINDOW_H
