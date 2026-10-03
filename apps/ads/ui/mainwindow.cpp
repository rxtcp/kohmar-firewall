#include "mainwindow.h"

#include <QBrush>

#include "ui_mainwindow.h"
//

MainWindow::MainWindow(QWidget *parent, NetLinkManager &manager,
                       PacksReceiver &receiver)
    : QMainWindow(parent),
      ui(std::make_unique<Ui::MainWindow>()),
      netlinkManager(manager),
      packsReceiver(receiver) {
  qDebug() << "setup ui";
  // UI
  ui->setupUi(this);
  ui->tableWidgetGenRules->setColumnWidth(3, 115);
  ui->tableWidgetGenRules->setColumnWidth(5, 115);
  ui->tableWidgetGroupRules->setColumnWidth(3, 115);
  ui->tableWidgetGroupRules->setColumnWidth(5, 115);
  ui->tableWidgetTCPDetAnom->setColumnWidth(1, 140);
  ui->tableWidgetTCPDetAnom->setColumnWidth(3, 115);
  ui->tableWidgetTCPDetAnom->setColumnWidth(5, 115);
  ui->tableWidgetTCPDetAnom->setColumnHidden(6, true);
  ui->tableWidgetTCPDetAnom->setColumnHidden(7, true);
  ui->tableWidgetFlowDetAnom->setColumnWidth(1, 140);
  ui->tableWidgetFlowDetAnom->setColumnHidden(2, true);

  // som table
  SelfOrganizedMap *som = packsReceiver.getSOM();
  QTableWidget *som_table = ui->tableWidgetSOM;
  int N = som->getN();
  int M = som->getM();
  int sz_one_n = (som_table->height() - 10) / N;
  // it should be trained until now

  for (int i = 0; i < N; i++) {
    som_table->insertRow(i);
    som_table->setRowHeight(i, sz_one_n);
  }

  som_table->setFont(QFont("Arial", 1));

  int sz_one_m = (som_table->width() - 10) / M;
  for (int i = 0; i < M; i++) {
    som_table->insertColumn(i);
    som_table->setColumnWidth(i, sz_one_m);
  }

  for (int i = 0; i < N; i++) {
    for (int j = 0; j < M; j++) {
      QTableWidgetItem *item = new QTableWidgetItem();
      som_table->setItem(i, j, item);
    }
  }

  QColor color;
  for (int i = 0; i < N; i++) {
    for (int j = 0; j < M; j++) {
      color.setRgbF(1.0, 0, 0, som->getNeuron(i, j)->getAnomaly() / 100);
      som_table->item(i, j)->setBackground(QBrush(color));
    }
  }

  run_pause = true;

  isLearnTcp = packsReceiver.getIsLearnTcp();
  tcp_depth = packsReceiver.getTcpDepth();
  tcp_anomaly_limit = packsReceiver.getTcpAnomalyLimit();
  tcp_gen_rules = packsReceiver.getTcpGenerateRules();
  tcp_drop_ports = packsReceiver.getTcpDropPorts();

  flow_packs_max_count = packsReceiver.getFlowPacksMaxCount();
  flow_min_count_packs_in_conn = packsReceiver.getFlowMinCountPacksInConn();
  flow_anomaly_limit = packsReceiver.getFlowAnomalyLimit();
  flow_gen_rules = packsReceiver.getFlowGenerateRules();
  flow_drop_ports = 0;

  // FRAMES
  tcp_anomaly_frame =
      new AnomalyTcpFrame(ui->groupBoxTCPGraph, tcp_anomaly_limit);
  tcp_anomaly_frame->setFixedWidth(ui->groupBoxTCPGraph->width() - 9);
  tcp_anomaly_frame->setFixedHeight(ui->groupBoxTCPGraph->height() - 25);
  tcp_anomaly_frame->move(5, 22);

  flow_anomaly_frame =
      new AnomalyTcpFrame(ui->groupBoxFlowGraph, flow_anomaly_limit);
  flow_anomaly_frame->setFixedWidth(ui->groupBoxFlowGraph->width() - 9);
  flow_anomaly_frame->setFixedHeight(ui->groupBoxFlowGraph->height() - 25);
  flow_anomaly_frame->move(5, 22);

  // RULES
  user_rules = nullptr;
  ads_rules = new QList<Rule *>();

  connect(ui->menu_2->actions()[0], &QAction::triggered, this,
          &MainWindow::showSettings);

  connect(ui->menu_3->actions()[0], &QAction::triggered, this,
          &MainWindow::showRulesForm);

  connect(ui->menu_4->actions()[0], &QAction::triggered, this,
          &MainWindow::learnTcp);

  connect(ui->menu_4->actions()[1], &QAction::triggered, this,
          &MainWindow::learnFlow);

  connect(ui->menu->actions()[0], &QAction::triggered, this,
          &MainWindow::showAbout);

  qDebug() << "main: nl maenagr";

  if (!netlinkManager.getDynamicRulesFromKernel(ads_rules)) {
    qWarning() << "Cannot read dynamic rules from kernel";
  }

  user_rules = DbManager::getRulesFromDb();

  if (user_rules == nullptr) {
    user_rules = new QList<Rule *>();
  }

  loadRulesToKernel();

  id_rule_dynamic = -1;

  for (const Rule *rule : *ads_rules) {
    if (rule != nullptr && rule->id_rule < 0 &&
        rule->id_rule <= id_rule_dynamic) {
      id_rule_dynamic = rule->id_rule - 1;
    }
  }

  qDebug() << "main: start readers";

  // READERS
  tcp_anomaly_reader = new AnomalyReaderTcp(
      this, ui->tableWidgetTCPDetAnom, ui->tableWidgetGenRules, &packsReceiver,
      tcp_anomaly_frame, ads_rules, netlinkManager, &tcp_anomaly_limit,
      &sem_dynamic_rules, &tcp_gen_rules, &sem_settings_tcp, &tcp_drop_ports,
      &id_rule_dynamic);

  flow_anomaly_reader = new AnomalyReaderFlow(
      this, ui->tableWidgetSOM, ui->tableWidgetFlowDetAnom,
      ui->tableWidgetGroupRules, &packsReceiver, flow_anomaly_frame, ads_rules,
      netlinkManager, &flow_anomaly_limit, &sem_dynamic_rules, &flow_gen_rules,
      &sem_settings_tcp, &flow_drop_ports, &id_rule_dynamic);

  tcp_anomaly_reader->start();
  flow_anomaly_reader->start();
}

void MainWindow::stopAnomalyReaders() noexcept {
  if (tcp_anomaly_reader != nullptr) {
    tcp_anomaly_reader->requestInterruption();
  }

  if (flow_anomaly_reader != nullptr) {
    flow_anomaly_reader->requestInterruption();
  }

  if (tcp_anomaly_reader != nullptr && tcp_anomaly_reader->isRunning()) {
    tcp_anomaly_reader->wait();
  }

  if (flow_anomaly_reader != nullptr && flow_anomaly_reader->isRunning()) {
    flow_anomaly_reader->wait();
  }
}

MainWindow::~MainWindow() {
  stopAnomalyReaders();

  if (ads_rules != nullptr) {
    for (Rule *rule : *ads_rules) {
      if (rule == nullptr) {
        continue;
      }

      if (!netlinkManager.deleteRuleFromKernel(rule)) {
        qWarning() << "Cannot remove dynamic rule from kernel:"
                   << rule->id_rule;
      }
    }

    qDeleteAll(*ads_rules);
    delete ads_rules;
    ads_rules = nullptr;
  }

  if (user_rules != nullptr) {
    qDeleteAll(*user_rules);
    delete user_rules;
    user_rules = nullptr;
  }

  // NetLinkManager принадлежит main().
  // Здесь его уничтожать или закрывать нельзя.
}

void MainWindow::showRulesForm() {
  auto *form = new RulesForm(this, user_rules, ads_rules, netlinkManager,
                             &sem_dynamic_rules);

  form->setAttribute(Qt::WA_DeleteOnClose);
  form->setWindowFlags((form->windowFlags() | Qt::CustomizeWindowHint) &
                       ~Qt::WindowMaximizeButtonHint);
  form->setFixedSize(form->size());
  form->show();
}

void MainWindow::loadRulesToKernel() {
  for (Rule *rule : *user_rules) {
    if (rule == nullptr) {
      continue;
    }

    if (!netlinkManager.sendRuleToKernel(rule)) {
      qWarning() << "Cannot load rule into kernel:" << rule->id_rule;
    }
  }
}

void MainWindow::learnTcp() {
  LearningTcpDialog form(this, &packsReceiver);

  form.setWindowFlags((form.windowFlags() | Qt::CustomizeWindowHint) &
                      ~Qt::WindowMaximizeButtonHint &
                      ~Qt::WindowCloseButtonHint);
  form.setFixedSize(form.size());
  form.exec();
}

void MainWindow::learnFlow() {
  LearningFlowDialog form(this, &packsReceiver);

  form.setWindowFlags((form.windowFlags() | Qt::CustomizeWindowHint) &
                      ~Qt::WindowMaximizeButtonHint &
                      ~Qt::WindowCloseButtonHint);
  form.setFixedSize(form.size());
  form.exec();
}

void MainWindow::showSettings() {
  AdsSettingsDialog *form = new AdsSettingsDialog(
      0, &sem_settings_tcp, &tcp_depth, &tcp_anomaly_limit, &tcp_gen_rules,
      &tcp_drop_ports, &flow_anomaly_limit, &flow_gen_rules,
      &flow_packs_max_count);

  form->setWindowFlags(((form->windowFlags() | Qt::CustomizeWindowHint) &
                        ~Qt::WindowMaximizeButtonHint));
  form->setFixedSize(form->size());

  if (form->exec()) {
    tcp_anomaly_frame->setLimit(tcp_anomaly_limit);
    flow_anomaly_frame->setLimit(flow_anomaly_limit);
    packsReceiver.setFlowPacksMaxCount(flow_packs_max_count);

    FILE *file = fopen("ads.settings", "w");

    if (file) {
      char str1[10];
      char str2[10];

      if (tcp_gen_rules)
        strcpy(str1, "true");
      else
        strcpy(str1, "false");

      if (flow_gen_rules)
        strcpy(str2, "true");
      else
        strcpy(str2, "false");

      fprintf(file, "tcp_anomaly_depth=%d\n", tcp_depth);
      fprintf(file, "tcp_anomaly_limit=%d\n", tcp_anomaly_limit);
      fprintf(file, "tcp_generate_rules=%s\n", str1);
      fprintf(file, "tcp_drop_ports=%d\n", tcp_drop_ports);
      fprintf(file, "flow_packs_max_count=%d\n", flow_packs_max_count);
      fprintf(file, "flow_min_count_packs_in_conn=%d\n",
              flow_min_count_packs_in_conn);
      fprintf(file, "flow_anomaly_limit=%d\n", flow_anomaly_limit);
      fprintf(file, "flow_generate_rules=%s\n", str2);
    }
  }
}

void MainWindow::run_pause_firewall() {
  if (run_pause) {
    if (netlinkManager.sendCommand(FW_COMMAND_PAUSE)) {
      run_pause = false;
      ui->run_stop_action->setText("Continue");
    }
  } else {
    if (netlinkManager.sendCommand(FW_COMMAND_START)) {
      run_pause = true;
      ui->run_stop_action->setText("Pause");
    }
  }
}

void MainWindow::showAbout() {
  QMessageBox msgBox;
  msgBox.setText(
      "ADS for network traffic\nDevelopers: \n"
      "Chudov Roman (ui, detectors, thesis)\nStaroletov Sergey (system "
      "part, ideas, fixes)\n2013, 2015, 2021\nBarnaul");
  msgBox.exec();
}

void MainWindow::on_pushButtonFalseAlarm_clicked() {
  int cur_row = ui->tableWidgetTCPDetAnom->currentRow();
  if (cur_row >= 0) {
    char *states =
        ui->tableWidgetTCPDetAnom->item(cur_row, 6)->text().toUtf8().data();
    int predictor = ui->tableWidgetTCPDetAnom->item(cur_row, 7)->text().toInt();
    packsReceiver.retrainPredictor(states, predictor);
    ui->tableWidgetTCPDetAnom->removeRow(cur_row);
  }
}

void MainWindow::on_pushButtonFalseAlarmFlow_clicked() {
  int cur_row = ui->tableWidgetFlowDetAnom->currentRow();
  if (cur_row >= 0) {
    int numAnomaly =
        ui->tableWidgetFlowDetAnom->item(cur_row, 2)->text().toInt();
    SampleSom *smp = flow_anomaly_reader->getSample(numAnomaly);
    // packs_receiver->retrainSom(flow_anomaly_reader->getSample(numAnomaly));
    FILE *file = fopen("data/samples/ads/flow.samples", "a");

    if (!file) {
      QMessageBox msgBox;
      msgBox.setText("Unable to open a file for saving!");
      msgBox.exec();
      return;
    }

    fprintf(file, "%f\n", smp->getAnomaly());

    for (int i = 0; i < 8; i++) {
      fprintf(file, "%f\n", smp->getKoeff(i));
    }

    fprintf(file, "\n");

    fclose(file);
    ui->tableWidgetFlowDetAnom->removeRow(cur_row);
  }
}

void MainWindow::on_tableWidgetSOM_cellClicked(int row, int column) {
  QMessageBox msgBox;

  QString txt;

  Neuron *n = packsReceiver.getSOM()->getNeuron(row, column);

  txt = "Anomaly : " + QString::number(n->getAnomaly()) + "\n\n";
  txt += "Vector blurred: \n";
  int max = n->getDimension();
  for (int i = 0; i < max; i++) {
    double k = n->getKoeff(i);
    if (k < 10e-3) k = 0;
    txt += QString::number(k, 'g', 3) + "\n";
  }

  msgBox.setText(txt);
  msgBox.exec();
}
