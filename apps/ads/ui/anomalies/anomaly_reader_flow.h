#ifndef ANOMALY_READER_FLOW_H
#define ANOMALY_READER_FLOW_H

#include <QDebug>
#include <QListWidget>
#include <QTableWidget>
#include <QThread>
#include <QTime>

#include "anomaly_frame.h"
#include "detectors/som/samplesom.h"
#include "engine/packsreceiver.h"
#include "engine/structs.h"
#include "kernel_client/netlinkmanager.h"
#include "platform/threading/UnixSemaphore.h"

class AnomalyReaderFlow : public QThread {
  Q_OBJECT

 public:
  explicit AnomalyReaderFlow(QObject *parent, QTableWidget *somTable,
                             QTableWidget *anomaliesTable,
                             QTableWidget *rulesTable, PacksReceiver *receiver,
                             AnomalyTcpFrame *painter, QList<Rule *> *rules,
                             NetLinkManager &netlinkManager, int *limitFlow,
                             UnixSemaphore *dynamicRulesSemaphore,
                             bool *generateRules,
                             UnixSemaphore *settingsSemaphore,
                             int *flowDropPorts, int *dynamicRuleId);

  void run();

  SampleSom *getSample(int ind);

 signals:

 public slots:

 private:
  QListWidget *alist;
  QTableWidget *rules_table;
  QTableWidget *anomalies_table;
  QTableWidget *som_table;
  PacksReceiver *receiver;
  AnomalyTcpFrame *painter;
  QList<Rule *> *rules;
  NetLinkManager &netlinkManager;
  int *limit_flow;
  bool *gen_rules;
  int *flow_drop_ports;

  int *id_rule;
  int col_rules;
  int col_anomalies;

  UnixSemaphore *sem_rules;
  UnixSemaphore *sem_settings;

  QList<SampleSom *> samples;

  QString getStrIp(unsigned int ip);

  bool isIpFromLAN(unsigned int ip);

  bool isRuleExist(Rule *rule_to_check);
};

#endif  // ANOMALY_READER_FLOW_H
