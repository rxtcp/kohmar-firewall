#ifndef ANOMALYREADER_H
#define ANOMALYREADER_H

#include <QDebug>
#include <QListWidget>
#include <QTableWidget>
#include <QThread>
#include <QTime>

#include "anomaly_frame.h"
#include "engine/packsreceiver.h"
#include "engine/structs.h"
#include "kernel_client/netlinkmanager.h"
#include "platform/threading/UnixSemaphore.h"

class AnomalyReaderTcp : public QThread {
  Q_OBJECT

 public:
  explicit AnomalyReaderTcp(QObject *parent, QTableWidget *anomaliesTable,
                            QTableWidget *rulesTable, PacksReceiver *receiver,
                            AnomalyTcpFrame *painter, QList<Rule *> *rules,
                            NetLinkManager &netlinkManager, int *limitTcp,
                            UnixSemaphore *dynamicRulesSemaphore,
                            bool *generateRules,
                            UnixSemaphore *settingsSemaphore, int *tcpDropPorts,
                            int *dynamicRuleId);

  void run();

 private:
  QListWidget *alist;
  QTableWidget *anomalies_table;
  QTableWidget *rules_table;
  PacksReceiver *receiver;
  AnomalyTcpFrame *painter;
  QList<Rule *> *rules;
  NetLinkManager &netlinkManager;
  int *limit_tcp;
  bool *gen_rules;
  int *tcp_drop_ports;

  int *id_rule;
  int __id;
  int col_rules;
  int col_anomalies;

  UnixSemaphore *sem_rules;
  UnixSemaphore *sem_settings;

  QString getStrIp(unsigned int ip);

  bool isIpFromLAN(unsigned int ip);

  bool isRuleExist(Rule *rule_to_check);

 signals:

 public slots:
};

#endif  // ANOMALYREADER_H
