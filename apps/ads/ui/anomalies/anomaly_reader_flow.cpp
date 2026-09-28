#include "anomaly_reader_flow.h"

AnomalyReaderFlow::AnomalyReaderFlow(
    QObject *parent, QTableWidget *somTable, QTableWidget *anomaliesTable,
    QTableWidget *rulesTable, PacksReceiver *packsReceiver,
    AnomalyTcpFrame *anomalyPainter, QList<Rule *> *dynamicRules,
    NetLinkManager &manager, int *limitFlow,
    UnixSemaphore *dynamicRulesSemaphore, bool *generateRules,
    UnixSemaphore *settingsSemaphore, int *flowDropPorts, int *dynamicRuleId)
    : QThread(parent),
      rules_table(rulesTable),
      anomalies_table(anomaliesTable),
      som_table(somTable),
      receiver(packsReceiver),
      painter(anomalyPainter),
      rules(dynamicRules),
      netlinkManager(manager),
      limit_flow(limitFlow),
      gen_rules(generateRules),
      flow_drop_ports(flowDropPorts),
      id_rule(dynamicRuleId),
      col_rules(0),
      col_anomalies(0),
      sem_rules(dynamicRulesSemaphore),
      sem_settings(settingsSemaphore) {}

void AnomalyReaderFlow::run() {
  AnomalyNodeFlow anomaly_node;
  QString ip_src_str, ip_dest_str, port_src_str, port_dest_str;
  QTableWidgetItem *timeItem, *numItem, *ipSrcItem, *ipDestItem, *portSrcItem,
      *portDestItem, *valItem, *typeItem;

  int old_i = 0, old_j = 0;
  QDateTime prevTime = QDateTime::currentDateTime();

  while (!isInterruptionRequested()) {
    if (receiver->getFlowAnomalyFromQueue(&anomaly_node)) {
      if (isInterruptionRequested()) {
        break;
      }

      painter->addPoint(anomaly_node.anomaly);
      painter->paintGraphic();

      qint64 d = abs(QDateTime::currentDateTime().msecsTo(prevTime));
      if (d > 500) {
        // qDebug() << d << "\n";
        som_table->clearSelection();
        int N = som_table->columnCount();
        int winner = anomaly_node.winner;
        int wi = winner / N;
        int wj = winner - wi * N;
        QModelIndex index = som_table->model()->index(wi, wj);
        som_table->item(old_i, old_j)->setText("");

        som_table->item(wi, wj)->setText("*");
        old_i = wi;
        old_j = wj;

        som_table->selectionModel()->select(index, QItemSelectionModel::Select);
        som_table->setFocus();
        som_table->update(index);

        qDebug() << "anomaly_flow=" << QString::number(anomaly_node.anomaly)
                 << "winner = " << winner;
      }
      prevTime = QDateTime::currentDateTime();

      sem_settings->wait();

      if (anomaly_node.anomaly >= *limit_flow) {
        timeItem = new QTableWidgetItem();
        valItem = new QTableWidgetItem();
        typeItem = new QTableWidgetItem();

        timeItem->setText(QTime::currentTime().toString("hh:mm:ss"));
        valItem->setText(QString::number(anomaly_node.anomaly));

        /*if(anomaly_node.flow_icmp_count > 70)
    typeItem->setText("ICMP-flood");
else if(anomaly_node.flow_new_tcp_conn_count > 30)
    typeItem->setText("TCP-DDoS");
else typeItem->setText("Смешанный");
*/

        SampleSom *smp = new SampleSom(8);
        smp->setKoeff(0, anomaly_node.flow_size_average);
        smp->setKoeff(1, anomaly_node.flow_diff_ip_src_count);
        smp->setKoeff(2, anomaly_node.flow_icmp_count);
        smp->setKoeff(3, anomaly_node.flow_low_active_conn_count);
        smp->setKoeff(4, anomaly_node.flow_new_tcp_conn_count);
        smp->setKoeff(5, anomaly_node.flow_udp_count);
        smp->setKoeff(6, anomaly_node.flow_little_count);
        smp->setKoeff(7, anomaly_node.flow_big_count);
        smp->setAnomaly(anomaly_node.anomaly);
        samples.append(smp);

        anomalies_table->insertRow(col_anomalies);
        anomalies_table->setItem(col_anomalies, 0, timeItem);
        anomalies_table->setItem(col_anomalies, 1, valItem);
        anomalies_table->setItem(col_anomalies, 2, typeItem);
        col_anomalies++;

        if (*gen_rules) {
          Rule *rule_new = new Rule;

          rule_new->action = _DROP;
          rule_new->host_name_dest = "-";
          rule_new->host_name_src = "-";

          rule_new->in_out = 1;
          rule_new->port_dest = -1;
          rule_new->port_src = -1;
          rule_new->ip_dest = "192.168.2.1";  // TODO : get my IP
          rule_new->ip_src = "-";
          port_dest_str = "Any";
          port_src_str = "Any";

          if (anomaly_node.flow_icmp_count > 70)
            rule_new->proto = 3;
          else if (anomaly_node.flow_new_tcp_conn_count > 30)
            rule_new->proto = 1;
          else
            rule_new->proto = 0;

          sem_rules->wait();

          rule_new->id_rule = *id_rule;

          if (isRuleExist(rule_new)) {
            delete rule_new;
          } else if (!netlinkManager.sendRuleToKernel(rule_new)) {
            delete rule_new;
          } else {
            rules->append(rule_new);

            timeItem = new QTableWidgetItem();
            numItem = new QTableWidgetItem();
            ipSrcItem = new QTableWidgetItem();
            ipDestItem = new QTableWidgetItem();
            portDestItem = new QTableWidgetItem();
            portSrcItem = new QTableWidgetItem();

            timeItem->setText(QTime::currentTime().toString("hh:mm:ss"));
            numItem->setText(QString::number(-rule_new->id_rule));
            ipSrcItem->setText(rule_new->ip_src);
            ipDestItem->setText(rule_new->ip_dest);
            portDestItem->setText(port_dest_str);
            portSrcItem->setText(port_src_str);

            rules_table->insertRow(col_rules);
            rules_table->setItem(col_rules, 0, numItem);
            rules_table->setItem(col_rules, 1, timeItem);
            rules_table->setItem(col_rules, 2, ipSrcItem);
            rules_table->setItem(col_rules, 3, portSrcItem);
            rules_table->setItem(col_rules, 4, ipDestItem);
            rules_table->setItem(col_rules, 5, portDestItem);

            ++col_rules;
            --(*id_rule);
          }

          sem_rules->post();
        }
      }

      sem_settings->post();
    } else {
      // pause
      this->msleep(100);
    }
  }
}

QString AnomalyReaderFlow::getStrIp(unsigned int ip) {
  int bit1, bit2, bit3, bit4;

  bit1 = 255 & ip;
  bit2 = (0xff00 & ip) >> 8;
  bit3 = (0xff0000 & ip) >> 16;
  bit4 = (0xff000000 & ip) >> 24;

  QString res;

  res = QString::number(bit1) + "." + QString::number(bit2) + "." +
        QString::number(bit3) + "." + QString::number(bit4);

  return res;
}

bool AnomalyReaderFlow::isIpFromLAN(unsigned int ip) {
  bool res = false;

  int bit1, bit2, bit3, bit4;

  bit1 = 255 & ip;
  bit2 = (0xff00 & ip) >> 8;
  bit3 = (0xff0000 & ip) >> 16;
  bit4 = (0xff000000 & ip) >> 24;

  (void)bit3;
  (void)bit4;

  if ((bit1 == 10) || ((bit1 == 172) && ((bit2 >= 16) && (bit2 <= 31))) ||
      ((bit1 == 192) && (bit2 == 168)))
    res = true;

  return res;
}

bool AnomalyReaderFlow::isRuleExist(Rule *rule_to_check) {
  Rule *r;
  foreach (r, *rules) {
    if (r->action == rule_to_check->action &&
        r->in_out == rule_to_check->in_out &&
        r->ip_dest == rule_to_check->ip_dest &&
        r->ip_src == rule_to_check->ip_src &&
        r->port_dest == rule_to_check->port_dest &&
        r->port_src == rule_to_check->port_src)
      return true;
  }

  return false;
}

SampleSom *AnomalyReaderFlow::getSample(int ind) { return samples.at(ind); }
