#include "rulesform.h"

#include "ui_rulesform.h"

RulesForm::RulesForm(QWidget *parent, QList<Rule *> *userRules,
                     QList<Rule *> *dynamicRules, NetLinkManager &manager,
                     UnixSemaphore *dynamicRulesSemaphore)
    : QWidget(parent),
      ui(new Ui::RulesForm),
      user_rules(userRules),
      dynamic_rules(dynamicRules),
      netlinkManager(manager),
      sem_dyn_rules(dynamicRulesSemaphore) {
  ui->setupUi(this);
  ui->tableWidget->setColumnWidth(2, 140);
  ui->tableWidget->setColumnWidth(3, 120);
  ui->tableWidget->setColumnWidth(4, 140);
  ui->tableWidget->setColumnWidth(5, 120);
  ui->tableWidget->setColumnWidth(8, 145);
  ui->tableWidget->setColumnWidth(9, 145);
  ui->tableWidget_2->setColumnWidth(3, 120);
  ui->tableWidget_2->setColumnWidth(5, 120);
  ui->tableWidget_2->setColumnWidth(8, 145);
  ui->tableWidget_2->setColumnWidth(9, 145);
  ui->tableWidget->setColumnHidden(0, true);
  // ui->tableWidget_2->setColumnHidden(0, true);

  fillUserGrid();
  fillDynamicGrid();
}

RulesForm::~RulesForm() { delete ui; }

void RulesForm::fillUserGrid() {
  QTableWidgetItem *idItem, *inOutItem, *ipSrcItem, *portSrcItem, *ipDestItem,
      *portDestItem, *protoItem, *actItem, *hostNameSrc, *hostNameDest;
  int count = 0;
  Rule *r;

  foreach (r, *user_rules) {
    idItem = new QTableWidgetItem();
    inOutItem = new QTableWidgetItem();
    ipSrcItem = new QTableWidgetItem();
    portSrcItem = new QTableWidgetItem();
    ipDestItem = new QTableWidgetItem();
    portDestItem = new QTableWidgetItem();
    protoItem = new QTableWidgetItem();
    actItem = new QTableWidgetItem();
    hostNameSrc = new QTableWidgetItem();
    hostNameDest = new QTableWidgetItem();

    idItem->setText(QString::number(r->id_rule));

    if (r->in_out == 1)
      inOutItem->setText("Input");
    else
      inOutItem->setText("Output");

    if (r->ip_src == "-")
      ipSrcItem->setText("Any");
    else
      ipSrcItem->setText(r->ip_src);

    if (r->port_src == -1)
      portSrcItem->setText("Any");
    else
      portSrcItem->setText(QString::number(r->port_src));

    if (r->ip_dest == "-")
      ipDestItem->setText("Any");
    else
      ipDestItem->setText(r->ip_dest);

    if (r->port_dest == -1)
      portDestItem->setText("Any");
    else
      portDestItem->setText(QString::number(r->port_dest));

    switch (r->proto) {
      case 0: {
        protoItem->setText("Any");
      } break;
      case 1: {
        protoItem->setText("TCP");
      } break;
      case 2: {
        protoItem->setText("UDP");
      } break;
      case 3: {
        protoItem->setText("ICMP");
      } break;
      default:
        break;
    }

    if (r->action == 0)
      actItem->setText("Deny");
    else
      actItem->setText("Accept");

    hostNameSrc->setText(r->host_name_src);
    hostNameDest->setText(r->host_name_dest);

    ui->tableWidget->insertRow(count);
    ui->tableWidget->setItem(count, 0, idItem);
    ui->tableWidget->setItem(count, 1, inOutItem);
    ui->tableWidget->setItem(count, 2, ipSrcItem);
    ui->tableWidget->setItem(count, 3, portSrcItem);
    ui->tableWidget->setItem(count, 4, ipDestItem);
    ui->tableWidget->setItem(count, 5, portDestItem);
    ui->tableWidget->setItem(count, 6, protoItem);
    ui->tableWidget->setItem(count, 7, actItem);
    ui->tableWidget->setItem(count, 8, hostNameSrc);
    ui->tableWidget->setItem(count, 9, hostNameDest);
  }
}

void RulesForm::fillDynamicGrid() {
  QTableWidgetItem *idItem, *inOutItem, *ipSrcItem, *portSrcItem, *ipDestItem,
      *portDestItem, *protoItem, *actItem, *hostNameSrc, *hostNameDest;
  int count = 0;
  Rule *r;

  sem_dyn_rules->wait();

  foreach (r, *dynamic_rules) {
    idItem = new QTableWidgetItem();
    inOutItem = new QTableWidgetItem();
    ipSrcItem = new QTableWidgetItem();
    portSrcItem = new QTableWidgetItem();
    ipDestItem = new QTableWidgetItem();
    portDestItem = new QTableWidgetItem();
    protoItem = new QTableWidgetItem();
    actItem = new QTableWidgetItem();
    hostNameSrc = new QTableWidgetItem();
    hostNameDest = new QTableWidgetItem();

    idItem->setText(QString::number(-1 * (r->id_rule)));

    if (r->in_out == 1)
      inOutItem->setText("Input");
    else
      inOutItem->setText("Output");

    if (r->ip_src == "-")
      ipSrcItem->setText("Any");
    else
      ipSrcItem->setText(r->ip_src);

    if (r->port_src == -1)
      portSrcItem->setText("Any");
    else
      portSrcItem->setText(QString::number(r->port_src));

    if (r->ip_dest == "-")
      ipDestItem->setText("Any");
    else
      ipDestItem->setText(r->ip_dest);

    if (r->port_dest == -1)
      portDestItem->setText("Any");
    else
      portDestItem->setText(QString::number(r->port_dest));

    switch (r->proto) {
      case 0: {
        protoItem->setText("Any");
      } break;
      case 1: {
        protoItem->setText("TCP");
      } break;
      case 2: {
        protoItem->setText("UDP");
      } break;
      case 3: {
        protoItem->setText("ICMP");
      } break;
      default:
        break;
    }

    if (r->action == 0)
      actItem->setText("Deny");
    else
      actItem->setText("Accept");

    hostNameSrc->setText(r->host_name_src);
    hostNameDest->setText(r->host_name_dest);

    ui->tableWidget_2->insertRow(count);
    ui->tableWidget_2->setItem(count, 0, idItem);
    ui->tableWidget_2->setItem(count, 1, inOutItem);
    ui->tableWidget_2->setItem(count, 2, ipSrcItem);
    ui->tableWidget_2->setItem(count, 3, portSrcItem);
    ui->tableWidget_2->setItem(count, 4, ipDestItem);
    ui->tableWidget_2->setItem(count, 5, portDestItem);
    ui->tableWidget_2->setItem(count, 6, protoItem);
    ui->tableWidget_2->setItem(count, 7, actItem);
    ui->tableWidget_2->setItem(count, 8, hostNameSrc);
    ui->tableWidget_2->setItem(count, 9, hostNameDest);
  }

  sem_dyn_rules->post();
}

void RulesForm::addToGrid(Rule *r) {
  QTableWidgetItem *idItem, *inOutItem, *ipSrcItem, *portSrcItem, *ipDestItem,
      *portDestItem, *protoItem, *actItem, *hostNameSrc, *hostNameDest;
  int count = ui->tableWidget->rowCount();

  idItem = new QTableWidgetItem();
  inOutItem = new QTableWidgetItem();
  ipSrcItem = new QTableWidgetItem();
  portSrcItem = new QTableWidgetItem();
  ipDestItem = new QTableWidgetItem();
  portDestItem = new QTableWidgetItem();
  protoItem = new QTableWidgetItem();
  actItem = new QTableWidgetItem();
  hostNameSrc = new QTableWidgetItem();
  hostNameDest = new QTableWidgetItem();

  idItem->setText(QString::number(r->id_rule));

  if (r->in_out == 1)
    inOutItem->setText("Input");
  else
    inOutItem->setText("Output");

  // ipSrcItem->setText(r->ip_src);
  if (r->ip_src == "-")
    ipSrcItem->setText("Any");
  else
    ipSrcItem->setText(r->ip_src);

  if (r->port_src == -1)
    portSrcItem->setText("Any");
  else
    portSrcItem->setText(QString::number(r->port_src));

  // ipDestItem->setText(r->ip_dest);
  if (r->ip_dest == "-")
    ipDestItem->setText("Any");
  else
    ipDestItem->setText(r->ip_dest);

  if (r->port_dest == -1)
    portDestItem->setText("Any");
  else
    portDestItem->setText(QString::number(r->port_dest));

  switch (r->proto) {
    case 0: {
      protoItem->setText("Any");
    } break;
    case 1: {
      protoItem->setText("TCP");
    } break;
    case 2: {
      protoItem->setText("UDP");
    } break;
    case 3: {
      protoItem->setText("ICMP");
    } break;
    default:
      break;
  }

  if (r->action == 0)
    actItem->setText("Deny");
  else
    actItem->setText("Accept");

  hostNameSrc->setText(r->host_name_src);
  hostNameDest->setText(r->host_name_dest);

  ui->tableWidget->insertRow(count);
  ui->tableWidget->setItem(count, 0, idItem);
  ui->tableWidget->setItem(count, 1, inOutItem);
  ui->tableWidget->setItem(count, 2, ipSrcItem);
  ui->tableWidget->setItem(count, 3, portSrcItem);
  ui->tableWidget->setItem(count, 4, ipDestItem);
  ui->tableWidget->setItem(count, 5, portDestItem);
  ui->tableWidget->setItem(count, 6, protoItem);
  ui->tableWidget->setItem(count, 7, actItem);
  ui->tableWidget->setItem(count, 8, hostNameSrc);
  ui->tableWidget->setItem(count, 9, hostNameDest);
}

void RulesForm::on_pushButton_clicked() {
  QList<Rule *> newRules;

  AddRuleForm form(this, &newRules, nullptr);
  form.setWindowFlags((form.windowFlags() | Qt::CustomizeWindowHint) &
                      ~Qt::WindowMaximizeButtonHint);
  form.setFixedSize(form.size());
  form.setModal(true);

  if (form.exec() != QDialog::Accepted || !form.okay_flag) {
    qDeleteAll(newRules);
    return;
  }

  for (Rule *rule : newRules) {
    if (rule == nullptr) {
      continue;
    }

    if (isExist(rule)) {
      QMessageBox::warning(this, tr("Firewall"),
                           tr("The rule already exists."));
      delete rule;
      continue;
    }

    if (!DbManager::addToDb(rule)) {
      QMessageBox::critical(this, tr("Firewall"),
                            tr("The rule could not be added to the database."));
      delete rule;
      continue;
    }

    if (!netlinkManager.sendRuleToKernel(rule)) {
      const int ruleId = rule->id_rule;

      if (!DbManager::removeFromDb(ruleId)) {
        qCritical() << "Cannot roll back database rule:" << ruleId;
      }

      QMessageBox::critical(this, tr("Firewall"),
                            tr("The rule could not be added to the kernel."));
      delete rule;
      continue;
    }

    addToGrid(rule);
    user_rules->append(rule);
  }
}

void RulesForm::on_pushButton_2_clicked() {
  const int currentRow = ui->tableWidget->currentRow();

  if (currentRow < 0) {
    return;
  }

  QTableWidgetItem *idItem = ui->tableWidget->item(currentRow, 0);

  if (idItem == nullptr) {
    return;
  }

  const int id = idItem->text().toInt();
  Rule *ruleToEdit = nullptr;

  for (Rule *rule : *user_rules) {
    if (rule != nullptr && rule->id_rule == id) {
      ruleToEdit = rule;
      break;
    }
  }

  if (ruleToEdit == nullptr) {
    QMessageBox::warning(this, tr("Firewall"),
                         tr("The selected rule no longer exists."));
    return;
  }

  const Rule oldRule = *ruleToEdit;
  Rule editedRule = oldRule;

  AddRuleForm form(this, nullptr, &editedRule);
  form.setWindowFlags((form.windowFlags() | Qt::CustomizeWindowHint) &
                      ~Qt::WindowMaximizeButtonHint);
  form.setFixedSize(form.size());
  form.setModal(true);

  if (form.exec() != QDialog::Accepted || !form.okay_flag) {
    return;
  }

  if (isExist(&editedRule)) {
    QMessageBox::warning(this, tr("Firewall"), tr("The rule already exists."));
    return;
  }

  if (!netlinkManager.updateRuleInKernel(&editedRule)) {
    QMessageBox::critical(this, tr("Firewall"),
                          tr("The rule could not be updated in the kernel."));
    return;
  }

  if (!DbManager::updateInDb(&editedRule)) {
    if (!netlinkManager.updateRuleInKernel(&oldRule)) {
      qCritical() << "Cannot roll back kernel rule:" << oldRule.id_rule;
    }

    QMessageBox::critical(this, tr("Firewall"),
                          tr("The rule could not be updated in the database."));
    return;
  }

  *ruleToEdit = std::move(editedRule);
  updateInGrid(currentRow, ruleToEdit);
}

void RulesForm::on_pushButton_3_clicked() {
  const int currentRow = ui->tableWidget->currentRow();

  if (currentRow < 0) {
    return;
  }

  const auto answer = QMessageBox::question(
      this, tr("Firewall"),
      tr("Are you sure you want to delete rule #%1?").arg(currentRow + 1),
      QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Cancel);

  if (answer != QMessageBox::Ok) {
    return;
  }

  QTableWidgetItem *idItem = ui->tableWidget->item(currentRow, 0);

  if (idItem == nullptr) {
    return;
  }

  const int id = idItem->text().toInt();
  Rule *ruleToDelete = nullptr;

  for (Rule *rule : *user_rules) {
    if (rule != nullptr && rule->id_rule == id) {
      ruleToDelete = rule;
      break;
    }
  }

  if (ruleToDelete == nullptr) {
    QMessageBox::warning(this, tr("Firewall"),
                         tr("The selected rule no longer exists."));
    return;
  }

  if (!netlinkManager.deleteRuleFromKernel(ruleToDelete)) {
    QMessageBox::critical(this, tr("Firewall"),
                          tr("The rule could not be deleted from the kernel."));
    return;
  }

  if (!DbManager::removeFromDb(ruleToDelete->id_rule)) {
    if (!netlinkManager.sendRuleToKernel(ruleToDelete)) {
      qCritical() << "Cannot restore kernel rule:" << ruleToDelete->id_rule;
    }

    QMessageBox::critical(
        this, tr("Firewall"),
        tr("The rule could not be deleted from the database."));
    return;
  }

  ui->tableWidget->removeRow(currentRow);
  user_rules->removeOne(ruleToDelete);
  delete ruleToDelete;
}

void RulesForm::updateInGrid(int row, Rule *r) {
  if (r->ip_dest == "-")
    ui->tableWidget->item(row, 4)->setText("Any");
  else
    ui->tableWidget->item(row, 4)->setText(r->ip_dest);

  if (r->ip_src == "-")
    ui->tableWidget->item(row, 2)->setText("Any");
  else
    ui->tableWidget->item(row, 2)->setText(r->ip_src);

  ui->tableWidget->item(row, 8)->setText(r->host_name_src);
  ui->tableWidget->item(row, 9)->setText(r->host_name_dest);
  // ui->tableWidget->item(row, 1)->setText(QString::number(r->in_out));
  // ui->tableWidget->item(row, 3)->setText(QString::number(r->port_src));
  // ui->tableWidget->item(row, 5)->setText(QString::number(r->port_dest));
  // ui->tableWidget->item(row, 6)->setText(QString::number(r->proto));
  // ui->tableWidget->item(row, 7)->setText(QString::number(r->action));

  if (r->in_out == 1)
    ui->tableWidget->item(row, 1)->setText("Input");
  else
    ui->tableWidget->item(row, 1)->setText("Output");

  if (r->port_src == -1)
    ui->tableWidget->item(row, 3)->setText("Any");
  else
    ui->tableWidget->item(row, 3)->setText(QString::number(r->port_src));

  if (r->port_dest == -1)
    ui->tableWidget->item(row, 5)->setText("Any");
  else
    ui->tableWidget->item(row, 5)->setText(QString::number(r->port_dest));

  switch (r->proto) {
    case 0: {
      ui->tableWidget->item(row, 6)->setText("Any");
    } break;
    case 1: {
      ui->tableWidget->item(row, 6)->setText("TCP");
    } break;
    case 2: {
      ui->tableWidget->item(row, 6)->setText("UDP");
    } break;
    case 3: {
      ui->tableWidget->item(row, 6)->setText("ICMP");
    } break;
    default:
      break;
  }

  if (r->action == 0)
    ui->tableWidget->item(row, 7)->setText("Deny");
  else
    ui->tableWidget->item(row, 7)->setText("Accept");
}

bool RulesForm::isExist(const Rule *toCheck) {
  if (toCheck == nullptr) {
    return false;
  }

  for (const Rule *rule : *user_rules) {
    if (rule == nullptr || rule->id_rule == toCheck->id_rule) {
      continue;
    }

    if (rule->action == toCheck->action && rule->in_out == toCheck->in_out &&
        rule->ip_dest == toCheck->ip_dest && rule->ip_src == toCheck->ip_src &&
        rule->port_dest == toCheck->port_dest &&
        rule->port_src == toCheck->port_src && rule->proto == toCheck->proto) {
      return true;
    }
  }

  return false;
}

void RulesForm::on_pushButton_5_clicked() {}

void RulesForm::on_pushButton_6_clicked() {
  const int currentRow = ui->tableWidget_2->currentRow();

  if (currentRow < 0) {
    return;
  }

  const auto answer = QMessageBox::question(
      this, tr("Firewall"),
      tr("Are you sure you want to delete dynamic rule #%1?")
          .arg(currentRow + 1),
      QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Cancel);

  if (answer != QMessageBox::Ok) {
    return;
  }

  QTableWidgetItem *idItem = ui->tableWidget_2->item(currentRow, 0);

  if (idItem == nullptr) {
    return;
  }

  const int id = -idItem->text().toInt();
  Rule *ruleToDelete = nullptr;

  sem_dyn_rules->wait();

  for (Rule *rule : *dynamic_rules) {
    if (rule != nullptr && rule->id_rule == id) {
      ruleToDelete = rule;
      break;
    }
  }

  sem_dyn_rules->post();

  if (ruleToDelete == nullptr) {
    QMessageBox::warning(this, tr("Firewall"),
                         tr("The selected dynamic rule no longer exists."));
    return;
  }

  if (!netlinkManager.deleteRuleFromKernel(ruleToDelete)) {
    QMessageBox::critical(
        this, tr("Firewall"),
        tr("The dynamic rule could not be deleted from the kernel."));
    return;
  }

  sem_dyn_rules->wait();
  const bool removed = dynamic_rules->removeOne(ruleToDelete);
  sem_dyn_rules->post();

  if (!removed) {
    qWarning() << "Dynamic rule disappeared from the userspace list:"
               << ruleToDelete->id_rule;
    return;
  }

  ui->tableWidget_2->removeRow(currentRow);
  delete ruleToDelete;
}
