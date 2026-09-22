#ifndef RULESFORM_H
#define RULESFORM_H

#include <QDebug>
#include <QWidget>
#include <QtSql>

#include "addruleform.h
#include "engine/structs.h"
#include "kernel_client/netlinkmanager.h"
#include "platform/threading/UnixSemaphore.h"
#include "storage/dbmanager.h"

namespace Ui {
class RulesForm;
}

class RulesForm : public QWidget {
  Q_OBJECT

 public:
  explicit RulesForm(QWidget *parent = 0, QList<Rule *> *_user_rules = 0,
                     QList<Rule *> *_dyn_rules = 0, NetLinkManager *mng = 0,
                     UnixSemaphore *_sem_dyn_rules = 0);

  ~RulesForm();

 private slots:

  void on_pushButton_clicked();

  void on_pushButton_2_clicked();

  void on_pushButton_3_clicked();

  void on_pushButton_5_clicked();

  void on_pushButton_6_clicked();

 private:
  Ui::RulesForm *ui;
  QList<Rule *> *user_rules;
  QList<Rule *> *dynamic_rules;
  NetLinkManager *nlManager;
  UnixSemaphore *sem_dyn_rules;

  void fillUserGrid();

  void fillDynamicGrid();

  void addToGrid(Rule *r);

  void updateInGrid(int row, Rule *r);

  bool isExist(Rule *r);
};

#endif  // RULESFORM_H
