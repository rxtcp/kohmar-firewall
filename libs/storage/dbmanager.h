#ifndef DBMANAGER_H
#define DBMANAGER_H

#ifndef ADS_DAEMON
#include <QMessageBox>
#endif  // ADS_DAEMON

#include "../../Common/adressresolver.h"
#include "../engine/structs.h"
#include "QtSql"

class DbManager {
 public:
  DbManager();

  static void addToDb(Rule *r);

  static void updateInDb(Rule *r);

  static void removeFromDb(int id);

  static QList<Rule *> *getRulesFromDb();
};

#endif  // DBMANAGER_H
