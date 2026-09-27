#ifndef DBMANAGER_H
#define DBMANAGER_H

#ifndef ADS_DAEMON
#include <QMessageBox>
#endif  // ADS_DAEMON

#include "QtSql"
#include "engine/structs.h"
#include "networking/addressresolver.h"

class DbManager {
 public:
  DbManager();

  static bool addToDb(Rule *rule);

  static bool updateInDb(const Rule *rule);

  static bool removeFromDb(int id);

  static QList<Rule *> *getRulesFromDb();
};

#endif  // DBMANAGER_H
