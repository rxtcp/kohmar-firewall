#ifndef DBMANAGER_H
#define DBMANAGER_H

#ifndef ADS_DAEMON
#include <QMessageBox>
#endif  // ADS_DAEMON

#include <filesystem>

#include "QtSql"
#include "engine/structs.h"
#include "networking/addressresolver.h"

class DbManager final {
 public:
  explicit DbManager(std::filesystem::path databasePath);

  bool addToDb(Rule* rule) const;
  bool updateInDb(const Rule* rule) const;
  bool removeFromDb(int id) const;

  [[nodiscard]] QList<Rule*>* getRulesFromDb() const;

 private:
  [[nodiscard]] QString databaseFileName() const;

  std::filesystem::path databasePath_;
};

#endif  // DBMANAGER_H
