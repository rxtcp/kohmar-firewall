#include "dbmanager.h"

#include <QThread>

DbManager::DbManager() {}

bool DbManager::addToDb(Rule *rule) {
  if (rule == nullptr) {
    qWarning() << "Cannot insert a null rule";
    return false;
  }

  const QString connectionName =
      QStringLiteral("firewall-%1")
          .arg(reinterpret_cast<quintptr>(QThread::currentThreadId()));

  QSqlDatabase database = QSqlDatabase::contains(connectionName)
                              ? QSqlDatabase::database(connectionName)
                              : QSqlDatabase::addDatabase(
                                    QStringLiteral("QSQLITE"), connectionName);

  database.setDatabaseName(
      QStringLiteral("data/seeds/common/db_firewall.sqlite"));

  if (!database.open()) {
    qWarning() << "Cannot open firewall database:"
               << database.lastError().text();
    return false;
  }

  QSqlQuery query(database);
  query.prepare(QStringLiteral(
      "INSERT INTO rule("
      "in_out, ip_src, ip_dest, port_src, port_dest, proto, action, "
      "src_name, dest_name"
      ") VALUES("
      ":in_out, :ip_src, :ip_dest, :port_src, :port_dest, :proto, "
      ":action, :src_name, :dest_name"
      ")"));

  query.bindValue(QStringLiteral(":in_out"), rule->in_out);
  query.bindValue(QStringLiteral(":ip_src"), rule->ip_src);
  query.bindValue(QStringLiteral(":ip_dest"), rule->ip_dest);
  query.bindValue(QStringLiteral(":port_src"), rule->port_src);
  query.bindValue(QStringLiteral(":port_dest"), rule->port_dest);
  query.bindValue(QStringLiteral(":proto"), rule->proto);
  query.bindValue(QStringLiteral(":action"), rule->action);
  query.bindValue(QStringLiteral(":src_name"), rule->host_name_src);
  query.bindValue(QStringLiteral(":dest_name"), rule->host_name_dest);

  if (!query.exec()) {
    qWarning() << "Cannot insert firewall rule:" << query.lastError().text();
    database.close();
    return false;
  }

  bool idOk = false;
  const int id = query.lastInsertId().toInt(&idOk);

  if (!idOk || id <= 0) {
    qWarning() << "Database returned an invalid firewall rule ID";
    database.close();
    return false;
  }

  rule->id_rule = id;
  database.close();
  return true;
}

bool DbManager::removeFromDb(int id) {
  if (id <= 0) {
    qWarning() << "Invalid firewall rule ID:" << id;
    return false;
  }

  const QString connectionName =
      QStringLiteral("firewall-%1")
          .arg(reinterpret_cast<quintptr>(QThread::currentThreadId()));

  QSqlDatabase database = QSqlDatabase::contains(connectionName)
                              ? QSqlDatabase::database(connectionName)
                              : QSqlDatabase::addDatabase(
                                    QStringLiteral("QSQLITE"), connectionName);

  database.setDatabaseName(
      QStringLiteral("data/seeds/common/db_firewall.sqlite"));

  if (!database.open()) {
    qWarning() << "Cannot open firewall database:"
               << database.lastError().text();
    return false;
  }

  QSqlQuery query(database);
  query.prepare(QStringLiteral("DELETE FROM rule WHERE id_rule = :id_rule"));
  query.bindValue(QStringLiteral(":id_rule"), id);

  if (!query.exec()) {
    qWarning() << "Cannot delete firewall rule:" << query.lastError().text();
    database.close();
    return false;
  }

  if (query.numRowsAffected() != 1) {
    qWarning() << "Firewall rule was not found in database:" << id;
    database.close();
    return false;
  }

  database.close();
  return true;
}

bool DbManager::updateInDb(const Rule *rule) {
  if (rule == nullptr || rule->id_rule <= 0) {
    qWarning() << "Cannot update an invalid firewall rule";
    return false;
  }

  const QString connectionName =
      QStringLiteral("firewall-%1")
          .arg(reinterpret_cast<quintptr>(QThread::currentThreadId()));

  QSqlDatabase database = QSqlDatabase::contains(connectionName)
                              ? QSqlDatabase::database(connectionName)
                              : QSqlDatabase::addDatabase(
                                    QStringLiteral("QSQLITE"), connectionName);

  database.setDatabaseName(
      QStringLiteral("data/seeds/common/db_firewall.sqlite"));

  if (!database.open()) {
    qWarning() << "Cannot open firewall database:"
               << database.lastError().text();
    return false;
  }

  QSqlQuery query(database);
  query.prepare(
      QStringLiteral("UPDATE rule SET "
                     "in_out = :in_out, "
                     "ip_src = :ip_src, "
                     "ip_dest = :ip_dest, "
                     "port_src = :port_src, "
                     "port_dest = :port_dest, "
                     "proto = :proto, "
                     "action = :action, "
                     "src_name = :src_name, "
                     "dest_name = :dest_name "
                     "WHERE id_rule = :id_rule"));

  query.bindValue(QStringLiteral(":in_out"), rule->in_out);
  query.bindValue(QStringLiteral(":ip_src"), rule->ip_src);
  query.bindValue(QStringLiteral(":ip_dest"), rule->ip_dest);
  query.bindValue(QStringLiteral(":port_src"), rule->port_src);
  query.bindValue(QStringLiteral(":port_dest"), rule->port_dest);
  query.bindValue(QStringLiteral(":proto"), rule->proto);
  query.bindValue(QStringLiteral(":action"), rule->action);
  query.bindValue(QStringLiteral(":src_name"), rule->host_name_src);
  query.bindValue(QStringLiteral(":dest_name"), rule->host_name_dest);
  query.bindValue(QStringLiteral(":id_rule"), rule->id_rule);

  if (!query.exec()) {
    qWarning() << "Cannot update firewall rule:" << query.lastError().text();
    database.close();
    return false;
  }

  if (query.numRowsAffected() != 1) {
    qWarning() << "Firewall rule was not found in database:" << rule->id_rule;
    database.close();
    return false;
  }

  database.close();
  return true;
}

QList<Rule *> *DbManager::getRulesFromDb() {
  QList<Rule *> *user_rules = new QList<Rule *>();

  // connect to DB
  QSqlDatabase dBase;
  dBase = QSqlDatabase::addDatabase("QSQLITE");
  dBase.setDatabaseName("data/seeds/common/db_firewall.sqlite");

  if (!dBase.open()) {
#ifndef ADS_DAEMON
    QMessageBox msgBox;
    msgBox.setText("Error connecting to database!");
    msgBox.exec();
#endif  // ADS_DAEMON
    qDebug() << "Error connecting to database!";
    qApp->quit();
  }

  // get data
  QSqlQuery query;

  if (!query.exec("SELECT * FROM rule ORDER BY id_rule DESC")) {
#ifndef ADS_DAEMON
    QMessageBox msgBox;
    msgBox.setText("Database read error!");
    msgBox.exec();
#endif  // ADS_DAEMON
    qDebug() << "Database read error!";
    qApp->quit();
  }

  QSqlRecord rec = query.record();

  int id_rule, in_out, proto, action, port_dest, port_src;
  QString ip_src, ip_dest, src_name, dest_name;
  // QTableWidgetItem *idItem, *inOutItem, *ipSrcItem, *portSrcItem,
  // *ipDestItem, *portDestItem, *protoItem, *actItem;
  Rule *rule;

  // append to user_rules
  while (query.next()) {
    id_rule = query.value(rec.indexOf("id_rule")).toInt();
    in_out = query.value(rec.indexOf("in_out")).toUInt();
    ip_src = query.value(rec.indexOf("ip_src")).toString();
    port_src = query.value(rec.indexOf("port_src")).toInt();
    ip_dest = query.value(rec.indexOf("ip_dest")).toString();
    port_dest = query.value(rec.indexOf("port_dest")).toInt();
    proto = query.value(rec.indexOf("proto")).toUInt();
    action = query.value(rec.indexOf("action")).toUInt();
    src_name = query.value(rec.indexOf("src_name")).toString();
    dest_name = query.value(rec.indexOf("dest_name")).toString();

    if (src_name != "-" && dest_name != "-") {
      QList<QHostAddress> src_adrs = AddressResolver::resolve(src_name);
      QList<QHostAddress> dest_adrs = AddressResolver::resolve(dest_name);

      if (src_adrs.count() != 0 && dest_adrs.count() != 0) {
        for (const QHostAddress &src_address : src_adrs) {
          for (const QHostAddress &dest_address : dest_adrs) {
            rule = new Rule;

            rule->id_rule = id_rule;
            rule->action = action;
            rule->in_out = in_out;
            rule->ip_dest = dest_address.toString();
            rule->ip_src = src_address.toString();
            rule->port_dest = port_dest;
            rule->port_src = port_src;
            rule->proto = proto;
            rule->host_name_src = src_name;
            rule->host_name_dest = dest_name;

            user_rules->append(rule);
          }
        }
      } else {
        if (src_adrs.count() == 0 && dest_adrs.count() != 0) {
          for (const QHostAddress &dest_address : dest_adrs) {
            rule = new Rule;

            rule->id_rule = id_rule;
            rule->action = action;
            rule->in_out = in_out;
            rule->ip_dest = dest_address.toString();
            rule->ip_src = ip_src;
            rule->port_dest = port_dest;
            rule->port_src = port_src;
            rule->proto = proto;
            rule->host_name_src = src_name;
            rule->host_name_dest = dest_name;

            user_rules->append(rule);
          }
        } else {
          if (src_adrs.count() != 0 && dest_adrs.count() == 0) {
            for (const QHostAddress &src_address : src_adrs) {
              rule = new Rule;

              rule->id_rule = id_rule;
              rule->action = action;
              rule->in_out = in_out;
              rule->ip_dest = ip_dest;
              rule->ip_src = src_address.toString();
              rule->port_dest = port_dest;
              rule->port_src = port_src;
              rule->proto = proto;
              rule->host_name_src = src_name;
              rule->host_name_dest = dest_name;

              user_rules->append(rule);
            }
          } else {
            rule = new Rule;

            rule->id_rule = id_rule;
            rule->action = action;
            rule->in_out = in_out;
            rule->ip_dest = ip_dest;
            rule->ip_src = ip_src;
            rule->port_dest = port_dest;
            rule->port_src = port_src;
            rule->proto = proto;
            rule->host_name_src = src_name;
            rule->host_name_dest = dest_name;

            user_rules->append(rule);
          }
        }
      }
    } else {
      if (src_name != "-") {
        QList<QHostAddress> src_adrs = AddressResolver::resolve(src_name);

        if (src_adrs.count() != 0) {
          for (const QHostAddress &src_address : src_adrs) {
            rule = new Rule;

            rule->id_rule = id_rule;
            rule->action = action;
            rule->in_out = in_out;
            rule->ip_dest = ip_dest;
            rule->ip_src = src_address.toString();
            rule->port_dest = port_dest;
            rule->port_src = port_src;
            rule->proto = proto;
            rule->host_name_src = src_name;
            rule->host_name_dest = "-";

            user_rules->append(rule);
          }
        } else {
          rule = new Rule;

          rule->id_rule = id_rule;
          rule->action = action;
          rule->in_out = in_out;
          rule->ip_dest = ip_dest;
          rule->ip_src = ip_src;
          rule->port_dest = port_dest;
          rule->port_src = port_src;
          rule->proto = proto;
          rule->host_name_src = src_name;
          rule->host_name_dest = "-";

          user_rules->append(rule);
        }
      } else {
        if (dest_name != "-") {
          QList<QHostAddress> dest_adrs = AddressResolver::resolve(dest_name);

          if (dest_adrs.count() != 0) {
            for (const QHostAddress &dest_address : dest_adrs) {
              rule = new Rule;

              rule->id_rule = id_rule;
              rule->action = action;
              rule->in_out = in_out;
              rule->ip_dest = dest_address.toString();
              rule->ip_src = ip_src;
              rule->port_dest = port_dest;
              rule->port_src = port_src;
              rule->proto = proto;
              rule->host_name_dest = dest_name;
              rule->host_name_src = "-";

              user_rules->append(rule);
            }
          } else {
            rule = new Rule;

            rule->id_rule = id_rule;
            rule->action = action;
            rule->in_out = in_out;
            rule->ip_dest = ip_dest;
            rule->ip_src = ip_src;
            rule->port_dest = port_dest;
            rule->port_src = port_src;
            rule->proto = proto;
            rule->host_name_dest = dest_name;
            rule->host_name_src = "-";

            user_rules->append(rule);
          }
        } else {
          rule = new Rule;

          rule->id_rule = id_rule;
          rule->in_out = in_out;
          rule->ip_src = ip_src;
          rule->port_src = port_src;
          rule->ip_dest = ip_dest;
          rule->port_dest = port_dest;
          rule->proto = proto;
          rule->action = action;
          rule->host_name_src = "-";
          rule->host_name_dest = "-";

          user_rules->append(rule);
        }
      }
    }

    // nlManager->sendRuleToKernel(rule);

    // count++;
  }

  dBase.close();

  return user_rules;
}
