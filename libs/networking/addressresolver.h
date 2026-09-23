#ifndef ADDRESSRESOLVER_H
#define ADDRESSRESOLVER_H

#include <QHostInfo>
#include <QList>
#include <QString>
#include <QStringList>

class AddressResolver {
 public:
  AddressResolver();

  static QList<QHostAddress> resolve(QString hostName);
};

#endif  // ADDRESSRESOLVER_H
