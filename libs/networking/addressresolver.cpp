#include "addressresolver.h"

AdressResolver::AdressResolver() {}

QList<QHostAddress> AdressResolver::resolve(QString hostName) {
  QHostInfo hInfo = QHostInfo::fromName(hostName);
  QList<QHostAddress> adrs = hInfo.addresses();
  return adrs;
}
