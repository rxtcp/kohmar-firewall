#include "addressresolver.h"

AddressResolver::AddressResolver() {}

QList<QHostAddress> AddressResolver::resolve(QString hostName) {
  QHostInfo hInfo = QHostInfo::fromName(hostName);
  QList<QHostAddress> adrs = hInfo.addresses();
  return adrs;
}
