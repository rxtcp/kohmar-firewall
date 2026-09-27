#ifndef NETLINKMANAGER_H
#define NETLINKMANAGER_H

#include <mutex>

#ifndef ADS_DAEMON
#include <QList>
#include <QString>
#endif

#include <linux/netlink.h>
#include <sys/socket.h>

#include "engine/structs.h"
#include "firewall/protocol.h"

class NetLinkManager {
 public:
  explicit NetLinkManager(int netlinkProtocol);
  ~NetLinkManager();

  NetLinkManager(const NetLinkManager &) = delete;
  NetLinkManager &operator=(const NetLinkManager &) = delete;

  bool isOpen() const;
  void closeNetlinkSocket();

  bool sendCommand(enum fw_command_type command);

  bool sendRuleToKernel(const Rule *rule);
  bool deleteRuleFromKernel(const Rule *rule);
  bool updateRuleInKernel(const Rule *rule);

#ifndef ADS_DAEMON
  bool getDynamicRulesFromKernel(QList<Rule *> *dynamicRules);
  static QString getStrIp(fw_u32 ip);
#endif

 private:
  bool sendRuleCommand(enum fw_command_type command, const Rule &rule);

  bool sendRequest(const struct fw_command_message &request,
                   fw_u32 netlinkSequence);

  bool receiveResponse(struct fw_response_message *response,
                       fw_u32 expectedNetlinkSequence);

  fw_u32 nextNetlinkSequence();

  static bool encodeRule(const Rule &source,
                         struct fw_rule_message *destination);

  std::mutex transactionMutex_;
  fw_u32 nextNetlinkSequence_ = 1;

  int netlinkSocket_ = -1;
  struct sockaddr_nl sourceAddress_{};
  struct sockaddr_nl destinationAddress_{};
};

#endif  // NETLINKMANAGER_H