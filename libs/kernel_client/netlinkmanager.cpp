#include "netlinkmanager.h"

#include <unistd.h>

#include <QDebug>
#include <QHostAddress>
#include <QMessageBox>
#include <QtAlgorithms>
#include <cerrno>
#include <cstring>

NetLinkManager::NetLinkManager(int netlinkProtocol) {
  netlinkSocket_ = socket(PF_NETLINK, SOCK_RAW, netlinkProtocol);

  if (netlinkSocket_ < 0) {
    qWarning() << "Netlink socket creation failed:" << strerror(errno);
#ifndef ADS_DAEMON
    QMessageBox::critical(nullptr, "Netlink", "Netlink socket creation error");
#endif
    return;
  }

  sourceAddress_ = {};
  sourceAddress_.nl_family = AF_NETLINK;
  sourceAddress_.nl_pid = static_cast<unsigned int>(getpid());
  sourceAddress_.nl_groups = 0;

  if (bind(netlinkSocket_, reinterpret_cast<struct sockaddr *>(&sourceAddress_),
           sizeof(sourceAddress_)) < 0) {
    qWarning() << "Netlink socket bind failed:" << strerror(errno);
#ifndef ADS_DAEMON
    QMessageBox::critical(nullptr, "Netlink", "Netlink socket bind error");
#endif
    closeNetlinkSocket();
    return;
  }

  struct timeval timeout{};
  timeout.tv_sec = 2;
  timeout.tv_usec = 0;

  if (setsockopt(netlinkSocket_, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                 sizeof(timeout)) < 0) {
    qWarning() << "Cannot set Netlink receive timeout:" << strerror(errno);
    closeNetlinkSocket();
    return;
  }

  destinationAddress_ = {};
  destinationAddress_.nl_family = AF_NETLINK;
  destinationAddress_.nl_pid = 0;
  destinationAddress_.nl_groups = 0;
}

NetLinkManager::~NetLinkManager() { closeNetlinkSocket(); }

bool NetLinkManager::isOpen() const { return netlinkSocket_ >= 0; }

void NetLinkManager::closeNetlinkSocket() {
  if (netlinkSocket_ >= 0) {
    close(netlinkSocket_);
    netlinkSocket_ = -1;
  }
}

fw_u32 NetLinkManager::nextNetlinkSequence() {
  const fw_u32 sequence = nextNetlinkSequence_++;

  if (nextNetlinkSequence_ == 0) {
    nextNetlinkSequence_ = 1;
  }

  return sequence;
}

bool NetLinkManager::sendRequest(const struct fw_command_message &request,
                                 fw_u32 netlinkSequence) {
  if (!isOpen()) {
    return false;
  }

  alignas(
      struct nlmsghdr) unsigned char buffer[NLMSG_SPACE(sizeof(request))] = {};

  auto *header = reinterpret_cast<struct nlmsghdr *>(buffer);

  header->nlmsg_len = NLMSG_LENGTH(sizeof(request));
  header->nlmsg_type = NLMSG_DONE;
  header->nlmsg_flags = 0;
  header->nlmsg_seq = netlinkSequence;
  header->nlmsg_pid = sourceAddress_.nl_pid;

  std::memcpy(NLMSG_DATA(header), &request, sizeof(request));

  struct iovec vector{};
  vector.iov_base = header;
  vector.iov_len = header->nlmsg_len;

  struct msghdr message{};
  message.msg_name = &destinationAddress_;
  message.msg_namelen = sizeof(destinationAddress_);
  message.msg_iov = &vector;
  message.msg_iovlen = 1;

  const ssize_t sent = sendmsg(netlinkSocket_, &message, 0);

  if (sent < 0) {
    qWarning() << "Netlink send failed:" << std::strerror(errno);
    return false;
  }

  if (static_cast<std::size_t>(sent) != header->nlmsg_len) {
    qWarning() << "Incomplete Netlink request";
    return false;
  }

  return true;
}

bool NetLinkManager::receiveResponse(struct fw_response_message *response,
                                     fw_u32 expectedNetlinkSequence) {
  if (!isOpen() || response == nullptr) {
    return false;
  }

  for (;;) {
    alignas(struct nlmsghdr) unsigned char
        buffer[NLMSG_SPACE(sizeof(*response))] = {};

    auto *header = reinterpret_cast<struct nlmsghdr *>(buffer);

    struct iovec vector{};
    vector.iov_base = buffer;
    vector.iov_len = sizeof(buffer);

    struct sockaddr_nl sender{};

    struct msghdr message{};
    message.msg_name = &sender;
    message.msg_namelen = sizeof(sender);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;

    const ssize_t received = recvmsg(netlinkSocket_, &message, 0);

    if (received < 0) {
      qWarning() << "Netlink receive failed:" << std::strerror(errno);
      return false;
    }

    if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
      qWarning() << "Truncated Netlink response";
      return false;
    }

    if (message.msg_namelen < sizeof(struct sockaddr_nl) ||
        sender.nl_family != AF_NETLINK || sender.nl_pid != 0) {
      qWarning() << "Unexpected Netlink sender";
      continue;
    }

    int remaining = static_cast<int>(received);

    if (received < static_cast<ssize_t>(NLMSG_LENGTH(sizeof(*response))) ||
        !NLMSG_OK(header, remaining) ||
        NLMSG_PAYLOAD(header, 0) != sizeof(*response)) {
      qWarning() << "Invalid Netlink response size";
      continue;
    }

    if (header->nlmsg_type != NLMSG_DONE) {
      qWarning() << "Unexpected Netlink message type:" << header->nlmsg_type;
      continue;
    }

    if (header->nlmsg_seq != expectedNetlinkSequence) {
      qWarning() << "Ignoring stale Netlink response:" << header->nlmsg_seq
                 << "expected:" << expectedNetlinkSequence;
      continue;
    }

    std::memcpy(response, NLMSG_DATA(header), sizeof(*response));

    if (response->version != FW_PROTOCOL_VERSION) {
      qWarning() << "Unsupported protocol version:" << response->version;
      return false;
    }

    return true;
  }
}

bool NetLinkManager::sendCommand(enum fw_command_type command) {
  std::lock_guard<std::mutex> lock(transactionMutex_);

  const fw_u32 netlinkSequence = nextNetlinkSequence();

  struct fw_command_message request{};
  request.version = FW_PROTOCOL_VERSION;
  request.command = static_cast<fw_u16>(command);
  request.payload_size = 0;

  if (!sendRequest(request, netlinkSequence)) {
    return false;
  }

  struct fw_response_message response{};

  if (!receiveResponse(&response, netlinkSequence)) {
    return false;
  }

  return response.command == request.command && response.status == FW_STATUS_OK;
}

bool NetLinkManager::encodeRule(const Rule &source,
                                struct fw_rule_message *destination) {
  if (destination == nullptr) {
    return false;
  }

  *destination = {};

  destination->id = source.id_rule;
  destination->direction = source.in_out;

  if (source.ip_src != "-") {
    const QHostAddress address(source.ip_src);
    bool conversionOk = false;

    if (address.protocol() != QAbstractSocket::IPv4Protocol) {
      return false;
    }

    destination->source_ipv4 = address.toIPv4Address(&conversionOk);

    if (!conversionOk) {
      return false;
    }
  }

  if (source.ip_dest != "-") {
    const QHostAddress address(source.ip_dest);
    bool conversionOk = false;

    if (address.protocol() != QAbstractSocket::IPv4Protocol) {
      return false;
    }

    destination->destination_ipv4 = address.toIPv4Address(&conversionOk);

    if (!conversionOk) {
      return false;
    }
  }

  const bool sourcePortValid =
      source.port_src == -1 ||
      (source.port_src >= 0 && source.port_src <= 65535);

  const bool destinationPortValid =
      source.port_dest == -1 ||
      (source.port_dest >= 0 && source.port_dest <= 65535);

  const bool directionValid =
      source.in_out == FW_DIRECTION_IN || source.in_out == FW_DIRECTION_OUT;

  const bool protocolValid = source.proto == FW_RULE_PROTOCOL_ANY ||
                             source.proto == FW_RULE_PROTOCOL_TCP ||
                             source.proto == FW_RULE_PROTOCOL_UDP ||
                             source.proto == FW_RULE_PROTOCOL_ICMP;

  const bool actionValid = source.action == FW_RULE_ACTION_DROP ||
                           source.action == FW_RULE_ACTION_ACCEPT;

  if (!sourcePortValid || !destinationPortValid || !directionValid ||
      !protocolValid || !actionValid) {
    return false;
  }

  destination->source_port = static_cast<fw_s32>(source.port_src);
  destination->destination_port = static_cast<fw_s32>(source.port_dest);
  destination->protocol = static_cast<fw_u8>(source.proto);
  destination->action = static_cast<fw_u8>(source.action);

  return true;
}

bool NetLinkManager::sendRuleCommand(enum fw_command_type command,
                                     const Rule &rule) {
  std::lock_guard<std::mutex> lock(transactionMutex_);

  const fw_u32 netlinkSequence = nextNetlinkSequence();

  struct fw_command_message request{};
  request.version = FW_PROTOCOL_VERSION;
  request.command = static_cast<fw_u16>(command);
  request.payload_size = sizeof(request.rule);

  if (!encodeRule(rule, &request.rule)) {
    qWarning() << "Cannot encode firewall rule";
    return false;
  }

  if (!sendRequest(request, netlinkSequence)) {
    return false;
  }

  struct fw_response_message response{};

  if (!receiveResponse(&response, netlinkSequence)) {
    return false;
  }

  return response.command == request.command && response.status == FW_STATUS_OK;
}

bool NetLinkManager::sendRuleToKernel(const Rule *rule) {
  return rule != nullptr && sendRuleCommand(FW_COMMAND_ADD_RULE, *rule);
}

bool NetLinkManager::deleteRuleFromKernel(const Rule *rule) {
  return rule != nullptr && sendRuleCommand(FW_COMMAND_DELETE_RULE, *rule);
}

bool NetLinkManager::updateRuleInKernel(const Rule *rule) {
  return rule != nullptr && sendRuleCommand(FW_COMMAND_UPDATE_RULE, *rule);
}

#ifndef ADS_DAEMON
bool NetLinkManager::getDynamicRulesFromKernel(QList<Rule *> *dynamicRules) {
  std::lock_guard<std::mutex> lock(transactionMutex_);
  if (dynamicRules == nullptr) {
    return false;
  }

  struct fw_command_message request{};
  request.version = FW_PROTOCOL_VERSION;
  request.command = FW_COMMAND_GET_DYNAMIC_RULES;
  request.payload_size = 0;

  const fw_u32 netlinkSequence = nextNetlinkSequence();

  if (!sendRequest(request, netlinkSequence)) {
    return false;
  }

  struct fw_response_message response{};

  if (!receiveResponse(&response, netlinkSequence) ||
      response.command != FW_COMMAND_GET_DYNAMIC_RULES ||
      response.status != FW_STATUS_OK || response.sequence != 0) {
    return false;
  }

  const fw_u32 ruleCount = response.item_count;
  QList<Rule *> receivedRules;

  for (fw_u32 index = 0; index < ruleCount; ++index) {
    if (!receiveResponse(&response, netlinkSequence) ||
        response.command != FW_COMMAND_GET_DYNAMIC_RULES ||
        response.status != FW_STATUS_OK || response.item_count != ruleCount ||
        response.sequence != index) {
      qDeleteAll(receivedRules);
      return false;
    }

    const struct fw_rule_message &source = response.rule;

    auto *rule = new Rule;
    rule->id_rule = source.id;
    rule->in_out = source.direction;
    rule->ip_src = source.source_ipv4 == 0 ? "-" : getStrIp(source.source_ipv4);
    rule->ip_dest =
        source.destination_ipv4 == 0 ? "-" : getStrIp(source.destination_ipv4);
    rule->port_src = source.source_port;
    rule->port_dest = source.destination_port;
    rule->proto = source.protocol;
    rule->action = source.action;
    rule->host_name_src = "-";
    rule->host_name_dest = "-";

    receivedRules.append(rule);
  }

  dynamicRules->append(receivedRules);
  return true;
}

QString NetLinkManager::getStrIp(fw_u32 ip) {
  return QHostAddress(ip).toString();
}
#endif