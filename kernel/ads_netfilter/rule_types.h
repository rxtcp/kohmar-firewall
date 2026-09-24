#ifndef ADS_NETFILTER_RULE_TYPES_H
#define ADS_NETFILTER_RULE_TYPES_H

#include <firewall/protocol.h>
#include <linux/list.h>

struct RuleListItem {
  fw_s32 id_rule;
  fw_u32 in_out;

  fw_u32 src_ip;
  fw_u32 src_netmask;
  fw_s32 src_port;

  fw_u32 dest_ip;
  fw_u32 dest_netmask;
  fw_s32 dest_port;

  fw_u8 proto;
  fw_u8 action;
  fw_u8 reserved[2];

  struct list_head list;
};

#endif