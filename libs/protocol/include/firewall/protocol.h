#ifndef FIREWALL_PROTOCOL_H
#define FIREWALL_PROTOCOL_H

#ifdef __KERNEL__
#include <linux/types.h>

typedef __u8 fw_u8;
typedef __u16 fw_u16;
typedef __u32 fw_u32;
typedef __s32 fw_s32;
#else
#include <stdint.h>

typedef uint8_t fw_u8;
typedef uint16_t fw_u16;
typedef uint32_t fw_u32;
typedef int32_t fw_s32;
#endif

#define FW_PROTOCOL_VERSION 1

/*
 * Числовое значение IPv4 хранится в host byte order.
 * Значение 0 означает любой адрес.
 */
enum fw_command_type {
  FW_COMMAND_DELETE_RULE = 0,
  FW_COMMAND_ADD_RULE = 1,
  FW_COMMAND_UPDATE_RULE = 2,
  FW_COMMAND_GET_DYNAMIC_RULES = 3,
  FW_COMMAND_PAUSE = 4,
  FW_COMMAND_START = 5
};

enum fw_status {
  FW_STATUS_OK = 0,
  FW_STATUS_INVALID_MESSAGE = -1,
  FW_STATUS_UNSUPPORTED_VERSION = -2,
  FW_STATUS_INVALID_COMMAND = -3,
  FW_STATUS_RULE_NOT_FOUND = -4,
  FW_STATUS_INTERNAL_ERROR = -5
};

struct fw_rule_message {
  fw_s32 id;
  fw_u32 direction;
  fw_u32 source_ipv4;
  fw_u32 destination_ipv4;
  fw_s32 source_port;
  fw_s32 destination_port;
  fw_u8 protocol;
  fw_u8 action;
  fw_u8 reserved[2];
};

struct fw_command_message {
  fw_u16 version;
  fw_u16 command;
  fw_u32 payload_size;
  struct fw_rule_message rule;
};

struct fw_response_message {
  fw_u16 version;
  fw_u16 command;
  fw_s32 status;

  /*
   * Для FW_COMMAND_GET_DYNAMIC_RULES:
   * item_count — общее число правил;
   * sequence — индекс текущего правила, начиная с нуля.
   *
   * Для остальных команд оба поля равны нулю.
   */
  fw_u32 item_count;
  fw_u32 sequence;

  struct fw_rule_message rule;
};

#if defined(__cplusplus)
static_assert(sizeof(struct fw_rule_message) == 28,
              "Unexpected fw_rule_message layout");
static_assert(sizeof(struct fw_command_message) == 36,
              "Unexpected fw_command_message layout");
static_assert(sizeof(struct fw_response_message) == 44,
              "Unexpected fw_response_message layout");
#else
_Static_assert(sizeof(struct fw_rule_message) == 28,
               "Unexpected fw_rule_message layout");
_Static_assert(sizeof(struct fw_command_message) == 36,
               "Unexpected fw_command_message layout");
_Static_assert(sizeof(struct fw_response_message) == 44,
               "Unexpected fw_response_message layout");
#endif

#endif