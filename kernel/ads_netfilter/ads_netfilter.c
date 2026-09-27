#ifndef KERNEL_NETFILTER
#define KERNEL_NETFILTER

#include <firewall/protocol.h>
#include <linux/capability.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netlink.h>
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "config.h"
#include "rule_types.h"
// #include <asm/current.h>
// #include <asm/segment.h>
// #include <asm/uaccess.h>
#include <asm/atomic.h>
#include <net/ip.h>
#include <net/sock.h>

#if DEBUG
#define log(S)                   \
  if (isLogging) {               \
    printk("[ads_drv] %s\n", S); \
  }
#else
#define log(S) ;
#endif

#define MAX_BUFFERED_LEN 2000

/* Own family for netlink socket */
#define NETLINK_USER 31

struct machdr {
  unsigned char dst[6], src[6];
  char type[2]; /* mac type */
};

static struct nf_hook_ops netfilter_ops_out; /* NF_IP_POST_ROUTING */
struct net_device *dev;

atomic_t got_p;
atomic_t tracked_connections;
int max_tracked_connections = 100000;
atomic_t filtered_packets;

int max_filter_rules = 200;
int filter_classes_count = 0;
int filter_types_count = 0;
int min_packet_size = 0;

char **filter_classes;
char **filter_types;
char *raw;

short drop;
short isLogging = 1;
short isFiltering = 0;
short isMultiFiltering = 0;

short isResender = 0;
short isSniffer = 0;

char ifdev[20];

long buf_size = 3 * 1024 * 1024;
long resender_buf_size = 3 * 1024 * 1024;

char user_data[80]; /* our device */

struct sock *netlink_sock;
static bool run_pause = true;

static struct RuleListItem policy_list;
static DEFINE_SPINLOCK(policy_lock);
static int dyn_rules_count = 0;
static int rules_count = 0;

// the structure used to register the function
static struct nf_hook_ops nfho;
static struct nf_hook_ops nfho_out;

//============Our includes ===========
#include "debug_utils.h"
#include "mmap_utils.h"
#include "nf_hook.h"
#include "proc_fs.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("linux-ai-firewall");
MODULE_AUTHOR("sergey_staroletov, roman_chudov");

//=============FUNCTIONS================================

unsigned int port_str_to_int(char *port_str) {
  unsigned int port = 0;
  int i = 0;
  if (port_str == NULL) {
    return 0;
  }
  while (port_str[i] != '\0') {
    port = port * 10 + (port_str[i] - '0');
    ++i;
  }
  return port;
}

/* convert the string to byte array first, e.g.: from "131.132.162.25" to
 * [131][132][162][25] */
unsigned int ip_str_to_hl(char *ip_str) {
  unsigned char ip_array[4];
  int i = 0;
  unsigned int ip = 0;
  if (ip_str == NULL) {
    return 0;
  }
  memset(ip_array, 0, 4);
  while (ip_str[i] != '.') {
    ip_array[0] = ip_array[0] * 10 + (ip_str[i++] - '0');
  }
  ++i;
  while (ip_str[i] != '.') {
    ip_array[1] = ip_array[1] * 10 + (ip_str[i++] - '0');
  }
  ++i;
  while (ip_str[i] != '.') {
    ip_array[2] = ip_array[2] * 10 + (ip_str[i++] - '0');
  }
  ++i;
  while (ip_str[i] != '\0') {
    ip_array[3] = ip_array[3] * 10 + (ip_str[i++] - '0');
  }
  /* convert from byte array to host long integer format */
  ip = (ip_array[0] << 24);
  ip = (ip | (ip_array[1] << 16));
  ip = (ip | (ip_array[2] << 8));
  ip = (ip | ip_array[3]);
  // printk(KERN_INFO "ip_str_to_hl convert %s to %u\n", ip_str, ip);
  return ip;
}

/* check the two input IP addresses, if they match, only the first few bits
 * (masked bits) are compared */
bool check_ip(unsigned int ip, unsigned int ip_rule, unsigned int mask) {
  unsigned int tmp = ntohl(ip);  // network to host long
  int cmp_len = 32;
  int i = 0, j = 0;
  if (mask != 0) {
    cmp_len = 0;
    for (i = 0; i < 32; ++i) {
      if (mask & (1 << (32 - 1 - i)))
        cmp_len++;
      else
        break;
    }
  }

  /* compare the two IP addresses for the first cmp_len bits */
  for (i = 31, j = 0; j < cmp_len; --i, ++j) {
    if ((tmp & (1 << i)) != (ip_rule & (1 << i))) {
      // printk(KERN_INFO "ip compare: %d bit doesn't match\n", (32-i));
      return false;
    }
  }
  return true;
}

void allocate_memory(void) {
  log("try to alloc buffer");
  raw = NULL;
  raw = (char *)kmalloc(MAX_BUFFERED_LEN, GFP_ATOMIC);
  if (!raw) {
    log("ERROR in memory allocating");
  } else {
    log("allocated memory OK");
  }
}

void free_memory(void) {
  int f;
  log("free mem");
  if (raw) kfree(raw);
  raw = NULL;

  for (f = 0; f < filter_classes_count; f++) kfree(filter_classes[f]);
  if (filter_classes) kfree(filter_classes);

  filter_classes = NULL;

  for (f = 0; f < filter_types_count; f++) kfree(filter_types[f]);
  if (filter_types) kfree(filter_types);
  filter_types = NULL;

  filter_classes_count = 0;
  filter_types_count = 0;
}

void change_target(const char *target) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 22)
  if (!strcmp(target, "pre_routing"))
    netfilter_ops_out.hooknum = NF_INET_PRE_ROUTING;
  if (!strcmp(target, "local_in")) netfilter_ops_out.hooknum = NF_INET_LOCAL_IN;
  if (!strcmp(target, "forward")) netfilter_ops_out.hooknum = NF_INET_FORWARD;
  if (!strcmp(target, "local_out"))
    netfilter_ops_out.hooknum = NF_INET_LOCAL_OUT;
  if (!strcmp(target, "post_routing"))
    netfilter_ops_out.hooknum = NF_INET_POST_ROUTING;
  if (!strcmp(target, "numhooks")) netfilter_ops_out.hooknum = NF_INET_NUMHOOKS;
#else
  if (!strcmp(target, "pre_routing"))
    netfilter_ops_out.hooknum = NF_IP_PRE_ROUTING;
  if (!strcmp(target, "local_in")) netfilter_ops_out.hooknum = NF_IP_LOCAL_IN;
  if (!strcmp(target, "forward")) netfilter_ops_out.hooknum = NF_IP_FORWARD;
  if (!strcmp(target, "local_out")) netfilter_ops_out.hooknum = NF_IP_LOCAL_OUT;
  if (!strcmp(target, "post_routing"))
    netfilter_ops_out.hooknum = NF_IP_POST_ROUTING;
  if (!strcmp(target, "numhooks")) netfilter_ops_out.hooknum = NF_IP_NUMHOOKS;
#endif
}

void change_priority(const char *priority) {
  if (!strcmp(priority, "first")) netfilter_ops_out.priority = NF_IP_PRI_FIRST;
  if (!strcmp(priority, "conntrack_defrag"))
    netfilter_ops_out.priority = NF_IP_PRI_CONNTRACK_DEFRAG;
  if (!strcmp(priority, "raw")) netfilter_ops_out.priority = NF_IP_PRI_RAW;
  if (!strcmp(priority, "selinux_first"))
    netfilter_ops_out.priority = NF_IP_PRI_SELINUX_FIRST;
  if (!strcmp(priority, "conntrack"))
    netfilter_ops_out.priority = NF_IP_PRI_CONNTRACK;
  if (!strcmp(priority, "mangle"))
    netfilter_ops_out.priority = NF_IP_PRI_MANGLE;
  if (!strcmp(priority, "nat_dst"))
    netfilter_ops_out.priority = NF_IP_PRI_NAT_DST;
  if (!strcmp(priority, "filter"))
    netfilter_ops_out.priority = NF_IP_PRI_FILTER;
  if (!strcmp(priority, "security"))
    netfilter_ops_out.priority = NF_IP_PRI_SECURITY;
  if (!strcmp(priority, "nat_src"))
    netfilter_ops_out.priority = NF_IP_PRI_NAT_SRC;
  if (!strcmp(priority, "selinux_last"))
    netfilter_ops_out.priority = NF_IP_PRI_SELINUX_LAST;
  if (!strcmp(priority, "conntrack_confirm"))
    netfilter_ops_out.priority = NF_IP_PRI_CONNTRACK_CONFIRM;
  if (!strcmp(priority, "last")) netfilter_ops_out.priority = NF_IP_PRI_LAST;
}

void init_run_sniffer(void);

int sniffer_dev_open(struct inode *inode, struct file *filep);

int sniffer_dev_release(struct inode *inode, struct file *filep);

ssize_t sniffer_dev_read(struct file *filep, char *buff, size_t count,
                         loff_t *offp);

ssize_t sniffer_dev_write(struct file *filep, const char *buff, size_t count,
                          loff_t *offp);

struct file_operations dev_fops = {
  open : sniffer_dev_open,
  read : sniffer_dev_read,
  write : sniffer_dev_write,
  release : sniffer_dev_release,
};

int sniffer_dev_open(struct inode *inode, struct file *filep) { return 0; }
int sniffer_dev_release(struct inode *inode, struct file *filep) { return 0; }

ssize_t sniffer_dev_read(struct file *filep, char *buff, size_t count,
                         loff_t *offp) {
  return 0;
}

/*
 * Handles parameters passing: user echo ... >/dev/ads_sniffer
 */
ssize_t sniffer_dev_write(struct file *filep, const char *buff, size_t count,
                          loff_t *offp) {
  char saveif[20];
  char buffer[30];
  int l;

  strcpy(saveif, ifdev);
  strcpy(ifdev, "null");

  log("dev_write");

  /* function to copy user space buffer to kernel space*/
  if (count > 79) count = 79;
  if (copy_from_user(user_data, buff, count) != 0)
    log("Userspace -> kernel copy failed!\n");

  user_data[count] = 0;

  for (l = 0; l < count; l++)
    if (user_data[l] == '\r' || user_data[l] == '\n') {
      user_data[l] = 0;
      break;
    }
  log("user sent:");
  log(user_data);

  // start sniffer by request
  if (!strcmp(user_data, "sniffer")) {
    isSniffer = 1;
    init_run_sniffer();
    strcpy(ifdev, saveif);
    return count;
  }

  // setup parameters
  if (!strcmp(user_data, "drop_packets")) {
    drop = 1;
    log("enabled packets drop");
  } else if (!strcmp(user_data, "pass_packets")) {
    drop = 0;
    log("disabled packets drop");
  }

  if (!strcmp(user_data, "logging")) {
    isLogging = 1;
  }

  if (!strcmp(user_data, "nologging")) {
    isLogging = 0;
  }

  // some commands known to the userspace starter app

  if (user_data[0] == 'i' && user_data[1] == 'f') {
    memset(saveif, 0, sizeof(saveif));
    strcpy(saveif, user_data + 3);
    printk("set up drop interface: '%s'\n", saveif);
  }

  // enable mime filtering?
  if (user_data[0] == 'm' && user_data[1] == 'f') {
    if (user_data[3] == '1') {
      isFiltering = 1;
      log("packet filtering with mime enabled");
    } else {
      isFiltering = 0;
      log("packet filtering with mime disabled");
    }
  }

  if (user_data[0] == 'm' && user_data[1] == 'g') {
    if (user_data[3] == '1') {
      isMultiFiltering = 1;
      log("multi connection filtering with mime enabled");
    } else {
      isMultiFiltering = 0;
      log("multi connection filtering with mime disabled");
    }
  }

  if (user_data[0] == 'p' && user_data[1] == 'r') {
    strcpy(buffer, user_data + 3);
    log("change priority to");
    log(buffer);
    change_priority(buffer);
  }

  if (user_data[0] == 't' && user_data[1] == 't') {
    strcpy(buffer, user_data + 3);
    log("change target to");
    log(buffer);
    change_target(buffer);
  }

  if (user_data[0] == 'm' && user_data[1] == 's') {
    strcpy(buffer, user_data + 3);
    min_packet_size = simple_strtol(buffer, NULL, 10);
    printk("set up min packet size: %d\n", min_packet_size);
  }

  if (user_data[0] == 'b' && user_data[1] == 'f') {
    // set buffer size
    strcpy(buffer, user_data + 3);
    buf_size = simple_strtol(buffer, NULL, 10);
  }

  if (user_data[0] == 'c' && user_data[1] == 'c') {
    char word[50];
    strcpy(word, user_data + 3);
    if (filter_classes_count < max_filter_rules) {
      filter_classes[filter_classes_count] = kmalloc(50, GFP_ATOMIC);
      strcpy(filter_classes[filter_classes_count], word);
      log("added rule:");
      log(filter_classes[filter_classes_count]);
      filter_classes_count++;
    } else {
      log("too many filter rules!");
    }
  }

  if (user_data[0] == 'c' && user_data[1] == 't') {
    char word[50];
    strcpy(word, user_data + 3);
    if (filter_types_count < max_filter_rules) {
      filter_types[filter_types_count] = kmalloc(50, GFP_ATOMIC);
      strcpy(filter_types[filter_types_count], word);
      log("added rule:");
      log(filter_types[filter_types_count]);
      filter_types_count++;
    } else {
      log("too many filter rules!");
    }
  }

  memset(user_data, 0, sizeof(user_data));
  strcpy(ifdev, saveif);

  return count;
}

void init_run_sniffer(void) {
  log("init ads_sniffer\n");

  allocate_memory();
  mmap_rx = kmalloc(sizeof(struct pkt_mmap), GFP_ATOMIC);

  init_mmap_all(buf_size, "ads_sniff_mmap", mmap_rx, &packet_mmap_ops_rx,
                &mmap_fops_rx);

  atomic_set(&mmap_rx->number_atomic, 1);
  atomic_set(&got_p, 0);
  atomic_set(&tracked_connections, 0);
  atomic_set(&filtered_packets, 0);

  // fill in the hook structure for incoming packet hook
  nfho.hook = hook_func_in;
  nfho.hooknum = NF_INET_LOCAL_IN;  // NF_INET_PRE_ROUTING;
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &nfho);  // Register the hook

  // fill in the hook structure for outgoing packet hook
  nfho_out.hook = hook_func_out;
  nfho_out.hooknum = NF_INET_LOCAL_OUT;  // NF_INET_POST_ROUTING;
  nfho_out.pf = PF_INET;
  nfho_out.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &nfho_out);  // Register the hook

  log("init ads sniffer done");
}

/*
 * FOR RULES
 */

static bool is_rule_message_valid(const struct fw_rule_message *rule) {
  if (rule == NULL) {
    return false;
  }

  if (rule->direction != FW_DIRECTION_IN &&
      rule->direction != FW_DIRECTION_OUT) {
    return false;
  }

  if (rule->source_port < -1 || rule->source_port > 65535 ||
      rule->destination_port < -1 || rule->destination_port > 65535) {
    return false;
  }

  if (rule->protocol != FW_RULE_PROTOCOL_ANY &&
      rule->protocol != FW_RULE_PROTOCOL_TCP &&
      rule->protocol != FW_RULE_PROTOCOL_UDP &&
      rule->protocol != FW_RULE_PROTOCOL_ICMP) {
    return false;
  }

  if (rule->action != FW_RULE_ACTION_DROP &&
      rule->action != FW_RULE_ACTION_ACCEPT) {
    return false;
  }

  if (rule->reserved[0] != 0 || rule->reserved[1] != 0) {
    return false;
  }

  return true;
}

static fw_s32 add_a_rule(const struct fw_rule_message *description) {
  struct RuleListItem *new_rule;
  struct RuleListItem *existing_rule;
  struct list_head *position;

  if (description == NULL) {
    return FW_STATUS_INVALID_RULE;
  }

  new_rule = kzalloc(sizeof(*new_rule), GFP_KERNEL);
  if (new_rule == NULL) {
    return FW_STATUS_INTERNAL_ERROR;
  }

  new_rule->id_rule = description->id;
  new_rule->in_out = description->direction;

  new_rule->src_ip = description->source_ipv4;
  new_rule->src_netmask = 0;
  new_rule->src_port = description->source_port;

  new_rule->dest_ip = description->destination_ipv4;
  new_rule->dest_netmask = 0;
  new_rule->dest_port = description->destination_port;

  new_rule->proto = description->protocol;
  new_rule->action = description->action;

  INIT_LIST_HEAD(&new_rule->list);

  spin_lock_bh(&policy_lock);

  list_for_each(position, &policy_list.list) {
    existing_rule = list_entry(position, struct RuleListItem, list);

    if (existing_rule->in_out == description->direction &&
        existing_rule->src_ip == description->source_ipv4 &&
        existing_rule->dest_ip == description->destination_ipv4 &&
        existing_rule->src_port == description->source_port &&
        existing_rule->dest_port == description->destination_port &&
        existing_rule->proto == description->protocol &&
        existing_rule->action == description->action) {
      spin_unlock_bh(&policy_lock);
      kfree(new_rule);
      return FW_STATUS_RULE_ALREADY_EXISTS;
    }
  }

  if (rules_count >= max_filter_rules) {
    spin_unlock_bh(&policy_lock);
    kfree(new_rule);
    return FW_STATUS_RULE_LIMIT_REACHED;
  }

  list_add_tail(&new_rule->list, &policy_list.list);
  rules_count++;

  if (new_rule->id_rule < 0) {
    dyn_rules_count++;
  }

  spin_unlock_bh(&policy_lock);
  return FW_STATUS_OK;
}

static int delete_a_rule(const struct fw_rule_message *description) {
  struct list_head *position;
  struct list_head *next;
  struct RuleListItem *rule;

  if (description == NULL) {
    return 0;
  }

  spin_lock_bh(&policy_lock);

  list_for_each_safe(position, next, &policy_list.list) {
    rule = list_entry(position, struct RuleListItem, list);

    if (rule->id_rule == description->id) {
      if (rule->id_rule < 0) {
        dyn_rules_count--;
      }

      list_del(position);

      if (rules_count > 0) {
        rules_count--;
      }

      spin_unlock_bh(&policy_lock);

      kfree(rule);
      return 1;
    }
  }

  spin_unlock_bh(&policy_lock);
  return 0;
}

static int update_a_rule(const struct fw_rule_message *description) {
  struct list_head *position;
  struct RuleListItem *rule;

  if (description == NULL) {
    return 0;
  }

  spin_lock_bh(&policy_lock);

  list_for_each(position, &policy_list.list) {
    rule = list_entry(position, struct RuleListItem, list);

    if (rule->id_rule == description->id) {
      rule->in_out = description->direction;

      rule->src_ip = description->source_ipv4;
      rule->src_netmask = 0;
      rule->src_port = description->source_port;

      rule->dest_ip = description->destination_ipv4;
      rule->dest_netmask = 0;
      rule->dest_port = description->destination_port;

      rule->proto = description->protocol;
      rule->action = description->action;

      spin_unlock_bh(&policy_lock);
      return 1;
    }
  }

  spin_unlock_bh(&policy_lock);
  return 0;
}

void return_count_dyn_rules(void) {}

static int send_response(fw_u32 port_id, fw_u32 netlink_sequence,
                         fw_u16 command, fw_s32 status, fw_u32 item_count,
                         fw_u32 item_sequence,
                         const struct fw_rule_message *rule) {
  struct fw_response_message response = {
      .version = FW_PROTOCOL_VERSION,
      .command = command,
      .status = status,
      .item_count = item_count,
      .sequence = item_sequence,
  };

  struct sk_buff *socket_buffer;
  struct nlmsghdr *header;

  if (rule != NULL) {
    response.rule = *rule;
  }

  socket_buffer = nlmsg_new(sizeof(response), GFP_KERNEL);

  if (socket_buffer == NULL) {
    return -ENOMEM;
  }

  header = nlmsg_put(socket_buffer, 0, netlink_sequence, NLMSG_DONE,
                     sizeof(response), 0);

  if (header == NULL) {
    kfree_skb(socket_buffer);
    return -EMSGSIZE;
  }

  memcpy(nlmsg_data(header), &response, sizeof(response));

  return nlmsg_unicast(netlink_sock, socket_buffer, port_id);
}

/* Called when data arrives at the netlink socket, the network packet containing
 * the netlink message is passed in the parameters */
static void netlink_Read_Msg(struct sk_buff *skb_in) {
  struct nlmsghdr *header;
  struct fw_command_message command = {0};
  fw_u32 port_id;
  fw_u32 netlink_sequence;
  fw_s32 status = FW_STATUS_OK;

  if (skb_in == NULL) {
    return;
  }

  port_id = NETLINK_CB(skb_in).portid;

  if (skb_in->len < NLMSG_HDRLEN) {
    return;
  }

  header = nlmsg_hdr(skb_in);

  if (header == NULL) {
    return;
  }

  netlink_sequence = header->nlmsg_seq;

  if (!netlink_capable(skb_in, CAP_NET_ADMIN)) {
    send_response(port_id, netlink_sequence, 0, FW_STATUS_PERMISSION_DENIED, 0,
                  0, NULL);
    return;
  }

  if (!nlmsg_ok(header, skb_in->len) || nlmsg_len(header) != sizeof(command)) {
    send_response(port_id, netlink_sequence, 0, FW_STATUS_INVALID_MESSAGE, 0, 0,
                  NULL);
    return;
  }

  memcpy(&command, nlmsg_data(header), sizeof(command));

  if (command.version != FW_PROTOCOL_VERSION) {
    send_response(port_id, netlink_sequence, command.command,
                  FW_STATUS_UNSUPPORTED_VERSION, 0, 0, NULL);
    return;
  }

  switch (command.command) {
    case FW_COMMAND_ADD_RULE:
    case FW_COMMAND_DELETE_RULE:
    case FW_COMMAND_UPDATE_RULE:
      if (command.payload_size != sizeof(command.rule)) {
        send_response(port_id, netlink_sequence, command.command,
                      FW_STATUS_INVALID_MESSAGE, 0, 0, NULL);
        return;
      }
      break;

    case FW_COMMAND_GET_DYNAMIC_RULES:
    case FW_COMMAND_PAUSE:
    case FW_COMMAND_START:
      if (command.payload_size != 0) {
        send_response(port_id, netlink_sequence, command.command,
                      FW_STATUS_INVALID_MESSAGE, 0, 0, NULL);
        return;
      }
      break;

    default:
      send_response(port_id, netlink_sequence, command.command,
                    FW_STATUS_INVALID_COMMAND, 0, 0, NULL);
      return;
  }

  if ((command.command == FW_COMMAND_ADD_RULE ||
       command.command == FW_COMMAND_DELETE_RULE ||
       command.command == FW_COMMAND_UPDATE_RULE) &&
      !is_rule_message_valid(&command.rule)) {
    send_response(port_id, netlink_sequence, command.command,
                  FW_STATUS_INVALID_RULE, 0, 0, NULL);
    return;
  }

  switch (command.command) {
    case FW_COMMAND_ADD_RULE:
      status = add_a_rule(&command.rule);
      break;

    case FW_COMMAND_DELETE_RULE:
      if (!delete_a_rule(&command.rule)) {
        status = FW_STATUS_RULE_NOT_FOUND;
      }
      break;

    case FW_COMMAND_UPDATE_RULE:
      if (!update_a_rule(&command.rule)) {
        status = FW_STATUS_RULE_NOT_FOUND;
      }
      break;

    case FW_COMMAND_START:
      WRITE_ONCE(run_pause, true);
      break;

    case FW_COMMAND_PAUSE:
      WRITE_ONCE(run_pause, false);
      break;

    case FW_COMMAND_GET_DYNAMIC_RULES: {
      struct list_head *position;
      struct RuleListItem *item;
      struct fw_rule_message *snapshot = NULL;
      fw_u32 capacity;
      fw_u32 count = 0;
      fw_u32 index;

      capacity = max_filter_rules > 0 ? (fw_u32)max_filter_rules : 0;

      if (capacity > 0) {
        snapshot = kcalloc(capacity, sizeof(*snapshot), GFP_KERNEL);

        if (snapshot == NULL) {
          send_response(port_id, netlink_sequence, command.command,
                        FW_STATUS_INTERNAL_ERROR, 0, 0, NULL);
          return;
        }
      }

      spin_lock_bh(&policy_lock);

      list_for_each(position, &policy_list.list) {
        item = list_entry(position, struct RuleListItem, list);

        if (item->id_rule >= 0) {
          continue;
        }

        if (count >= capacity) {
          break;
        }

        snapshot[count].id = item->id_rule;
        snapshot[count].direction = item->in_out;
        snapshot[count].source_ipv4 = item->src_ip;
        snapshot[count].destination_ipv4 = item->dest_ip;
        snapshot[count].source_port = item->src_port;
        snapshot[count].destination_port = item->dest_port;
        snapshot[count].protocol = item->proto;
        snapshot[count].action = item->action;

        ++count;
      }

      spin_unlock_bh(&policy_lock);

      if (send_response(port_id, netlink_sequence, command.command,
                        FW_STATUS_OK, count, 0, NULL) < 0) {
        kfree(snapshot);
        return;
      }

      for (index = 0; index < count; ++index) {
        if (send_response(port_id, netlink_sequence, command.command,
                          FW_STATUS_OK, count, index, &snapshot[index]) < 0) {
          kfree(snapshot);
          return;
        }
      }

      kfree(snapshot);
      return;
    }

    default:
      return;
  }

  if (send_response(port_id, netlink_sequence, command.command, status, 0, 0,
                    NULL) < 0) {
    pr_warn("Firewall: failed to send Netlink response\n");
  }
}

/* Initialization routine */

static int __init ads_netfilter_init(void) {
  struct netlink_kernel_cfg cfg = {
      .input = netlink_Read_Msg,
  };

  int dev_num = 232;

  log("INIT...");

  INIT_LIST_HEAD(&(policy_list.list));

  log("creating device");

  if (register_chrdev(dev_num, "ads_sniffer", &dev_fops)) {
    printk("failed to register character device, num = %d\n", 232);
    return 1;
  }

  filter_classes = NULL;
  filter_types = NULL;
  filter_classes = kmalloc(max_filter_rules * sizeof(char *), GFP_ATOMIC);
  filter_types = kmalloc(max_filter_rules * sizeof(char *), GFP_ATOMIC);

  if (!filter_classes || !filter_types) {
    log("ERROR memory allocating for types/classes");
  };

  init_procfs();

  netlink_sock = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);

  if (netlink_sock == NULL) {
    printk(KERN_ERR "Firewall: Error creating netlink socket.\n");
    unregister_chrdev(232, "ads_sniffer");
    remove_proc();
    return -ENOMEM;
  }

  log("INIT done");

  return 0;
}

void cleanup(void) { nf_unregister_net_hook(&init_net, &netfilter_ops_out); }

/* main cleanup routine */
static void __exit ads_netfilter_exit(void) {
  struct list_head *p, *q;
  struct RuleListItem *a_rule;

  printk("unloading ads_drv...");

  remove_proc();

  if (isSniffer) {
    // nf_unregister_hook(&netfilter_ops_out);
    nf_unregister_net_hook(&init_net, &nfho);
    nf_unregister_net_hook(&init_net, &nfho_out);

    mmap_clear_all(mmap_rx);
    free_memory();
  }

  unregister_chrdev(232, "ads_sniffer");

  if (netlink_sock != NULL) {
    netlink_kernel_release(netlink_sock);
    netlink_sock = NULL;
  }

  printk(KERN_INFO "Firewall: free policy list\n");

  list_for_each_safe(p, q, &policy_list.list) {
    a_rule = list_entry(p, struct RuleListItem, list);
    list_del(p);
    kfree(a_rule);
  }

  printk(KERN_INFO "Firewall: kernel module UNLOADED.\n");
}

static int hex_to_int(char c) {
  int first = c / 16 - 3;
  int second = c % 16;
  int result = first * 10 + second;

  if (result > 9) {
    result--;
  }

  return result;
}

static int hex_to_ascii(char c, char d) {
  int high = hex_to_int(c) * 16;
  int low = hex_to_int(d);

  return high + low;
}

module_init(ads_netfilter_init);
module_exit(ads_netfilter_exit);

#endif  // KERNEL_NETFILTER
