#ifndef STRUCTS_H
#define STRUCTS_H

#define TCP_DROP_ALL_PORTS 1
#define TCP_DROP_SRC_PORT_ONLY 2
#define TCP_DROP_DEST_PORT_ONLY 3

#define _ICMP 1
#define _TCP 6
#define _UDP 17

#define LEARN_HTTP 1
#define LEARN_HTTPS 2
#define LEARN_FTP 3
#define LEARN_SSH 4
#define LEARN_TELNET 5
#define LEARN_ALL 6

#define _DROP 0
#define _ACCEPT 1

#include <QString>

#include "platform/threading/UnixSemaphore.h"

struct MyPacket {
  unsigned int in_out;
  unsigned int src_ip;
  unsigned int dest_ip;
  int src_port;  // 0~2^32
  int dest_port;
  unsigned int proto;  // 0: all, 1: tcp, 2: udp 3: icmp

  bool urg;
  bool ack;
  bool syn;
  bool fin;
  bool rst;
  bool psh;
};

struct Rule {
  int id_rule = 0;
  unsigned int in_out = 0;
  QString ip_src = "-";
  QString ip_dest = "-";
  int port_src = -1;
  int port_dest = -1;
  unsigned int proto = 0;
  unsigned int action = 0;
  QString host_name_dest = "-";
  QString host_name_src = "-";
};

struct CommandToAds {
  int command;
  unsigned int in_out;
  char ip_src[15];
  char ip_dest[15];
  char host_src[100];
  char host_dest[100];
  int port_src;
  int port_dest;
  unsigned int proto;
  unsigned int action;
  int id_rule;
};

struct AnomalyNodeTCP {
  unsigned int src_ip;
  unsigned int dest_ip;
  int src_port;
  int dest_port;
  unsigned int proto;
  double anomaly;
  int predictor;
  char *states;
};

struct AnomalyNodeFlow {
  double flow_size_average;
  int flow_new_tcp_conn_count;
  double flow_udp_count;
  double flow_icmp_count;
  int flow_diff_ip_src_count;
  double flow_low_active_conn_count;
  int flow_little_count;
  int flow_big_count;
  // int flow_diff_ports_count;
  double anomaly;
  //
  int winner;  // for som visualization
};

struct ConnectionTreeNode {
  // int key;
  unsigned int ip_src;
  unsigned int ip_dest;
  unsigned int port_src;
  unsigned int port_dest;
  ConnectionTreeNode *left;
  ConnectionTreeNode *right;

  char *states;
  // std::vector<char*> learning_strings;
  char *learning_string;
  // bool learned;
  // int last_l_str;

  UnixSemaphore *sem;

  long packs_transmitted;

  int bal;

  int id;
};

#endif
