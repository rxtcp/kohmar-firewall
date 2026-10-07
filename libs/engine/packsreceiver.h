#ifndef PACKSRECEIVER_H
#define PACKSRECEIVER_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <QDebug>
#include <QList>
#include <QObject>
#include <QThread>
#include <atomic>
#include <iostream>
#include <memory>
#include <queue>
#include <sstream>
#include <vector>

#include "detectors/pst/pst_predictor.h"
#include "detectors/som/samplesom.h"
#include "detectors/som/selforganizedmap.h"
#include "engine/config.h"
#include "engine/structs.h"
#include "platform/PlatformFactory.h"
#include "platform/config/ConfigReader.h"
#include "platform/logging/Logger.h"
#include "platform/logging/NullLogger.h"
#include "platform/logging/PrintfLogger.h"
#include "platform/logging/SyslogLogger.h"
#include "platform/paths/RuntimePaths.h"
#include "platform/services/DaemonService.h"
#include "platform/services/Service.h"
#include "platform/sockets/LowLevelSocket.h"
#include "platform/sockets/UnixLowLevelSocket.h"
#include "platform/threading/StdThread.h"
#include "platform/threading/Thread.h"
#include "platform/threading/UnixSemaphore.h"

using namespace std;

// forward declaration
struct DataSaved;

// this data struct we are getting from kernel module
struct DataFromKernel {
  char buffer[2000];  // for one mtu packet
  short length;
};

struct DataSaved {
  char *buffer;
  int length;
};

struct NewPacketHeader {
  int flagReady;
  int size;
};

class PacksReceiver : public StdThread {
 public:
  explicit PacksReceiver(firewall::RuntimePaths paths);
  ~PacksReceiver() override;

  void run() override;

  void stop() noexcept;

  void setIsLearnTcp(bool _isLearn, int _learnedProto);

  bool getIsLearnTcp();

  void setIsLearnFlow(bool _isLearn);

  bool getIsLearnFlow();

  bool getTcpAnomalyFromQueue(AnomalyNodeTCP *to_save);

  bool getFlowAnomalyFromQueue(AnomalyNodeFlow *to_save);

  bool packCanLearned(unsigned int port_dest, unsigned int port_src);

  QList<SampleSom *> getFlowLearningSamplesFromQueue();

  QList<char *> getLerningStrings(int learned_proto, int *len_to_save);

  void clearFlowLearningSamples();

  void clearLearningStrings();

  // settings
  int getTcpDepth();

  int getTcpAnomalyLimit();

  int getTcpDropPorts();

  bool getTcpGenerateRules();

  int getFlowPacksMaxCount();

  int getFlowMinCountPacksInConn();

  int getFlowAnomalyLimit();

  bool getFlowGenerateRules();

  void setFlowPacksMaxCount(int _max);

  void setCurFlowAnomaly(double _anomaly);

  void retrainPredictor(char *seq, int predictor);

 signals:

 public slots:

 private:
  firewall::RuntimePaths paths_;

  class OutputThread : public StdThread {
   public:
    explicit OutputThread(PacksReceiver *receiver) : receiver(receiver) {
      flow_cur_count = 0;
      flow_big_count = 0;
      flow_cur_count = 0;
      flow_diff_ip_src_count = 0;
      flow_diff_ports_count = 0;
      flow_icmp_count = 0;
      flow_little_count = 0;
      flow_low_active_conn_count = 0;
      flow_new_tcp_conn_count = 0;
      flow_size = 0;
      flow_udp_count = 0;
    }

    void run() override;

   private:
    PacksReceiver *receiver;

    char tcp_beg_conn = 1 + 48;
    char tcp_beg_conn_else = 63 + 48;

    int flow_cur_count;
    int flow_size;  //_average;
    int flow_little_count;
    int flow_big_count;
    int flow_new_tcp_conn_count;
    int flow_udp_count;
    int flow_icmp_count;
    int flow_diff_ip_src_count;
    int flow_diff_ports_count;
    int flow_low_active_conn_count;

    // void addConnectionToTree(const char* data, int len);
    void processing_packet(const char *data, int len);

    void addStateToTcpConnection(ConnectionTreeNode *con, char new_state);

    void addStateToLearningString(ConnectionTreeNode *con, char new_state);

    void addTcpAnomalyToQueue(ConnectionTreeNode *node, double anomaly,
                              int predictor);

    bool isIpFromLAN(unsigned int ip);

    // bool packCanLearned(unsigned int port_dest, unsigned int port_src);
  };

  class KernelDataReaderThread : public StdThread {
   public:
    explicit KernelDataReaderThread(PacksReceiver *receiver)
        : receiver(receiver) {}

    void run() override;

   private:
    PacksReceiver *receiver;
  };

  //-------------------------
  // some global data
  //-------------------------
  PstPredictor *http_predictor;
  PstPredictor *ftp_predictor;
  PstPredictor *https_predictor;
  PstPredictor *ssh_predictor;
  PstPredictor *telnet_predictor;
  PstPredictor *common_predictor;

  SelfOrganizedMap *som;
  int N;
  int M;
  // int dimension;
  int Iters;
  double Radius;
  double G;
  double lambda;
  double eta;

  bool isLearnTcp;
  bool isLearnFlow;
  bool tcp_generate_rules;
  int learnedProtocol;
  int states_count;
  int tcp_anomaly_limit;
  int tcp_drop_ports;
  unsigned int my_ip;

  int flow_packs_max_count;
  int flow_min_count_packs_in_conn;
  int flow_anomaly_limit;
  int flow_som_dimension;
  bool flow_generate_rules;
  double flow_cur_anomaly;
  long flow_cur_anomalies_in_queue;
  QList<int> packs_sizes;

  static const int maxBufferLenConst = 20 * 1024 * 1024 * 2;
  int bufferLength;
  /*static*/
  long mmapBufSize;
  int delay;       // buffer's delay in ms
  Logger *logger;  // logger for logging

  string pathToConfig;  // need for daemons

  std::unique_ptr<UnixSemaphore> sem_output;
  std::unique_ptr<UnixSemaphore> sem_send;
  std::unique_ptr<UnixSemaphore> sem_pause_kernel_reader;
  std::unique_ptr<UnixSemaphore> sem_con_tcp;
  std::unique_ptr<UnixSemaphore> sem_con_udp;
  std::unique_ptr<UnixSemaphore> sem_con_icmp;
  std::unique_ptr<UnixSemaphore> sem_is_learn_tcp;
  std::unique_ptr<UnixSemaphore> sem_is_learn_flow;
  std::unique_ptr<UnixSemaphore> sem_anomaly_tcp;
  std::unique_ptr<UnixSemaphore> sem_anomaly_flow;
  std::unique_ptr<UnixSemaphore> sem_flow_cur_anomaly;

  std::atomic_bool needPauseKernelReader{false};

  std::unique_ptr<OutputThread> outputThread_;
  std::unique_ptr<KernelDataReaderThread> kernelDataReaderThread_;
  // count

  // queue
  std::queue<DataSaved *> outputQueue;
  std::queue<AnomalyNodeTCP> anomalyQueueTcp;
  std::queue<AnomalyNodeFlow> anomalyQueueFlow;
  QList<SampleSom *> flow_learning_samples;

  // conditions and corresponding mutexes for thread wakeups (new data posted to
  // queues)
  pthread_cond_t cond_kernel_data_arrive;
  pthread_mutex_t mutex_kernel_data_arrive;

  pthread_mutex_t mutex_kernel_reader_paused;
  pthread_cond_t cond_kernel_reader_paused;

  QList<ConnectionTreeNode> connections_tcp;
  QList<ConnectionTreeNode> connections_udp;
  QList<ConnectionTreeNode> connections_icmp;

  const char *protocol_from_number(int n);

  int ReaderDaemonRereadConfig();

  int ReaderDaemonStopWork();

  int ReaderDaemonWork();

  void loadSettings();

  void initPredictors();

  void initSOM();

  unsigned int ip_str_to_hl(char *ip_str);

 public:
  SelfOrganizedMap *getSOM() { return som; }
};

#endif  // PACKSRECEIVER_H
