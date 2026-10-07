#include "packsreceiver.h"

#include <QByteArray>
#include <QFile>
#include <utility>

#include "platform/paths/SystemPaths.h"

namespace {

class ScopedFd {
 public:
  explicit ScopedFd(int fd = -1) noexcept : fd_(fd) {}

  ~ScopedFd() {
    if (fd_ >= 0) {
      ::close(fd_);
    }
  }

  ScopedFd(const ScopedFd &) = delete;
  ScopedFd &operator=(const ScopedFd &) = delete;

  [[nodiscard]] int get() const noexcept { return fd_; }

 private:
  int fd_;
};

class ScopedMmap {
 public:
  ScopedMmap(void *address, std::size_t size) noexcept
      : address_(address), size_(size) {}

  ~ScopedMmap() {
    if (address_ != MAP_FAILED && address_ != nullptr) {
      ::munmap(address_, size_);
    }
  }

  ScopedMmap(const ScopedMmap &) = delete;
  ScopedMmap &operator=(const ScopedMmap &) = delete;

 private:
  void *address_;
  std::size_t size_;
};

}  // namespace

PacksReceiver::PacksReceiver(firewall::RuntimePaths paths)
    : StdThread(), paths_(std::move(paths)) {
  // maxBufferLenConst = 20 * 1024 * 1024 * 2;
  isLearnTcp = false;
  isLearnFlow = false;

  // TCP
  learnedProtocol = LEARN_HTTP;
  states_count = 4;
  tcp_anomaly_limit = 40;
  tcp_generate_rules = true;
  tcp_drop_ports = 1;

  // FLOW
  flow_packs_max_count = 30;
  flow_min_count_packs_in_conn = 2;
  flow_som_dimension = 8;
  flow_cur_anomalies_in_queue = 0;
  flow_anomaly_limit = 30;
  flow_generate_rules = false;

  // SOM seup - todo!
  N = 15, M = 15;
  Iters = 150;
  Radius = 4;
  G = 5;
  lambda = 15;
  eta = 0.1;

  loadSettings();

  bufferLength = 0;
  mmapBufSize = 0;

  sem_output = std::make_unique<UnixSemaphore>();
  sem_send = std::make_unique<UnixSemaphore>();
  sem_pause_kernel_reader = std::make_unique<UnixSemaphore>();
  sem_is_learn_tcp = std::make_unique<UnixSemaphore>();
  sem_is_learn_flow = std::make_unique<UnixSemaphore>();
  sem_anomaly_tcp = std::make_unique<UnixSemaphore>();
  sem_anomaly_flow = std::make_unique<UnixSemaphore>();
  sem_flow_cur_anomaly = std::make_unique<UnixSemaphore>();

  sem_con_tcp = std::make_unique<UnixSemaphore>();
  sem_con_udp = std::make_unique<UnixSemaphore>();
  sem_con_icmp = std::make_unique<UnixSemaphore>();
  // sem_con_tree = new UnixSemaphore();

  needPauseKernelReader = false;

  cond_kernel_data_arrive = PTHREAD_COND_INITIALIZER;
  mutex_kernel_data_arrive = PTHREAD_MUTEX_INITIALIZER;

  mutex_kernel_reader_paused = PTHREAD_MUTEX_INITIALIZER;
  cond_kernel_reader_paused = PTHREAD_COND_INITIALIZER;

  // connections = new ConnetctionTree();

  initPredictors();

  initSOM();
}

PacksReceiver::~PacksReceiver() {
  stop();

  while (!outputQueue.empty()) {
    DataSaved *data = outputQueue.front();
    outputQueue.pop();

    if (data != nullptr) {
      delete[] data->buffer;
      delete data;
    }
  }

  pthread_cond_destroy(&cond_kernel_data_arrive);
  pthread_mutex_destroy(&mutex_kernel_data_arrive);

  pthread_cond_destroy(&cond_kernel_reader_paused);
  pthread_mutex_destroy(&mutex_kernel_reader_paused);
}

void PacksReceiver::run() {
  string daemonName = "readerd";

  signal(SIGPIPE, SIG_IGN);  // ignore SIGPIPE for send() error recovery

#ifndef ADS_QT
  cout << "Backend for send data from sniffer to remote" << endl << endl;
  cout << "see tcreaderd.conf for setup" << endl;
#endif
#ifdef ADS_QT
  qDebug() << "Backend for send data from sniffer to remote";
  qDebug() << "see tcreaderd.conf for setup";
#endif

  // know path
  pathToConfig = paths_.readerConfig().string();

  bool isDaemon = false;

  ConfigReader cfgReader(pathToConfig, true);
  if (!cfgReader.isOk()) {
#ifndef ADS_QT
    cout << "Bad config, not started. " << endl;
#endif
#ifdef ADS_QT
    qDebug() << "Bad config, not started. ";
#endif
    return;
  }

  bufferLength =
      cfgReader.getGlobalProperty("max_buffer_memory", maxBufferLenConst);

  string islog = cfgReader.getGlobalProperty("logging", "on");

  if (islog == "on")
    logger = new PrintfLogger();
  else
    logger = new NullLogger();

  delay = cfgReader.getGlobalProperty("buffer_delay", 100);

  mmapBufSize = cfgReader.getGlobalProperty("sniffer_memory_map_size", 0);

  if (isDaemon) {
  } else {
    // no daemon
    ReaderDaemonWork();
  }
}

const char *PacksReceiver::protocol_from_number(int n) {
  switch (n) {
    case 0:
      return "tcp_dummy";
    case 1:
      return "icmp";
    case 2:
      return "igmp";
    case 4:
      return "ipip";
    case 6:
      return "tcp";
    case 8:
      return "egp";
    case 12:
      return "pup";
    case 17:
      return "udp";
    case 22:
      return "idp";
    case 29:
      return "tp";
    case 41:
      return "ipv6_header";
    case 43:
      return "ipv6_routing";
    case 44:
      return "ipv6_fragment";
    case 46:
      return "vsvp";
    case 47:
      return "gre";
    case 50:
      return "esp";
    case 51:
      return "ah";
    case 58:
      return "icmpv6";
    case 59:
      return "ipv6_none";
    case 60:
      return "ipv6_dstopts";
    case 92:
      return "mtp";
    case 98:
      return "encap";
    case 103:
      return "pim";
    case 108:
      return "comp";
    case 132:
      return "sctp";
    case 255:
      return "raw";
  }
  return "unknown";
}

void PacksReceiver::setIsLearnTcp(bool _isLearn, int _learnedProto) {
  sem_is_learn_tcp->wait();
  isLearnTcp = _isLearn;
  learnedProtocol = _learnedProto;
  sem_is_learn_tcp->post();
}

bool PacksReceiver::getIsLearnTcp() { return isLearnTcp; }

void PacksReceiver::setIsLearnFlow(bool _isLearn) {
  sem_is_learn_flow->wait();
  isLearnFlow = _isLearn;
  /*if(isLearnFlow == true)
    flow_learning_samples.clear();*/
  sem_is_learn_flow->post();
}

bool PacksReceiver::getIsLearnFlow() { return isLearnFlow; }

void PacksReceiver::OutputThread::processing_packet(const char *data, int len) {
  // qDebug() << "processing";
  stringstream os;

  iphdr *iph;  // = (iphdr*) (data);
  struct tcphdr *tcp_header;
  struct udphdr *udp_header;

  QList<ConnectionTreeNode> *connections;
  UnixSemaphore *sem_con;

  unsigned int ip_dest, ip_src, src_port = 0, dest_port = 0;
  bool con_exist = false;
  bool ip_exist_in_conns = false;
  bool pack_is_in;
  char cur_state = 0;

  double anomaly;

  os.clear();

  iph = (iphdr *)(data);
  ip_dest = iph->daddr;
  ip_src = iph->saddr;

  if (!(isIpFromLAN(ip_dest) || isIpFromLAN(ip_src)))  // packs not for me
    return;

  if (iph->protocol == 6) {
    tcp_header = (tcphdr *)(data + sizeof(iphdr));
    src_port = (unsigned int)ntohs(tcp_header->source);
    dest_port = (unsigned int)ntohs(tcp_header->dest);

    int ack = tcp_header->ack;
    int syn = tcp_header->syn;
    int fin = tcp_header->fin;
    int psh = tcp_header->psh;
    int urg = tcp_header->urg;
    int rst = tcp_header->rst;
    os << "ack=" << ack << " syn=" << syn << " fin=" << fin << " psh=" << psh
       << " urg=" << urg << " rst=" << rst;
    os << endl;
    cur_state = syn + ack * 2 + psh * 4 + rst * 8 + urg * 16 + fin * 32 + 48;

    connections = &(receiver->connections_tcp);
    sem_con = receiver->sem_con_tcp.get();
  } else if (iph->protocol == 17) {
    // return;
    udp_header = (udphdr *)(data + sizeof(iphdr));
    src_port = (unsigned int)ntohs(udp_header->source);
    dest_port = (unsigned int)ntohs(udp_header->dest);
    connections = &(receiver->connections_udp);
    sem_con = receiver->sem_con_udp.get();

    flow_udp_count++;
  } else if (iph->protocol == 1) {
    // return;
    connections = &(receiver->connections_icmp);
    sem_con = receiver->sem_con_icmp.get();

    flow_icmp_count++;
  } else
    return;

  flow_cur_count++;
  flow_size += len;

  if (len < 80)
    flow_little_count++;
  else if (len > 2000)
    flow_big_count++;

  ConnectionTreeNode *conn_to_add_state;

  if (ip_dest == receiver->my_ip)
    pack_is_in = true;
  else
    pack_is_in = false;

  sem_con->wait();

  for (ConnectionTreeNode node : *connections) {
    if (pack_is_in && node.ip_src == ip_src) {
      ip_exist_in_conns = true;
    }

    if (node.ip_dest == ip_dest && node.ip_src == ip_src &&
        node.port_dest == dest_port && node.port_src == src_port) {
      con_exist = true;
      conn_to_add_state = &node;
      break;
    }

    if (node.ip_dest == ip_src && node.ip_src == ip_dest &&
        node.port_dest == src_port && node.port_src == dest_port) {
      con_exist = true;
      conn_to_add_state = &node;
      break;
    }
  }

  if (!con_exist) {
    ConnectionTreeNode new_node;
    new_node.ip_dest = ip_dest;
    new_node.ip_src = ip_src;
    new_node.port_dest = dest_port;
    new_node.port_src = src_port;
    new_node.sem = new UnixSemaphore();
    new_node.packs_transmitted = 1;

    if (iph->protocol == 6) {
      new_node.states = new char[receiver->states_count + 1];
      new_node.states[0] = cur_state;
      new_node.states[1] = 0;

      receiver->sem_is_learn_tcp->wait();
      if (receiver->isLearnTcp) {
        if (receiver->packCanLearned(dest_port, src_port)) {
          new_node.learning_string = new char[2];
          new_node.learning_string[0] = cur_state;
          new_node.learning_string[1] = 0;

          os << "+states: " << new_node.states;
        }
      }
      receiver->sem_is_learn_tcp->post();

      if (!receiver->isLearnTcp) {
        int predictor;
        os << "states: " << new_node.states;

        if (src_port == 80 || dest_port == 80 || src_port == 8080 ||
            dest_port == 8080)  // HTTP
        {
          anomaly = receiver->http_predictor->logEval(new_node.states);
          os << "     http_logEval = " << anomaly;
          predictor = 1;
        } else if (src_port == 21 || src_port == 20 || dest_port == 21 ||
                   dest_port == 20)  // FTP
        {
          anomaly = receiver->ftp_predictor->logEval(new_node.states);
          os << "     ftp_logEval = " << anomaly;
          predictor = 2;
        } else if (src_port == 443 || dest_port == 443)  // HTTPS
        {
          anomaly = receiver->https_predictor->logEval(new_node.states);
          os << "     https_logEval = " << anomaly;
          predictor = 3;
        } else if (src_port == 22 || dest_port == 22)  // SSH
        {
          anomaly = receiver->ssh_predictor->logEval(new_node.states);
          os << "     ssh_logEval = " << anomaly;
          predictor = 4;
        } else if (src_port == 23 || dest_port == 23)  // TELNET
        {
          anomaly = receiver->telnet_predictor->logEval(new_node.states);
          os << "     telnet_logEval = " << anomaly;
          predictor = 5;
        } else {
          // COMMON
          anomaly = receiver->common_predictor->logEval(new_node.states);
          os << "     common_logEval = " << anomaly;
          predictor = 6;
        }

        addTcpAnomalyToQueue(&new_node, anomaly, predictor);
      }

      flow_new_tcp_conn_count++;
    } else if (iph->protocol == 17) {
    }

    if (pack_is_in) {
      flow_diff_ports_count++;
    }

    connections->append(new_node);
  } else {
    conn_to_add_state->sem->wait();

    if (iph->protocol == 6) {
      addStateToTcpConnection(conn_to_add_state, cur_state);

      receiver->sem_is_learn_tcp->wait();
      if (receiver->isLearnTcp) {
        if (receiver->packCanLearned(dest_port, src_port)) {
          addStateToLearningString(conn_to_add_state, cur_state);
          os << " states: " << conn_to_add_state->states;
        }
      }
      receiver->sem_is_learn_tcp->post();

      if (!receiver->isLearnTcp) {
        int predictor;
        os << " state = " << conn_to_add_state->states;

        if (src_port == 80 || dest_port == 80 || src_port == 8080 ||
            dest_port == 8080)  // HTTP
        {
          anomaly =
              receiver->http_predictor->logEval(conn_to_add_state->states);
          // addTcpAnomalyToQueue(conn_to_add_state, anomaly);
          os << "     http_logEval = " << anomaly;
          predictor = 1;
        } else if (src_port == 21 || src_port == 20 || dest_port == 21 ||
                   dest_port == 20)  // FTP
        {
          anomaly = receiver->ftp_predictor->logEval(conn_to_add_state->states);
          os << "     ftp_logEval = " << anomaly;
          predictor = 2;
        } else if (src_port == 443 || dest_port == 443)  // HTTPS
        {
          anomaly =
              receiver->https_predictor->logEval(conn_to_add_state->states);
          os << "     https_logEval = " << anomaly;
          predictor = 3;
        } else if (src_port == 22 || dest_port == 22)  // SSH
        {
          anomaly = receiver->ssh_predictor->logEval(conn_to_add_state->states);
          os << "     ssh_logEval = " << anomaly;
          predictor = 4;
        } else if (src_port == 23 || dest_port == 23)  // TELNET
        {
          anomaly =
              receiver->telnet_predictor->logEval(conn_to_add_state->states);
          os << "     telnet_logEval = " << anomaly;
          predictor = 5;
        } else {
          // COMMON
          anomaly =
              receiver->common_predictor->logEval(conn_to_add_state->states);
          os << "     common_logEval = " << anomaly;
          predictor = 6;
        }

        addTcpAnomalyToQueue(conn_to_add_state, anomaly, predictor);
      }
    }

    conn_to_add_state->packs_transmitted++;

    conn_to_add_state->sem->post();
  }

  if (!ip_exist_in_conns) {
    flow_diff_ip_src_count++;
  }

  os << endl;

  //------------------------------SOM--------------------------------------
  if (flow_cur_count == receiver->flow_packs_max_count) {
    for (ConnectionTreeNode node : receiver->connections_tcp) {
      if (node.packs_transmitted < receiver->flow_min_count_packs_in_conn) {
        flow_low_active_conn_count++;
      }

      node.packs_transmitted = 0;
    }

    for (ConnectionTreeNode node : receiver->connections_udp) {
      if (node.packs_transmitted < receiver->flow_min_count_packs_in_conn) {
        flow_low_active_conn_count++;
      }

      node.packs_transmitted = 0;
    }

    double size_average = (double)flow_size / receiver->flow_packs_max_count;
    int diff_ip_percent =
        flow_diff_ip_src_count;  //(double) (flow_diff_ip_src_count * 100) /
    // receiver->flow_packs_max_count;
    double low_active_percent =
        (double)(flow_low_active_conn_count * 100) /
        (receiver->connections_tcp.count() + receiver->connections_udp.count());
    int tcp_percent =
        flow_new_tcp_conn_count;  //(double) (flow_new_tcp_conn_count * 100) /
    // receiver->connections_tcp.count();//receiver->flow_packs_max_count;
    double udp_percent =
        (double)(flow_udp_count * 100) / receiver->flow_packs_max_count;
    double icmp_count_percent =
        (double)(flow_icmp_count * 100) / receiver->flow_packs_max_count;

    os << endl
       << "size_average=" << size_average << " little=" << flow_little_count
       << " big=" << flow_big_count << " diff_ip_p=" << diff_ip_percent
       << " icmp_p=" << icmp_count_percent << " low=" << low_active_percent
       << " tcp_p=" << tcp_percent << " udp_p=" << udp_percent;

    SampleSom *sample_som = new SampleSom(receiver->flow_som_dimension);
    sample_som->setKoeff(0, size_average);
    sample_som->setKoeff(1, diff_ip_percent);
    sample_som->setKoeff(2, icmp_count_percent);
    sample_som->setKoeff(3, low_active_percent);
    sample_som->setKoeff(4, tcp_percent);
    sample_som->setKoeff(5, udp_percent);
    sample_som->setKoeff(6, flow_little_count);
    sample_som->setKoeff(7, flow_big_count);

    receiver->flow_cur_anomalies_in_queue++;

    if (!receiver->isLearnFlow) {
      AnomalyNodeFlow anomaly_flow_node;
      Neuron *res;
      int winner = 0;
      int i, j;

      anomaly_flow_node.flow_diff_ip_src_count = diff_ip_percent;
      anomaly_flow_node.flow_icmp_count = icmp_count_percent;
      anomaly_flow_node.flow_low_active_conn_count = low_active_percent;
      anomaly_flow_node.flow_new_tcp_conn_count = tcp_percent;
      anomaly_flow_node.flow_size_average = size_average;
      anomaly_flow_node.flow_udp_count = udp_percent;
      anomaly_flow_node.flow_big_count = flow_big_count;
      anomaly_flow_node.flow_little_count = flow_little_count;

      winner = receiver->som->recognize(sample_som);

      i = winner / receiver->N;
      j = winner - i * receiver->N;

      res = receiver->som->getNeuron(i, j);

      anomaly_flow_node.anomaly = res->getAnomaly();
      anomaly_flow_node.winner = winner;

      if (winner >= 0) {
        receiver->sem_anomaly_flow->wait();
        receiver->anomalyQueueFlow.push(anomaly_flow_node);
        receiver->sem_anomaly_flow->post();
      }
    } else {
      sample_som->setAnomaly(receiver->flow_cur_anomaly);

      if (receiver->flow_cur_anomalies_in_queue >= 0)
        receiver->flow_learning_samples.append(sample_som);
    }

    flow_cur_count = 0;
    flow_size = 0;
    flow_new_tcp_conn_count = 0;
    flow_udp_count = 0;
    flow_icmp_count = 0;
    flow_diff_ip_src_count = 0;
    flow_low_active_conn_count = 0;
    flow_little_count = 0;
    flow_big_count = 0;
  }

  sem_con->post();

  receiver->logger->log(os.str());
}

void PacksReceiver::OutputThread::addStateToTcpConnection(
    ConnectionTreeNode *con, char new_state) {
  // con->sem->wait();

  int len = strlen(con->states);

  if (len >= receiver->states_count) {
    int i = 1;
    while (con->states[i]) {
      con->states[i - 1] = con->states[i];
      i++;
    }
    con->states[i - 1] = new_state;
    con->states[i] = 0;
  } else {
    con->states[len] = new_state;
    con->states[len + 1] = 0;
  }
  // con->sem->post();
}

void PacksReceiver::OutputThread::addStateToLearningString(
    ConnectionTreeNode *con, char new_state) {
  char str[2];
  str[0] = new_state;
  str[1] = 0;
  strcat(con->learning_string, str);
}

void PacksReceiver::OutputThread::addTcpAnomalyToQueue(ConnectionTreeNode *node,
                                                       double anomaly,
                                                       int predictor) {
  AnomalyNodeTCP new_node;
  new_node.anomaly = anomaly;
  new_node.dest_ip = node->ip_dest;
  new_node.src_ip = node->ip_src;
  new_node.dest_port = node->port_dest;
  new_node.src_port = node->port_src;
  new_node.predictor = predictor;
  new_node.states = node->states;

  receiver->sem_anomaly_tcp->wait();
  receiver->anomalyQueueTcp.push(new_node);
  receiver->sem_anomaly_tcp->post();
}

int PacksReceiver::ReaderDaemonWork() {
  outputThread_ = std::make_unique<OutputThread>(this);
  kernelDataReaderThread_ = std::make_unique<KernelDataReaderThread>(this);

  outputThread_->start();
  kernelDataReaderThread_->start();

  qDebug() << "end_start_work";

  return 0;
}

void PacksReceiver::stop() noexcept {
  if (outputThread_ != nullptr) {
    outputThread_->requestStop();
  }

  if (kernelDataReaderThread_ != nullptr) {
    kernelDataReaderThread_->requestStop();
  }

  // OutputThread может находиться в pthread_cond_wait().
  pthread_mutex_lock(&mutex_kernel_data_arrive);
  pthread_cond_broadcast(&cond_kernel_data_arrive);
  pthread_mutex_unlock(&mutex_kernel_data_arrive);

  if (kernelDataReaderThread_ != nullptr) {
    kernelDataReaderThread_->wait();
  }

  if (outputThread_ != nullptr) {
    outputThread_->wait();
  }

  kernelDataReaderThread_.reset();
  outputThread_.reset();

  // Останавливаем/дожидаемся также основного StdThread PacksReceiver.
  requestStop();
  wait();
}

int PacksReceiver::ReaderDaemonStopWork() {
  stop();
  return 0;
}

int PacksReceiver::ReaderDaemonRereadConfig() { return 0; }

void PacksReceiver::OutputThread::run() {
  DataSaved *data = NULL;

  while (!isStopRequested()) {
    pthread_mutex_lock(&receiver->mutex_kernel_data_arrive);

    while (receiver->outputQueue.empty() && !isStopRequested()) {
      pthread_cond_wait(&receiver->cond_kernel_data_arrive,
                        &receiver->mutex_kernel_data_arrive);
    }

    pthread_mutex_unlock(&receiver->mutex_kernel_data_arrive);

    if (isStopRequested()) {
      break;
    }

    data = nullptr;

    receiver->sem_output->wait();

    if (!receiver->outputQueue.empty()) {
      data = receiver->outputQueue.front();
      receiver->outputQueue.pop();
    }

    receiver->sem_output->post();

    if (data == nullptr) {
      continue;
    }

    // print packets here!!!!

    //*********************************************************

    char *buf2 = data->buffer;
    if (!buf2) continue;  //?

    int N = *((int *)buf2);
    buf2 += sizeof(int);

#ifndef ADS_QT
    // receiver->logger->log("got N=" + PrintfLogger::itos(N));
#endif
#ifdef ADS_QT
    // qDebug() << "got N=" << PrintfLogger::itos(N).c_str();
#endif

    for (int p = 0; p < N; p++) {
#ifndef ADS_QT
      // receiver->logger->log("Showing packet " + PrintfLogger::itos(p + 1) + "
      // of " + PrintfLogger::itos(N));
#endif
#ifdef ADS_QT
      // qDebug() << "Showing packet " << PrintfLogger::itos(p + 1).c_str() << "
      // of " << PrintfLogger::itos(N).c_str();
#endif

      short s_len = *((short *)(buf2));
      buf2 += sizeof(short);

#ifndef ADS_QT
      // receiver->logger->log("size=" + PrintfLogger::itos(s_len));
#endif
#ifdef ADS_QT
      // qDebug() << "size=" << PrintfLogger::itos(s_len).c_str();
#endif

      processing_packet(buf2, s_len);
      // addConnectionToTree(buf2, s_len);

      buf2 += s_len;
    }
    //**********************************************************

    delete[] data->buffer;
    delete data;
  }
}

void PacksReceiver::KernelDataReaderThread::run() {
  std::vector<char> outputStorage(
      static_cast<std::size_t>(receiver->bufferLength));

  char *output_buf = outputStorage.data();
  char *output_buf_start = outputStorage.data();

  // for buffer read delay calculation
  struct timespec timetoexpire;
  struct timeval today;
  int secDelay = receiver->delay / 1000;
  int msecDelay = receiver->delay % 1000;

  unsigned int snifferLastReadIndex = 0;
  unsigned int ourLastWroteIndex = 0;

  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

#if DEBUG
#ifndef ADS_QT
  // receiver->logger->log("Reader thread connecting to sniffer...");
#endif
#ifdef ADS_QT
  // qDebug() << "Reader thread connecting to sniffer...";
#endif
#endif

  struct tpacket_req s_packet_req;

  int block_count = receiver->mmapBufSize / 4096;

  s_packet_req.tp_block_size = 4096;
  s_packet_req.tp_frame_size = 2048;
  s_packet_req.tp_block_nr = block_count;
  s_packet_req.tp_frame_nr = block_count * 2;

  // calculate memory to mmap in the kernel
  int size = s_packet_req.tp_block_size * s_packet_req.tp_block_nr;

  // mmap Tx ring buffers memory
  constexpr auto device = firewall::system_paths::mmapDevice;

  ScopedFd fd{::open(device.data(), O_RDWR | O_SYNC)};

  if (fd.get() < 0) {
    qWarning() << "Cannot open" << device.data();
    return;
  }

  void *mapping = ::mmap(nullptr, static_cast<std::size_t>(size),
                         PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0);

  if (mapping == MAP_FAILED) {
    qWarning() << "Cannot mmap" << device.data();
    return;
  }

  ScopedMmap mappedMemory{mapping, static_cast<std::size_t>(size)};

  auto *ps_header_start = static_cast<char *>(mapping);

  snifferLastReadIndex = s_packet_req.tp_frame_nr;
  output_buf_start = output_buf;
  char *pkt;

  while (!isStopRequested()) {
    if (receiver->needPauseKernelReader.load(std::memory_order_acquire)) {
      // notify we are here
      pthread_mutex_lock(&(receiver->mutex_kernel_reader_paused));
      pthread_cond_signal(&(receiver->cond_kernel_reader_paused));
      pthread_mutex_unlock(&(receiver->mutex_kernel_reader_paused));

      // sleep
      receiver->sem_pause_kernel_reader->wait();
      receiver->sem_pause_kernel_reader->post();
    }

    int N = 0;

    char *ps_header = ps_header_start;

    struct NewPacketHeader *hdr;

    // we walk through our last receiver's number and
    // index that stored kernel module in memory
    // for this index ps_header_start with 0 index is used

    snifferLastReadIndex = *((int *)ps_header_start);

    if (ourLastWroteIndex + 1 > s_packet_req.tp_frame_nr) ourLastWroteIndex = 0;
    if (snifferLastReadIndex >= s_packet_req.tp_frame_nr)
      snifferLastReadIndex = 1;

    int a = ourLastWroteIndex + 1;
    ps_header = ps_header_start + a * s_packet_req.tp_frame_size;

    int b = snifferLastReadIndex;

    bool repeatFromOneFlag = 0;

    if (snifferLastReadIndex != ourLastWroteIndex) {
      if (a > b) {
        // this interval has new packets
        b = s_packet_req.tp_frame_nr;
        repeatFromOneFlag = 1;
      }

      // printf("[A B]=[%d %d]/%d flag=%d\n\n", a, b,
      //		s_packet_req.tp_frame_nr, repeatFromOneFlag);

      output_buf = output_buf_start;
      output_buf += sizeof(int);  // place for packets count

      for (int i = a; i <= b; i++) {
        if (i == b)
          if (repeatFromOneFlag) {
            a = 1;
            i = 0;
            ps_header = ps_header_start + s_packet_req.tp_frame_size;
            b = snifferLastReadIndex;
            repeatFromOneFlag = 0;
            continue;
          }

        hdr = (NewPacketHeader *)ps_header;

        if (hdr->flagReady == 1) {
          ourLastWroteIndex = i;

          // here we put packet
          // calculate IP
          pkt = (char *)(ps_header + sizeof(NewPacketHeader));
          // iph = (iphdr *)pkt;
          {
            *((short *)output_buf) = hdr->size;  // first put size
            output_buf += sizeof(short);
            memcpy(output_buf, pkt,
                   hdr->size);  // minus mac header

            output_buf += (hdr->size);

            N++;
          }
          hdr->flagReady = 0;
        }

        ps_header += s_packet_req.tp_frame_size;
      }

      if (N > 0) {
        // add to queue

        DataSaved *data_to_save = new DataSaved;

        *((int *)output_buf_start) = N;

        int size = output_buf - output_buf_start;
        char *buff = new char[(size < 1024) ? 10240 : size * 10];
        //
        memcpy(buff, output_buf_start, size);
        data_to_save->buffer = buff;
        data_to_save->length = size;

        ps_header = ps_header_start;
#if DEBUG
#ifndef ADS_QT
        // receiver->logger->log("add to queue...");
#endif
#ifdef ADS_QT
        // qDebug() << "add to queue...";
#endif
#endif
        // we must to think which queue we must to use

        receiver->sem_output->wait();
        receiver->outputQueue.push(data_to_save);
        receiver->sem_output->post();

        // wake the threads
        pthread_mutex_lock(&(receiver->mutex_kernel_data_arrive));
        pthread_cond_broadcast(&(receiver->cond_kernel_data_arrive));
        pthread_mutex_unlock(&(receiver->mutex_kernel_data_arrive));
      }
    }
    //-- this code is pthread_sleep(delay)
    gettimeofday(&today, NULL);
    timetoexpire.tv_sec = today.tv_sec + secDelay;
    long nano = (long)today.tv_usec * 1000 + (long)msecDelay * 1000000;
    if (nano > 999999999) {
      timetoexpire.tv_sec += 1;
      timetoexpire.tv_nsec = nano - 999999999;
    } else {
      timetoexpire.tv_nsec = nano;
    }
    do {
      pthread_cond_timedwait(&cond, &mutex, &timetoexpire);
      gettimeofday(&today, NULL);
      if (today.tv_sec > timetoexpire.tv_sec)
        break;
      else {
        if (today.tv_sec == timetoexpire.tv_sec)
          if (today.tv_usec * 1000000 > timetoexpire.tv_nsec) break;
      }
    } while (true);
    //-- end of sleep
  }
}

QList<char *> PacksReceiver::getLerningStrings(int learned_proto,
                                               int *len_to_save) {
  (void)learned_proto;  // unused
  int len;
  int max_len = 0;
  QList<char *> res;
  // stringstream os;
  // os.clear();

  if (isLearnTcp == false) {
    sem_con_tcp->wait();
    qDebug() << "FALSE11";
    for (ConnectionTreeNode tn : connections_tcp) {
      if (packCanLearned(tn.port_dest, tn.port_src)) {
        if (tn.learning_string[0]) {
          res.append(tn.learning_string);

          len = strlen(tn.learning_string);
          if (len > max_len) max_len = len;

          tn.learning_string = new char[1];
          tn.learning_string[0] = 0;
        }
      }
    }

    sem_con_tcp->post();

    *len_to_save = max_len;
  } else
    qDebug() << "TRUE";

  qDebug() << "END return learning strings";

  return res;
}

bool PacksReceiver::getTcpAnomalyFromQueue(AnomalyNodeTCP *to_save) {
  bool res = true;

  sem_anomaly_tcp->wait();

  if (anomalyQueueTcp.size()) {
    AnomalyNodeTCP front = anomalyQueueTcp.front();

    to_save->anomaly = front.anomaly;
    to_save->dest_ip = front.dest_ip;
    to_save->dest_port = front.dest_port;
    to_save->src_ip = front.src_ip;
    to_save->src_port = front.src_port;
    to_save->states = new char[1];
    strcpy(to_save->states, "");

    qDebug() << "Anomaly: ip_src=" + QString::number(to_save->src_ip) +
                    " ip_dest=" + QString::number(to_save->dest_ip);

    anomalyQueueTcp.pop();
  } else
    res = false;

  sem_anomaly_tcp->post();

  return res;
}

bool PacksReceiver::getFlowAnomalyFromQueue(AnomalyNodeFlow *to_save) {
  bool res = true;

  sem_anomaly_flow->wait();

  if (anomalyQueueFlow.size()) {
    AnomalyNodeFlow front = anomalyQueueFlow.front();

    to_save->anomaly = front.anomaly;
    to_save->winner = front.winner;

    anomalyQueueFlow.pop();
  } else
    res = false;

  sem_anomaly_flow->post();

  return res;
}

int PacksReceiver::getFlowAnomalyLimit() { return flow_anomaly_limit; }

void PacksReceiver::loadSettings() {
  stringstream os;

  const auto settingsPath = paths_.adsSettings();
  FILE *file = std::fopen(settingsPath.c_str(), "r");
  char str[20];
  int depth;
  int tcplimit;
  int tcpdrop;
  int flow_count;
  int flow_min_count;
  int flow_limit;
  int r = 0;
  char ip[] = "192.168.64.3";
  my_ip = ip_str_to_hl(ip);  // todo detect!

  os.clear();

  if (file == nullptr) {
    qWarning() << "Settings file not found:"
               << QString::fromStdString(settingsPath.string())
               << "; default settings will be used";
    return;
  }

  os << "loading settings for ADS..." << endl;

  // fscanf(file, "my_ip=%s\n", ip);
  // my_ip = ip_str_to_hl(ip);

  r = fscanf(file, "tcp_anomaly_depth=%d\n", &depth);
  if (r == 1 && depth >= 2 && depth <= 6) {
    states_count = depth;
  } else {
    os << "bad tcp_anomaly_depth param!" << endl;
  }

  r = fscanf(file, "tcp_anomaly_limit=%d\n", &tcplimit);
  if (tcplimit >= 10 && tcplimit <= 100)
    tcp_anomaly_limit = tcplimit;
  else
    os << "bad tcp_anomaly_limit param!" << endl;

  r = fscanf(file, "tcp_generate_rules=%19s\n", str);

  if (!strcmp(str, "true"))
    tcp_generate_rules = true;
  else if (!strcmp(str, "false"))
    tcp_generate_rules = false;
  else
    os << "bad tcp_generate_rules param!" << endl;

  r = fscanf(file, "tcp_drop_ports=%d\n", &tcpdrop);
  if (tcpdrop == 1 || tcpdrop == 2 || tcpdrop == 3)
    tcp_drop_ports = tcpdrop;
  else
    os << "bad tcp_drop_ports param!" << endl;

  r = fscanf(file, "flow_packs_max_count=%d\n", &flow_count);
  if (flow_count >= 20 && flow_count <= 200)
    flow_packs_max_count = flow_count;
  else
    os << "bad flow_packs_max_count param!" << endl;

  r = fscanf(file, "flow_min_count_packs_in_conn=%d\n", &flow_min_count);
  if (flow_min_count >= 0 && flow_min_count <= 20)
    flow_min_count_packs_in_conn = flow_min_count;
  else
    os << "bad flow_min_count_packs_in_conn param!" << endl;

  r = fscanf(file, "flow_anomaly_limit=%d\n", &flow_limit);
  if (flow_limit >= 0 && flow_limit <= 100)
    flow_anomaly_limit = flow_limit;
  else
    os << "bad flow_anomaly_limit param!" << endl;

  r = fscanf(file, "flow_generate_rules=%19s\n", str);

  if (!strcmp(str, "true"))
    flow_generate_rules = true;
  else if (!strcmp(str, "false"))
    flow_generate_rules = false;
  else
    os << "bad flow_generate_rules param!" << endl;

  ///----------------------------------------------------------
  os << "tcp_anomaly_depth=" << states_count << endl;
  os << "tcp_anomaly_limit=" << tcp_anomaly_limit << endl;
  os << "tcp_generate_rules=" << tcp_generate_rules << endl;
  if (r) os << "ads.settings loaded" << endl;

  // os << endl;
  // logger->log(os.str());

  fclose(file);
}

int PacksReceiver::getTcpAnomalyLimit() { return tcp_anomaly_limit; }

int PacksReceiver::getTcpDepth() { return states_count; }

bool PacksReceiver::getTcpGenerateRules() { return tcp_generate_rules; }

int PacksReceiver::getTcpDropPorts() { return tcp_drop_ports; }

int PacksReceiver::getFlowPacksMaxCount() { return flow_packs_max_count; }

int PacksReceiver::getFlowMinCountPacksInConn() {
  return flow_min_count_packs_in_conn;
}

bool PacksReceiver::getFlowGenerateRules() { return flow_generate_rules; }

bool PacksReceiver::packCanLearned(unsigned int port_dest,
                                   unsigned int port_src) {
  bool res = false;
  if (learnedProtocol == LEARN_HTTP) {
    if (port_dest == 80 || port_dest == 8080 || port_src == 80 ||
        port_src == 8080)
      res = true;
  } else if (learnedProtocol == LEARN_FTP) {
    if (port_dest == 21 || port_dest == 20 || port_src == 21 || port_src == 20)
      res = true;
  } else if (learnedProtocol == LEARN_HTTPS) {
    if (port_dest == 443 || port_src == 443) res = true;
  } else if (learnedProtocol == LEARN_SSH) {
    if (port_dest == 22 || port_src == 22) res = true;
  } else if (learnedProtocol == LEARN_TELNET) {
    if (port_dest == 23 || port_src == 23) res = true;
  } else if (learnedProtocol == LEARN_ALL) {
    res = true;
  }

  return res;
}

void PacksReceiver::initPredictors() {
  const auto loadSamples = [this](Samples *samples,
                                  std::string_view fileName) -> int {
    if (samples == nullptr) {
      return -1;
    }

    const auto path = paths_.sample(fileName);
    return samples->loadFromFile(path.c_str());
  };

  http_predictor = new PstPredictor();
  Samples *http_samples = new Samples();
  const int http_len = loadSamples(http_samples, "http.samples");
  http_predictor->init(256, 0.0001, 0.0, 0.0001, 1.05, http_len, 2);
  http_predictor->setName("http");
  http_predictor->learn(http_samples);

  ftp_predictor = new PstPredictor();
  Samples *ftp_samples = new Samples();
  const int ftp_len = loadSamples(ftp_samples, "ftp.samples");
  ftp_predictor->init(256, 0.0001, 0.0, 0.0001, 1.05, ftp_len, 2);
  ftp_predictor->setName("ftp");
  ftp_predictor->learn(ftp_samples);

  https_predictor = new PstPredictor();
  Samples *https_samples = new Samples();
  const int https_len = loadSamples(https_samples, "https.samples");
  https_predictor->init(256, 0.0001, 0.0, 0.0001, 1.05, https_len, 2);
  https_predictor->setName("https");
  https_predictor->learn(https_samples);

  ssh_predictor = new PstPredictor();
  Samples *ssh_samples = new Samples();
  const int ssh_len = loadSamples(ssh_samples, "ssh.samples");
  ssh_predictor->init(256, 0.0001, 0.0, 0.0001, 1.05, ssh_len, 2);
  ssh_predictor->setName("ssh");
  ssh_predictor->learn(ssh_samples);

  telnet_predictor = new PstPredictor();
  Samples *telnet_samples = new Samples();
  const int telnet_len = loadSamples(telnet_samples, "telnet.samples");
  telnet_predictor->init(256, 0.0001, 0.0, 0.0001, 1.05, telnet_len, 2);
  telnet_predictor->setName("telnet");
  telnet_predictor->learn(telnet_samples);

  common_predictor = new PstPredictor();
  Samples *common_samples = new Samples();
  const int common_len = loadSamples(common_samples, "common.samples");
  common_predictor->init(256, 0.0001, 0.0, 0.0001, 1.05, common_len, 2);
  common_predictor->setName("common");
  common_predictor->learn(common_samples);
}

bool PacksReceiver::OutputThread::isIpFromLAN(unsigned int ip) {
  bool res = false;
  // stringstream os;

  int bit1, bit2, bit3, bit4;

  bit1 = 255 & ip;
  bit2 = (0xff00 & ip) >> 8;
  bit3 = (0xff0000 & ip) >> 16;
  bit4 = (0xff000000 & ip) >> 24;
  (void)bit4;

  if ((bit1 == 10) || ((bit1 == 127) && (bit2 == 0) && (bit3 == 0)) ||
      ((bit1 == 172) && ((bit2 >= 16) && (bit2 <= 31))) ||
      ((bit1 == 192) && (bit2 == 168)))
    res = true;
  return res;
}

unsigned int PacksReceiver::ip_str_to_hl(char *ip_str) {
  /*convert the string to byte array first, e.g.: from "131.132.162.25" to
   * [131][132][162][25]*/
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
  /*convert from byte array to host long integer format*/
  ip = (ip_array[0] << 24);
  ip = (ip | (ip_array[1] << 16));
  ip = (ip | (ip_array[2] << 8));
  ip = (ip | ip_array[3]);

  return ip;
}

void PacksReceiver::setCurFlowAnomaly(double _anomaly) {
  sem_flow_cur_anomaly->wait();
  flow_cur_anomaly = _anomaly;
  sem_flow_cur_anomaly->post();
}

void PacksReceiver::initSOM() {
  som = new SelfOrganizedMap(N, M, flow_som_dimension, Iters, Radius, G, lambda,
                             eta, 0);

  const auto samplesPath = paths_.sample("flow.samples");

  QList<SampleSom *> samples =
      SampleSom::loadFromFile(QString::fromStdString(samplesPath.string()));

  som->learn(&samples);
}

QList<SampleSom *> PacksReceiver::getFlowLearningSamplesFromQueue() {
  return flow_learning_samples;
}

void PacksReceiver::clearFlowLearningSamples() {
  flow_learning_samples.clear();
}

void PacksReceiver::clearLearningStrings() {
  if (!isLearnTcp) {
    sem_con_tcp->wait();
    qDebug() << "FALSE12";
    for (ConnectionTreeNode tn : connections_tcp) {
      if (packCanLearned(tn.port_dest, tn.port_src)) {
        if (tn.learning_string[0]) {
          tn.learning_string = new char[1];
          tn.learning_string[0] = 0;
        }
      }
    }

    sem_con_tcp->post();
  } else
    qDebug() << "TRUE12";
}

void PacksReceiver::setFlowPacksMaxCount(int _max) {
  flow_packs_max_count = _max;
}

void PacksReceiver::retrainPredictor(char *seq, int predictor) {
  switch (predictor) {
    case 1:
      http_predictor->retrainForSeq(seq);
      break;
    case 2:
      ftp_predictor->retrainForSeq(seq);
      break;
    case 3:
      https_predictor->retrainForSeq(seq);
      break;
    case 4:
      ssh_predictor->retrainForSeq(seq);
      break;
    case 5:
      telnet_predictor->retrainForSeq(seq);
      break;
    case 6:
      common_predictor->retrainForSeq(seq);
      break;
  }
}
