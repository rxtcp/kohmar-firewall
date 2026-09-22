#ifndef SOCKETSIGNAL_H_
#define SOCKETSIGNAL_H_

#include <string>

#include "Signal.h"
#include "platform/sockets/LowLevelSocket.h"

/* Class that represents a realization of abstract class Signal by using unix
 * sockets  */
class SocketSignal : public Signal {
 public:
  SocketSignal(std::string name, bool role);

  void signal();

  void wait();

  virtual ~SocketSignal();

 private:
  LowLevelSocket *socket;
};

#endif /* SOCKETSIGNAL_H_ */
