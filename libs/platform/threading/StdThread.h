#ifndef STDTHREAD_H
#define STDTHREAD_H

#include <QObject>
#include <atomic>
#include <thread>

class StdThread : public QObject {
  Q_OBJECT

 public:
  StdThread() = default;

  ~StdThread() override;

  StdThread(const StdThread &) = delete;
  StdThread &operator=(const StdThread &) = delete;

  void start();

  void requestStop() noexcept;

  [[nodiscard]] bool isStopRequested() const noexcept;

  void wait() noexcept;

 protected:
  virtual void run() = 0;

 private:
  std::atomic_bool stopRequested_{false};
  std::thread thread_;
};

#endif  // STDTHREAD_H