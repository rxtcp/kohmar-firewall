#include "StdThread.h"

StdThread::~StdThread() {
  requestStop();
  wait();
}

void StdThread::start() {
  if (thread_.joinable()) {
    return;
  }

  stopRequested_.store(false, std::memory_order_release);

  thread_ = std::thread([this] { run(); });
}

void StdThread::requestStop() noexcept {
  stopRequested_.store(true, std::memory_order_release);
}

bool StdThread::isStopRequested() const noexcept {
  return stopRequested_.load(std::memory_order_acquire);
}

void StdThread::wait() noexcept {
  if (thread_.joinable()) {
    thread_.join();
  }
}