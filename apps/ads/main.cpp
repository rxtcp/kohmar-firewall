#ifndef ADS_QT
#define ADS_QT
#endif

#include <pthread.h>

#include <QApplication>
#include <QDebug>
#include <QMessageBox>
#include <cstdlib>

#include "detectors/pst/pst_predictor.h"
#include "engine/packsreceiver.h"
#include "kernel_client/netlinkmanager.h"
#include "ui/mainwindow.h"

bool checkModLoaded();

int main(int argc, char *argv[]) {
  QApplication application(argc, argv);

  qDebug() << "starting netlink manager";

  NetLinkManager netlinkManager(NETLINK_USERSOCK);

  if (!netlinkManager.isOpen()) {
    QMessageBox::critical(
        nullptr, "Firewall",
        "Cannot open Netlink connection to the kernel module.");
    return EXIT_FAILURE;
  }

  qDebug() << "starting packet receiver";

  PacksReceiver packsReceiver;
  packsReceiver.start();

  int exitCode = EXIT_FAILURE;

  {
    qDebug() << "starting ui";

    MainWindow window(nullptr, netlinkManager, packsReceiver);

    window.setWindowFlags((window.windowFlags() | Qt::CustomizeWindowHint) &
                          ~Qt::WindowMaximizeButtonHint);
    window.show();

    exitCode = application.exec();
  }

  // MainWindow и его anomaly readers уже уничтожены.
  // После этого можно безопасно остановить backend.
  packsReceiver.stop();

  return exitCode;

  // Здесь MainWindow и его anomaly reader уже уничтожены.
  // Никто больше не может вызвать NetLinkManager.
  // Сам NetLinkManager будет уничтожен при выходе из main().

  return exitCode;
}

bool checkModLoaded() {
  FILE *fd = popen("lsmod | grep ads_netfilter", "r");

  char buf[16];

  if (fread(buf, 1, sizeof(buf), fd) >
      0)  // if there is some result the module must be loaded
    return true;
  else
    return false;

  return false;
}
