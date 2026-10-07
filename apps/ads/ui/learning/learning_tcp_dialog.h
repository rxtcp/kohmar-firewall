#ifndef LEARNING_TCP_DIALOG_H
#define LEARNING_TCP_DIALOG_H

#include <QDialog>
#include <QMessageBox>

#include "engine/packsreceiver.h"
#include "engine/structs.h"
#include "platform/paths/RuntimePaths.h"

namespace Ui {
class LearningTcpDialog;
}

class LearningTcpDialog : public QDialog {
  Q_OBJECT

 public:
  explicit LearningTcpDialog(QWidget* parent, PacksReceiver& packsReceiver,
                             const firewall::RuntimePaths& paths);

  ~LearningTcpDialog();

 private slots:

  void on_pushButton_clicked();

  void on_pushButton_2_clicked();

  void on_pushButton_3_clicked();

 private:
  Ui::LearningTcpDialog* ui;
  int learned_protocol;
  bool isLearn;
  PacksReceiver& packs_receiver;
  const firewall::RuntimePaths& paths;

  void closeEvent(QCloseEvent* event);
};

#endif  // LEARNING_TCP_DIALOG_H
