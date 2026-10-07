#ifndef SAMPLESOM_H
#define SAMPLESOM_H

#include <stdio.h>

#include <QDebug>
#include <QFile>
#include <QMessageBox>
#include <QObject>
#include <QTextStream>
#include <QXmlStreamReader>

#include "neuron.h"

class SampleSom : public Neuron {
  Q_OBJECT

 public:
  explicit SampleSom(int _dimension);

  [[nodiscard]] static QList<SampleSom*> loadFromFile(const QString& fileName);

 signals:

 public slots:
};

#endif  // SAMPLESOM_H
