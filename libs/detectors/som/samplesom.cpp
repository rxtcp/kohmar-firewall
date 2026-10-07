#include "samplesom.h"

#include <fstream>

SampleSom::SampleSom(int _dimension) : Neuron(_dimension) {}

QList<SampleSom*> SampleSom::loadFromFile(const QString& fileName) {
  QMessageBox msgBox;
  QList<SampleSom*> result;

  const QByteArray nativeFileName = QFile::encodeName(fileName);

  std::fstream file{nativeFileName.constData(), std::ios::in};

  if (!file.is_open()) {
    msgBox.setText(
        QStringLiteral("The file containing the training sample "
                       "for the traffic flow system cannot be opened:\n") +
        fileName);
    msgBox.exec();
    return result;
  }

  int dimension = 0;

  if (!(file >> dimension) || dimension <= 0) {
    msgBox.setText(QStringLiteral("Invalid SOM sample dimension in:\n") +
                   fileName);
    msgBox.exec();
    return result;
  }

  constexpr int maxSamples = 100000;
  int loadedSamples = 0;
  double anomaly = 0.0;

  while (loadedSamples < maxSamples && file >> anomaly) {
    auto* sample = new SampleSom(dimension);
    sample->setAnomaly(anomaly);

    bool validSample = true;

    for (int index = 0; index < dimension; ++index) {
      double coefficient = 0.0;

      if (!(file >> coefficient)) {
        validSample = false;
        break;
      }

      sample->setKoeff(index, coefficient);
    }

    if (!validSample) {
      delete sample;
      qDeleteAll(result);
      result.clear();

      msgBox.setText(QStringLiteral("Invalid SOM sample data in:\n") +
                     fileName);
      msgBox.exec();

      return result;
    }

    result.append(sample);
    ++loadedSamples;
  }

  return result;
}
