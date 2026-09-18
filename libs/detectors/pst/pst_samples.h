/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef SAMPLES_H
#define SAMPLES_H

#include <stdio.h>
#include <string.h>

#include <vector>

#include "pst_common.h"

class Samples {
 private:
  std::vector<char *> samples;

 public:
  Samples();

  void add(char *smp);

  BYTE getElem(int sampleIndex, int index);

  int sizeSample(int sampleIndex);

  int sizeAll();

  int numOfSamples();

  int loadFromFile(const char *filename);

  char *getSample(int index);
};

#endif  // SAMPLES_H
