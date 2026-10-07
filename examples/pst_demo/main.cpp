#include <cstdlib>
#include <cstring>
#include <iostream>

#include "detectors/pst/pst_predictor.h"
#include "detectors/pst/pst_samples.h"

int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: pst_demo <samples-file>\n";
    return EXIT_FAILURE;
  }

  Samples samples;

  const int maxLength = samples.loadFromFile(argv[1]);

  if (maxLength < 0) {
    std::cerr << "Cannot load samples file: " << argv[1] << '\n';
    return EXIT_FAILURE;
  }

  PstPredictor predictor;

  predictor.init(256, 0.0001, 2, 0.000001, 2, maxLength, 1);

  predictor.learn(&samples);

  std::cout << "\nLearned!";

  char sequence[] = "13R";

  double logEvaluation = predictor.logEval(sequence);
  std::cout << "\nlogEval = " << logEvaluation;

  predictor.retrainForSeq(sequence);

  logEvaluation = predictor.logEval(sequence);
  std::cout << "\nafter_retrain_logEval = " << logEvaluation << '\n';

  return EXIT_SUCCESS;
}