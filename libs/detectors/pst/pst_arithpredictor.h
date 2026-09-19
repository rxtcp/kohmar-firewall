#ifndef PSTARITHPREDICTOR_H_
#define PSTARITHPREDICTOR_H_

#include "../../../PST/pst_context.h"
#include "pst_node.h"

class PstArithPredictor {
 private:
  PstNode *pst;
  Context *context;

 public:
  PstArithPredictor(PstNode *node);

  virtual ~PstArithPredictor();

  int alphabetSize();

  void increment(int symbol);

  PstNode *predict(double *prediction);
};

#endif  // PSTARITHPREDICTOR_H_
