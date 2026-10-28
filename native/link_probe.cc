#include "naive_rs/include/naive.h"
int main() {
  return naive_abi_version() == 3 ? 0 : 1;
}
