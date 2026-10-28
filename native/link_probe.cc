#include "naive_rs/include/naive.h"
int main() {
  auto volatile create = &naive_engine_create;
  auto volatile http = &naive_browser_http;
  auto volatile websocket = &naive_browser_websocket;
  return create && http && websocket && naive_abi_version() == 6 ? 0 : 1;
}
