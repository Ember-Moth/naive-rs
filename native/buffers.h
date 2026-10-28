#ifndef NAIVE_RS_BUFFERS_H_
#define NAIVE_RS_BUFFERS_H_

#include "base/containers/span.h"
#include "base/memory/ref_counted.h"
#include "naive_rs/include/naive.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"

struct naive_buffer : base::RefCountedThreadSafe<naive_buffer> {
  explicit naive_buffer(size_t size);
  scoped_refptr<net::IOBufferWithSize> io;
  const size_t capacity;

 private:
  friend class base::RefCountedThreadSafe<naive_buffer>;
  ~naive_buffer();
};

namespace naive {
inline constexpr size_t kMaxIO = 64 * 1024;

class OwnedIOBuffer final : public net::IOBuffer {
 public:
  OwnedIOBuffer(uint8_t* data,
                size_t capacity,
                void* context,
                naive_owned_callback completed);
  void Complete(int result, size_t transferred);

 private:
  ~OwnedIOBuffer() override;
  void* context_;
  naive_owned_callback completed_;
  int result_ = net::ERR_ABORTED;
  size_t transferred_ = 0;
  bool finished_ = false;
};
}  // namespace naive
#endif
