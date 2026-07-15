#pragma once
#include <boost/lockfree/spsc_queue.hpp>
#include <memory>

namespace storage {

enum class EventType {
    FLOW_CLOSED,
    ALERT_FIRED,
    DNS_TRANSACTION,
    HTTP_TRANSACTION,
    METRICS_SNAPSHOT,
    SESSION_STARTED
};

// We store raw pointers in the lock-free queue because boost::lockfree requires
// trivially copyable types. Ownership is transferred via shared_ptr on the
// slow path (serialization thread), not the hot enqueue path.
struct StorageEvent {
    EventType type;
    void*     data_ptr = nullptr;    // raw pointer into the shared_ptr's block
    void*     shared_block = nullptr; // opaque handle — cast back by BatchWriter
};

// ── WriteQueue ────────────────────────────────────────────────────────────────
// Single-producer single-consumer. The CaptureApi event callbacks are the
// single producer; BatchWriter is the single consumer.
// StorageEvent is 24 bytes and trivially copyable — safe for lockfree queue.
static_assert(std::is_trivially_copyable_v<StorageEvent>,
              "StorageEvent must be trivially copyable for boost::lockfree::spsc_queue");

// 100,000 capacity. At 10,000 flows/sec, gives 10 seconds of headroom.
using WriteQueue = boost::lockfree::spsc_queue<StorageEvent, boost::lockfree::capacity<100000>>;

} // namespace storage
