#include "MongoBufferProvider.h"

namespace galay::mongo
{

MongoRingBufferProvider::MongoRingBufferProvider(size_t capacity)
    : m_buffer(capacity)
{
}

size_t MongoRingBufferProvider::getWriteIovecs(struct iovec* out, size_t max_iovecs)
{
    return m_buffer.getWriteIovecs(out, max_iovecs);
}

size_t MongoRingBufferProvider::getReadIovecs(struct iovec* out, size_t max_iovecs) const
{
    return m_buffer.getReadIovecs(out, max_iovecs);
}

void MongoRingBufferProvider::produce(size_t len)
{
    m_buffer.produce(len);
}

void MongoRingBufferProvider::consume(size_t len)
{
    m_buffer.consume(len);
}

void MongoRingBufferProvider::clear()
{
    m_buffer.clear();
}

MongoBufferHandle::MongoBufferHandle(size_t capacity,
                                     std::shared_ptr<MongoBufferProvider> provider)
{
    if (provider) {
        m_provider = std::move(provider);
    } else {
        m_provider = std::make_shared<MongoRingBufferProvider>(capacity);
    }
}

} // namespace galay::mongo
