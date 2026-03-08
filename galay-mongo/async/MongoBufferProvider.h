#ifndef GALAY_MONGO_BUFFER_PROVIDER_H
#define GALAY_MONGO_BUFFER_PROVIDER_H

#include <galay-kernel/common/Buffer.h>

#include <cstddef>
#include <memory>
#include <sys/uio.h>

namespace galay::mongo
{

class MongoBufferProvider
{
public:
    virtual ~MongoBufferProvider() = default;

    virtual size_t getWriteIovecs(struct iovec* out, size_t max_iovecs = 2) = 0;
    virtual size_t getReadIovecs(struct iovec* out, size_t max_iovecs = 2) const = 0;
    virtual void produce(size_t len) = 0;
    virtual void consume(size_t len) = 0;
    virtual void clear() = 0;
};

class MongoRingBufferProvider final : public MongoBufferProvider
{
public:
    explicit MongoRingBufferProvider(size_t capacity);

    size_t getWriteIovecs(struct iovec* out, size_t max_iovecs = 2) override;
    size_t getReadIovecs(struct iovec* out, size_t max_iovecs = 2) const override;
    void produce(size_t len) override;
    void consume(size_t len) override;
    void clear() override;

private:
    galay::kernel::RingBuffer m_buffer;
};

class MongoBufferHandle
{
public:
    explicit MongoBufferHandle(size_t capacity = galay::kernel::RingBuffer::kDefaultCapacity,
                               std::shared_ptr<MongoBufferProvider> provider = nullptr);

    MongoBufferHandle(const MongoBufferHandle&) = default;
    MongoBufferHandle& operator=(const MongoBufferHandle&) = default;
    MongoBufferHandle(MongoBufferHandle&&) noexcept = default;
    MongoBufferHandle& operator=(MongoBufferHandle&&) noexcept = default;
    ~MongoBufferHandle() = default;

    size_t getWriteIovecs(struct iovec* out, size_t max_iovecs = 2)
    {
        return m_provider->getWriteIovecs(out, max_iovecs);
    }

    size_t getReadIovecs(struct iovec* out, size_t max_iovecs = 2) const
    {
        return m_provider->getReadIovecs(out, max_iovecs);
    }

    void produce(size_t len) { m_provider->produce(len); }
    void consume(size_t len) { m_provider->consume(len); }
    void clear() { m_provider->clear(); }

    MongoBufferProvider& provider() { return *m_provider; }
    const MongoBufferProvider& provider() const { return *m_provider; }
    std::shared_ptr<MongoBufferProvider> shared() const { return m_provider; }

private:
    std::shared_ptr<MongoBufferProvider> m_provider;
};

} // namespace galay::mongo

#endif // GALAY_MONGO_BUFFER_PROVIDER_H
