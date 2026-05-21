/**
 * @file buf_provider.h
 * @brief MongoDB 异步 I/O 缓冲区抽象与提供者接口
 * @author galay-mongo
 * @version 1.0.0
 *
 * @details 定义 galay-mongo 异步客户端使用的缓冲区抽象层，包括：
 * - MongoBufferProvider：缓冲区提供者的抽象接口
 * - MongoRingBufferProvider：基于 RingBuffer 的具体实现
 * - MongoBufferHandle：持有 shared_ptr 的缓冲区句柄，方便值语义传递
 */

#ifndef GALAY_MONGO_BUFFER_PROVIDER_H
#define GALAY_MONGO_BUFFER_PROVIDER_H

#include <galay-kernel/common/buffer.h>

#include <cstddef>
#include <memory>
#include <sys/uio.h>

namespace galay::mongo
{

/**
 * @brief MongoDB 缓冲区提供者的抽象接口
 * @details 定义 scatter-gather I/O 所需的缓冲区操作，供异步客户端进行读写
 */
class MongoBufferProvider
{
public:
    virtual ~MongoBufferProvider() = default;

    /**
     * @brief 获取可写区域的 iovec 描述符（用于 readv）
     * @param out 输出 iovec 数组
     * @param max_iovecs 数组容量；最多使用 2 个槽位
     * @return 填充的 iovec 条目数
     */
    virtual size_t getWriteIovecs(struct iovec* out, size_t max_iovecs = 2) = 0;

    /**
     * @brief 获取可读区域的 iovec 描述符（用于 writev）
     * @param out 输出 iovec 数组
     * @param max_iovecs 数组容量；最多使用 2 个槽位
     * @return 填充的 iovec 条目数
     */
    virtual size_t getReadIovecs(struct iovec* out, size_t max_iovecs = 2) const = 0;

    /**
     * @brief 确认已写入的字节数并推进写指针
     * @param len 已写入的字节数
     */
    virtual void produce(size_t len) = 0;

    /**
     * @brief 消费字节并推进读指针
     * @param len 要消费的字节数
     */
    virtual void consume(size_t len) = 0;

    /**
     * @brief 清空缓冲区（重置读写指针，不释放内存）
     */
    virtual void clear() = 0;
};

/**
 * @brief 基于环形缓冲区的 MongoBufferProvider 实现
 * @details 使用 galay::kernel::RingBuffer 作为底层存储，提供固定容量的环形缓冲区
 */
class MongoRingBufferProvider final : public MongoBufferProvider
{
public:
    /**
     * @brief 构造指定容量的环形缓冲区提供者
     * @param capacity 缓冲区大小（字节）
     */
    explicit MongoRingBufferProvider(size_t capacity);

    size_t getWriteIovecs(struct iovec* out, size_t max_iovecs = 2) override;
    size_t getReadIovecs(struct iovec* out, size_t max_iovecs = 2) const override;
    void produce(size_t len) override;
    void consume(size_t len) override;
    void clear() override;

private:
    galay::kernel::RingBuffer m_buffer;  ///< 底层环形缓冲区
};

/**
 * @brief 缓冲区句柄，通过 shared_ptr 持有 MongoBufferProvider
 * @details 提供值语义的缓冲区访问，支持拷贝和移动。所有操作委托给内部 provider。
 */
class MongoBufferHandle
{
public:
    /**
     * @brief 构造缓冲区句柄
     * @param capacity 缓冲区容量，当 provider 为 nullptr 时用于创建默认 RingBuffer
     * @param provider 自定义缓冲区提供者；为 nullptr 时自动创建 MongoRingBufferProvider
     */
    explicit MongoBufferHandle(size_t capacity = galay::kernel::RingBuffer::kDefaultCapacity,
                               std::shared_ptr<MongoBufferProvider> provider = nullptr);

    MongoBufferHandle(const MongoBufferHandle&) = default;                ///< 拷贝构造
    MongoBufferHandle& operator=(const MongoBufferHandle&) = default;     ///< 拷贝赋值
    MongoBufferHandle(MongoBufferHandle&&) noexcept = default;            ///< 移动构造
    MongoBufferHandle& operator=(MongoBufferHandle&&) noexcept = default; ///< 移动赋值
    ~MongoBufferHandle() = default;                                       ///< 析构函数

    /**
     * @brief 获取可写区域的 iovec 描述符（用于 readv）
     * @param out 输出 iovec 数组
     * @param max_iovecs 数组容量
     * @return 填充的 iovec 条目数
     */
    size_t getWriteIovecs(struct iovec* out, size_t max_iovecs = 2)
    {
        return m_provider->getWriteIovecs(out, max_iovecs);
    }

    /**
     * @brief 获取可读区域的 iovec 描述符（用于 writev）
     * @param out 输出 iovec 数组
     * @param max_iovecs 数组容量
     * @return 填充的 iovec 条目数
     */
    size_t getReadIovecs(struct iovec* out, size_t max_iovecs = 2) const
    {
        return m_provider->getReadIovecs(out, max_iovecs);
    }

    void produce(size_t len) { m_provider->produce(len); }  ///< 确认已写入 len 字节
    void consume(size_t len) { m_provider->consume(len); }  ///< 消费 len 字节
    void clear() { m_provider->clear(); }                   ///< 清空缓冲区

    MongoBufferProvider& provider() { return *m_provider; }              ///< 获取底层 provider 的可变引用
    const MongoBufferProvider& provider() const { return *m_provider; }  ///< 获取底层 provider 的只读引用

    /**
     * @brief 获取底层 provider 的 shared_ptr
     * @return provider 的共享指针
     */
    std::shared_ptr<MongoBufferProvider> shared() const { return m_provider; }

private:
    std::shared_ptr<MongoBufferProvider> m_provider;  ///< 底层缓冲区提供者
};

} // namespace galay::mongo

#endif // GALAY_MONGO_BUFFER_PROVIDER_H
