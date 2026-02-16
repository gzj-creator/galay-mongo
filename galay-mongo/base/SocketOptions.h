#ifndef GALAY_MONGO_BASE_SOCKET_OPTIONS_H
#define GALAY_MONGO_BASE_SOCKET_OPTIONS_H

#include <cstdint>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>

namespace galay::mongo
{

inline void trySetTcpNoDelay(int fd, bool enabled)
{
    if (fd < 0) {
        return;
    }
    const int value = enabled ? 1 : 0;
    (void)::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
}

inline void trySetSocketTimeoutMs(int fd, uint32_t timeout_ms)
{
    if (fd < 0 || timeout_ms == 0) {
        return;
    }

    struct timeval tv{};
    tv.tv_sec = static_cast<decltype(tv.tv_sec)>(timeout_ms / 1000);
    tv.tv_usec = static_cast<decltype(tv.tv_usec)>((timeout_ms % 1000) * 1000);
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

} // namespace galay::mongo

#endif // GALAY_MONGO_BASE_SOCKET_OPTIONS_H
