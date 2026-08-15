

#include "log.h"
#include "msquic.h"
#include "stream.h"
#include "quic.h"
#include "session.h"


int stream_send(stream_t *stream, uint8_t *buf, size_t len)
{
    assert(stream);
    session_t *session = stream->session;
    assert(session);
    SERVER_QUIC_CONTEXT* MsQuic = stream->session->MsQuic;
    assert(MsQuic);

    uint8_t *out_buf = (uint8_t*)malloc(len);
    if (out_buf == NULL) {
        MsQuic->Api->StreamShutdown(
                stream->StreamHandle, 
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 
                0);
        return -ENOMEM;
    }
    memcpy(out_buf, buf, len);

    QUIC_BUFFER* quic_buf = malloc(sizeof(QUIC_BUFFER));
    quic_buf->Buffer = out_buf;
    quic_buf->Length = (uint32_t)len;

    QUIC_STATUS Status = MsQuic->Api->StreamSend(
        stream->StreamHandle,
        quic_buf,
        1,
        QUIC_SEND_FLAG_NONE,
        quic_buf
    );

    if (QUIC_FAILED(Status)) {
        LOG_ERROR("StreamSend failed, 0x%x", Status);
        free(quic_buf->Buffer);
        free(quic_buf);
        MsQuic->Api->StreamShutdown(
            stream->StreamHandle, 
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 
            0
        );
        return -ECANCELED;
    }
    return 0;
}