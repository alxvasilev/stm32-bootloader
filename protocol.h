#ifndef BOOTLOADER_PROTOCOL_H
#define BOOTLOADER_PROTOCOL_H

#include <stdint.h>
#define BOOTLOADER_UART_BITRATE 115200

enum {
    ERR_ASSERT = 0x01,
    ERR_INVAL = 0x02,
    ERR_NOMEM = 0x03,
    ERR_ADDR = 0x04,
    ERR_ERASE = 0x05,
    ERR_VERIFY = 0x06,
    ERR_ERASE_VERIFY =0x07,
    ERR_CRC = 0x08,
    ERR_TOOBIG = 0x09,
    ERR_SIZE = 0x0a,
    ERR_UNKNOWN = 0x0b,
    ERR_TIMEOUT = 0xff
};

enum {
    CMD_HELLO = 0x2E,
    CMD_PING = 0x01,
    CMD_PONG = 0x02,
    CMD_WRITE_DATA = 0x03,
    CMD_BOOT = 0x04,
    CMD_SESSION = 0x05,
    CMD_DEVICEINFO = 0x06,
    CMD_WRITE_PAGE_ACK = 0x07,
    CMD_DUMP = 0x08,
    CMD_SETBITRATE = 0x09,
    CMD_FLAG_NACK = 0x80
};
enum { kMaxRecvBufSize = 10240 };
struct DeviceInfo {
    uint16_t bldrVersion;
    uint16_t chipId;
    uint32_t writableFlashStart;
    uint32_t appFlashAddr;
    uint16_t flashPageSize;
    uint16_t flashSize;
    uint16_t bldrSize;
    uint16_t padding1;
    uint32_t crc;
};

struct ChunkInfo
{
    uint32_t startAddr;
    uint32_t dataSize;
    uint16_t id;
    uint16_t reserved;
    uint32_t crc;
};
struct WriteChunkPacket
{
    struct ChunkInfo header;
    uint16_t data[kMaxRecvBufSize / 2];
};

#endif // PROTOCOL_H
