#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <assert.h>
#include <stdexcept>
#include <alloca.h>
#include "protocol.h"

enum { kRecvTimeout = 2000 };
uint16_t gRecvTimeoutMs = kRecvTimeout;

static_assert(sizeof(DeviceInfo) == 24, "");
DeviceInfo gDeviceInfo;

int ttyConfig(int fd, int speed, int parity)
{
    struct termios tty;
    memset(&tty, 0, sizeof tty);
    if (tcgetattr(fd, &tty) != 0)
    {
        perror("tcgetattr");
        return -1;
    }

    cfsetospeed(&tty, speed);
    cfsetispeed(&tty, speed);

    tty.c_cflag &= ~(CSIZE | PARENB | PARODD | CRTSCTS);      // shut off parity
    tty.c_cflag |= (CS8 | CSTOPB | CLOCAL | CREAD | parity);// ignore modem controls, enable reading

    // disable IGNBRK for mismatched speed tests; otherwise receive break
    // as \000 chars
    tty.c_lflag = 0;                // no signaling chars, no echo, no canonical processing
    tty.c_oflag = 0;                // no remapping, no delays
    tty.c_iflag &= ~(IGNBRK | BRKINT | ICRNL | INLCR | PARMRK | INPCK | ISTRIP | IXON | IXOFF | IXANY);

    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSANOW, &tty) != 0)
    {
        perror("tcsetattr");
        return -1;
    }
    return 0;
}
int ttyOpen(const char* fname, int speed, int parity)
{
    int fd = open(fname, O_RDWR | O_NOCTTY | O_SYNC | O_NDELAY | O_NONBLOCK);
    if (fd < 0)
    {
        perror("Error opening tty file");
        return -1;
    }
    if(!isatty(fd)) {
        close(fd);
        printf("Device file is not a tty\n");
        return -1;
    }
    int err = ttyConfig(fd, speed, parity);
    if (err) {
        close(fd);
        return -1;
    }
    return fd;
}
int ttyFd = -1;

uint64_t getTimestampMs()
{
    struct timespec t;
    int ret = clock_gettime(CLOCK_MONOTONIC_RAW, &t);
    if (ret < 0) {
        perror("ttyReadBuf: clock_gettime");
        return 0;
    }
    return (t.tv_sec * 1000) + (t.tv_nsec / 1000000);
}

void throwErrno(const char* operation, const char* call=nullptr)
{
    assert(operation);
    const char* errStr = strerror(errno);
    if (!errStr) {
        errStr = "(unknown error)";
    }
    std::string msg(operation);
    if (call) {
        msg.append(": ").append(call).append(": ").append(errStr);
    } else {
        msg.append(": ").append(errStr);
    }
    throw std::runtime_error(msg);
}
uint8_t recvByteTimeout(const char* op)
{
    struct pollfd pfd;
    pfd.fd = ttyFd;
    pfd.events = POLLIN;
    uint8_t byte;
    for(;;) {
        int n = read(ttyFd, &byte, 1);
        if (n < 0) {
            if (errno == EAGAIN) {
                usleep(100);
                continue;
            } else {
                throwErrno(op, "read");
            }
        } else if (n > 0) {
            assert(n == 1);
            return byte;
        }
        int ret = poll(&pfd, 1, gRecvTimeoutMs);
        if (ret < 0) {
            throwErrno(op, "poll");
        } else if (ret == 0) {
            throw std::runtime_error(op +std::string(": recvByteTimeout: Timeout"));
        }
    }
}

void recvBufTimeout(void* aBuf, int bufsize, const char* operation)
{
    assert(operation);
    struct pollfd pfd;
    pfd.fd = ttyFd;
    pfd.events = POLLIN;
    uint8_t* buf = (uint8_t*)aBuf;
    for(;;) {
        int ret = poll(&pfd, 1, gRecvTimeoutMs);
        if (ret < 0) {
            throwErrno(operation, "poll");
        } else if (ret == 0) {
            throw std::runtime_error(std::string(operation) +": Receive buffer timeout");
        }
        int n = read(ttyFd, buf, bufsize);
        if (n < 0) {
            if (errno == EAGAIN) {
                usleep(1000);
                continue;
            } else {
                throwErrno(operation, "read");
            }
        } else if (n > 0) {
            buf += n;
            bufsize -= n;
            if (bufsize <= 0) {
                assert(bufsize == 0);
                return;
            }
        } else {
            usleep(1000);
        }
    }
}

void sendByte(uint8_t byte, const char* op)
{
    int ret = write(ttyFd, &byte, 1);
    if (ret < 0) {
        throwErrno(op, "write");
    } else if (ret == 0) {
        throw std::runtime_error(std::string(op) + ": sendByte: write() returned zero");
    }
    assert(ret == 1);
}

void sendBuf(const void* aBuf, size_t bufsize, const char* op)
{
    uint8_t* buf = (uint8_t*)aBuf;
    for (;;)
    {
        int ret = write(ttyFd, buf, bufsize);
        if (ret > 0) {
            if (ret == bufsize) {
                return;
            }
            assert(ret < bufsize);
            buf += ret;
            bufsize -= ret;
        } else if ((ret < 0) && (errno != EAGAIN)) {
            throwErrno(op, "write");
        }
        usleep(10000);
    }
}

void term(int)
{
    printf("Ctrl+C\n");
}
uint32_t crcAddWord(uint32_t curr, uint32_t data)
{
    const uint32_t poly =  0x4C11DB7;
    curr ^= data;
    for (uint8_t bindex = 0; bindex < 32; bindex++) {
        if (curr & 0x80000000) {
            curr = (curr << 1) ^ poly;
        } else {
            curr <<= 1;
        }
    }
    return curr;
}

void printDeviceInfo(const DeviceInfo& info)
{
    printf("Device info:\n"
           "\tbootloader version:   0x%04x\n"
           "\tbootloader size:      %u bytes\n"
           "\tchip id:              0x%04x\n"
           "\tflash size:           %d KiB\n"
           "\twritable flash start: 0x%08x\n"
           "\tapp flash addr:       0x%08x\n"
           "\tflash page size:      %u bytes\n",
           info.bldrVersion, info.bldrSize, info.chipId, info.flashSize,
           info.writableFlashStart, info.appFlashAddr, info.flashPageSize);
}

uint32_t calculateBufCRC(const void* aBuf, size_t bufsize)
{
    uint32_t result = 0XFFFFFFFF;
    uint32_t* buf = (uint32_t*)aBuf;
    uint32_t* bufEnd = buf + bufsize / 4;
    for (; buf < bufEnd; buf++) {
        result = crcAddWord(result, *buf);
    }
    uint8_t remain = (bufsize % 4);
    if (remain) {
        uint32_t data = 0;
        memcpy(&data, (uint8_t*)bufEnd, remain);
        result = crcAddWord(result, data);
    }
    return result;
}

void recvDeviceInfo()
{
    recvBufTimeout(&gDeviceInfo, sizeof(gDeviceInfo), "recvDeviceInfo");
    uint32_t crc = calculateBufCRC(&gDeviceInfo, sizeof(gDeviceInfo) - 4);
    if (crc != gDeviceInfo.crc) {
        printf("device info CRC mismatch: expected %08x, got: %08x\n", crc, gDeviceInfo.crc);
        throw std::runtime_error("recvDeviceInfo: Device info CRC mismatch");
    }
    printDeviceInfo(gDeviceInfo);
}
void sendRecvSession()
{
    uint32_t txUid = (rand() << 16) | rand();
    sendByte(CMD_SESSION, "send session");
    sendBuf(&txUid, sizeof(txUid), "send session uid");
    for (;;) {
        printf("receiving CMD_SESSION\n");
        uint8_t cmd = recvByteTimeout("recv cmd session");
        if (cmd != CMD_SESSION) {
            continue;
        }
        printf("CMD_SESSION received, reading id\n");

        uint32_t rxUid;
        recvBufTimeout(&rxUid, sizeof(rxUid), "recv session uid");
        if (txUid != rxUid) {
            printf("sendRecvSession: Received CMD_SESSION response, but with different uid\n"
                                     "expected: %08x, got: %08x\n", txUid, rxUid);
            throw std::runtime_error("sendRecvSession: Received CMD_SESSION response, but with different uid");
        } else {
            return;
        }
    }
}

uint8_t doHello()
{
    char buf[16];
    for (;;) { // drain input buffer
        int n = read(ttyFd, buf, 16);
        if (n == 0) {
            break;
        } else if (n < 0) {
            if (errno == EAGAIN) {
                usleep(100);
                continue;
            } else {
                throwErrno("doHello", "read");
            }
        }
    }
    printf("Waiting for bootloader...\n");
    const uint8_t hello = CMD_HELLO;
    const uint8_t ping = CMD_PING;
    uint8_t in = 0;
    for(uint32_t i = 0; i < 1000000; i++) {
        int n = write(ttyFd, (i == 2) ? &ping : &hello, 1);
        if (n < 0) {
            if (errno == EAGAIN) {
                usleep(100);
            } else {
                throwErrno("doHello", "write");
            }
        } else if (n == 1) {
            printf(".");
            fflush(stdout);
        }
        struct pollfd pfd;
        pfd.fd = ttyFd;
        pfd.events = POLLIN;
        n = poll(&pfd, 1, 10);
        if (n == 1) {
            n = read(ttyFd, &in, 1);
            if (n < 0) {
                if (errno == EAGAIN) {
                    continue;
                }
                throwErrno("doHello", "read");
            } else if (n == 0) {
                continue;
            }
            assert(n == 1);
            switch (in)
            {
            case CMD_HELLO:
                printf("Bootloader responded with HELLO\n");
                return CMD_HELLO;
            case CMD_PONG:
                if (i < 2) { // we haven't sent PING yet
                    printf("PONG received, but we haven't yet sent PING, ignoring\n");
                    continue;
                }
                printf("Bootloader reseponded with CMD_PONG\n");
                return CMD_PONG;
            default:
                printf("\nBootloader responded with incorrect code %x, continuing to listen\n", in);
                continue;
            }
        } else if (n < 0) {
            if (errno != EAGAIN) {
                throwErrno("doHello", "poll");
            }
        }
        //usleep(100000);
    }
    throw std::runtime_error("doHello: Timeout");
}

void handshake()
{
    uint8_t ret = doHello();
    // ret is either CMD_HELLO or CMD_PONG
    if (ret == CMD_PONG) {
//      sendRecvSession();
        sendByte(CMD_DEVICEINFO, "send CMD_DEVICEINFO");
        while ((ret = recvByteTimeout("recv CMD_DEVICEINFO")) != CMD_DEVICEINFO) {
            printf("expecting CMD_DEVICEINFO, received %02x\n", ret);
        }
    }
    recvDeviceInfo();
}

void sendBootCommand()
{
    printf("Booting device...");
    sendByte(CMD_BOOT, "send CMD_BOOT");
    while (recvByteTimeout("recv CMD_BOOT ack") != CMD_BOOT);
    printf("acknowledged\n");
}

void handleWriteCommand(const char* fname, uint32_t addr)
{
    if (addr != gDeviceInfo.appFlashAddr) {
        printf("Specified offset of firmware is different than the jump address the bootloader uses");
        return;
    }
    int fd = open(fname, O_RDONLY);
    if (fd < 0) {
        perror("Open firmware file");
        return;
    }
    WriteChunkPacket packet;
    for(int id = 0;; id++) {
        enum { kReadSize = kMaxRecvBufSize };
        int n = read(fd, packet.data, kReadSize);
        if (n < 0) {
            perror("read firmware file");
            goto cleanup;
        }
        if (n == 0) {
            goto cleanup;
        }
        packet.header.dataSize = n;
        packet.header.startAddr = addr;
        packet.header.id = id;
        packet.header.crc = calculateBufCRC(&packet, sizeof(packet.header)-sizeof(packet.header.crc));
        uint32_t dataCrc = calculateBufCRC(packet.data, n);
        sendByte(CMD_WRITE_DATA, "send CMD_WRITE_DATA");
        sendBuf(&packet, sizeof(packet.header) + n, "Send write chunk data");
        sendBuf(&dataCrc, sizeof(dataCrc), "send write chunk CRC");
        for (;;) {
            auto ch = recvByteTimeout("recv CMD_WRITE_DATA ack");
            if (ch == CMD_WRITE_PAGE_ACK) {
                printf(".");
                fflush(stdout);
            } else if (ch == CMD_WRITE_DATA) {
                break;
            }
        }
        printf("\n");
        uint16_t writeId;
        recvBufTimeout(&writeId, sizeof(writeId), "recv write id");
        if (writeId != packet.header.id) {
            printf("Write id doesn't match in the write ACK response");
            goto cleanup;
        }
        if (n < kReadSize) {
            printf("Flash write complete\n");
            return;
        }
        addr += n;
    }
cleanup:
        close(fd);
}
void handleDumpCommand(const char* fname, uint32_t addr, uint32_t size)
{
    ChunkInfo info;
    info.startAddr = addr;
    info.dataSize = size;
    info.id = 0;
    info.crc = calculateBufCRC(&info, sizeof(info) - sizeof(info.crc));
    sendByte(CMD_DUMP, "recv CMD_DUMP");
    sendBuf(&info, sizeof(info), "send CMD_DUMP parameters");
    auto ch = recvByteTimeout("recv CMD_DUMP reply");
    if (ch != CMD_DUMP) {
        throw std::runtime_error("Invalid response received to CMD_DUMP");
    }
    uint16_t dumpId;
    recvBufTimeout(&dumpId, sizeof(dumpId), "recv id from CMD_DUMP response");
    if (dumpId != 0) {
        throw std::runtime_error("Received dump id mismatch");
    }
    void* buf = alloca(size);
    if (!buf) {
        throw std::runtime_error("Error allocating receive buf");
    }
    printf("Receiving data....\n");
    recvBufTimeout(buf, size, "Recv CMD_DUMP data");
    printf("Received data\n");
    uint32_t crc;
    recvBufTimeout(&crc, sizeof(crc), "Recv CMD_DUMP CRC");
    if (calculateBufCRC(buf, size) != crc) {
        throw std::runtime_error("Dump data CRC verification failed");
    }
    int fd = open(fname, O_WRONLY | O_TRUNC | O_CREAT, 0644);
    if (fd < 0) {
        throw std::runtime_error("Error opening '" + std::string(fname) + "' file for writing");
    }
    int ret = write(fd, buf, size);
    close(fd);
    if (ret < 0) {
        throwErrno("Write dump to file", "write");
    } else if (ret < size) {
        throw std::runtime_error("Wrote less bytes " + std::to_string(ret) + " to dump file");
    }
}

int main(int argc, char* argv[])
{
    printf("===========================================================\n"
           "= Bluetooth firmware flasher for BlueBoot bootloader v1.0 =\n"
           "===========================================================\n");
    if (argc < 2) {
        printf("Usage: %s <device> [<command> [args]]\n"
               "<command> can be:\n"
               "boot: boots the user firmware\n\n"
               "flash <file>: Writes the specified firmware file in .bin format\n"
               "\tand verifies it\n\n"
               "dump <file> [size]: Reads the user firmware up to the specified size\n"
               "\t and saves it to the specified file in .bin format\n\n", argv[0]
               );
        exit(1);
    }
    const char* ttyName = argv[1];
    std::string command;
    if (argc > 2) {
        command = argv[2];
    }
    signal(SIGTERM, term);
    srand(time(NULL));
    try {
    ttyFd = ttyOpen(ttyName, B38400, PARENB);  // set speed to 57600 bps, 8e1
    if (ttyFd < 0) {
        return 1;
    }
    handshake();
    if (command.empty()) {
        close(ttyFd);
        return 0;
    }
    // device is ready to receive commands
    if (command == "boot") {
        sendBootCommand();
    } else if (command == "write") {
        if (argc < 4) {
            printf("No filename specified\n");
            return 1;
        }
        if (argc < 5) {
            printf("No offset specified\n");
            return 1;
        }
        uint32_t offset = strtoul(argv[4], NULL, 16);
        printf("Sending firmware file '%s' for writing at offset %08x\n", basename(argv[3]), offset);
        gRecvTimeoutMs = 4000;
        handleWriteCommand(argv[3], offset);
        if (argc >= 6 && argv[5] == std::string("boot")){
            sendBootCommand();
        }
    } else if (command == "dump") {
        if (argc < 4) {
            printf("No filename specified\n");
            return 1;
        }
        if (argc < 5) {
            printf("No address specified\n");
            return 1;
        }
        uint32_t size = (argc < 6) ? 0 : strtoul(argv[5], NULL, 10);
        uint32_t addr = strtoul(argv[4], NULL, 16);
        handleDumpCommand(argv[3], addr, size);
    }
    } catch(std::exception& e) {
        printf("Error: %s\n", e.what());
        return 2;
    }
}
