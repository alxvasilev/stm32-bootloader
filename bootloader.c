#include <stdint.h>
#include <stddef.h>
#include <alloca.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/usart.h>
#include <libopencm3/cm3/dwt.h>
#include <libopencm3/cm3/scb.h>
#include <libopencm3/cm3/scs.h>
#include <libopencm3/stm32/flash.h>
#include <libopencm3/stm32/desig.h>
#include <libopencm3/stm32/crc.h>
#include <string.h>
#include <stdlib.h>
#include "protocol.h"

//#define DEBUG_LOGGING

#ifdef DEBUG_LOGGING
    #include <stdio.h>
    void initialise_monitor_handles();
#endif

#define BOOTLOADER_VERSION 0x0001
#define USER_APP_START 0x0800F000

# define STM32F74xxx_75xxx  0x449
# define STM32F76xxx_77xxx  0x451
# define STM32F40x_41x      0x413
# define STM32F42x_43x      0x419
# define STM32F103_LD       0x412
# define STM32F103_MD       0x410
# define STM32F103_HD       0x414
# define STM32F103_XLD      0x430
# define STM32F103_CON      0x418

#ifndef CHIP_FAMILY
    #define CHIP_FAMILY STM32F103_MD
#endif

extern char __FLASH_WRITABLE_START_ADDR[];
extern char __BOOTLOADER_END_ADDR[];
extern char __FLASH_WRITABLE_END_ADDR[];
extern char _myStack[];

enum {
    kRecvTimeoutMs = 2000,
    kHelloRecvTimeoutMs = 500,
};

#ifdef DEBUG_LOGGING
    #define LOG(fmtString,...) printf(fmtString "\n", ##__VA_ARGS__)
#else
    #define LOG(fmtString,...)
#endif

enum { kFlashWriteErrorFlags = FLASH_SR_WRPRTERR
#ifdef FLASH_SR_PGERR
| FLASH_SR_PGERR
#endif
#ifdef FLASH_SR_PGAERR
| FLASH_SR_PGAERR
#endif
#ifdef FLASH_SR_PGPERR
| FLASH_SR_PGPERR
#endif
#ifdef FLASH_SR_ERSERR
| FLASH_SR_ERSERR
#endif
};

uint16_t gRecvTimeoutMs = 0;

void ledBlink(uint8_t code);
void crashWithLedBlink(uint8_t code);
#ifndef NDEBUG
    #define assert(cond) if (!(cond)) { crashWithLedBlink(ERR_ASSERT); }
#else
    #define assert(cond)
#endif

uint16_t flashGetPageSize()
{
    return (DESIG_FLASH_SIZE < 256) ? 1024 : 2048;
}
uint32_t flashGetErrorFlags()
{
    uint32_t flags = FLASH_SR;
    if (DESIG_FLASH_SIZE > 512)
    {
        flags |= FLASH_SR2;
    }
    return flags & kFlashWriteErrorFlags;
}

void flashUnlockWrite()
{
    flash_unlock();
    if (DESIG_FLASH_SIZE > 512) {
        flash_unlock_upper();
    }
}
void flashLockWrite()
{
    flash_lock();
    if (DESIG_FLASH_SIZE > 512) {
        flash_lock_upper();
    }
}

uint8_t flashErasePage(void* page)
{
    assert(((size_t)page) % 4 == 0);
    flash_erase_page((uint32_t)page);
    uint32_t err = flashGetErrorFlags();
    if (err) {
        return ERR_ERASE;
    }
    uint32_t* pageEnd = (uint32_t*)((size_t)page + flashGetPageSize());
    for (uint32_t* ptr = (uint32_t*)page; ptr < pageEnd; ptr++)
    {
        if (*ptr != 0xffffffff)
        {
            return ERR_ERASE_VERIFY;
        }
    }
    return 0;
}

void crashWithLedBlink(uint8_t code);

static void clock_setup(void)
{
    rcc_clock_setup_in_hse_8mhz_out_72mhz();
	rcc_periph_clock_enable(RCC_GPIOA);
	rcc_periph_clock_enable(RCC_GPIOC);
    rcc_periph_clock_enable(RCC_USART1);
    rcc_periph_clock_enable(RCC_CRC);
}

static void usart_setup(void)
{
	gpio_set_mode(GPIOA, GPIO_MODE_OUTPUT_50_MHZ,
        GPIO_CNF_OUTPUT_ALTFN_PUSHPULL, GPIO_USART1_TX);

    gpio_set_mode(GPIOA, GPIO_MODE_INPUT,
        GPIO_CNF_INPUT_PULL_UPDOWN, GPIO_USART1_RX);

    gpio_set(GPIOA, GPIO_USART1_RX);

	/* Setup UART parameters. */
    usart_set_baudrate(USART1, BOOTLOADER_UART_BITRATE);
    usart_set_databits(USART1, 9);
    usart_set_stopbits(USART1, USART_STOPBITS_1);
    usart_set_mode(USART1, USART_MODE_TX_RX);
    usart_set_parity(USART1, USART_PARITY_EVEN);
    usart_set_flow_control(USART1, USART_FLOWCONTROL_NONE);

	/* Finally enable the USART. */
    usart_enable(USART1);

}

static void led_setup(void)
{
    gpio_set_mode(GPIOC, GPIO_MODE_OUTPUT_2_MHZ,
              GPIO_CNF_OUTPUT_PUSHPULL, GPIO13);
}

void sendByte(uint8_t byte)
{
    usart_send_blocking(USART1, byte);
}

void sendString(const char* str)
{
    while (*str)
    {
        usart_send_blocking(USART1, *str);
        str++;
    }
}
void sendBuf(const void* aBuf, uint32_t buflen)
{
    uint8_t* buf = (uint8_t*)aBuf;
    for(const uint8_t* end = buf + buflen; buf < end; buf++)
    {
        usart_send_blocking(USART1, *buf);
    }
}

static inline volatile uint32_t currentTicks()
{
    return (volatile uint32_t)DWT_CYCCNT;
}
/*
static inline uint32_t ticksToMs(uint32_t ticks)
{
    return ticks / (rcc_ahb_frequency/1000);
}
*/

static inline uint32_t msToTicks(uint16_t ms)
{
    uint64_t ticks = ms * ((uint64_t)rcc_ahb_frequency/1000);
    if (ticks > 0xffffffff) {
        ticks = 0xffffffff;
    }
    return ticks;
}

typedef int(*CheckFunc)();

static inline volatile int wait(uint32_t ticks, CheckFunc func)
{
#ifndef NDEBUG
    enum { kCycleOverhead = 160 }; //in debug build, the func call overhead is quite high
#else
    enum { kCycleOverhead = 16 };
#endif
    uint32_t now = currentTicks();
    if (ticks > kCycleOverhead)
        ticks -= kCycleOverhead;
    else
        ticks = 0;
    register uint32_t tsEnd = now + ticks;
    if (now > tsEnd) //will wrap
    {
        while(currentTicks() > tsEnd) {
            if (func && func()) {
                return 1;
            }
        }
    }
    while(currentTicks() < tsEnd) {
        if (func && func()) {
            return 1;
        }
    }
    return 0;
}

static inline volatile int msWait(uint16_t ms, CheckFunc func)
{
    if (func && func()) {
        return 1;
    }
    return wait(msToTicks(ms), func);
}
/*
static inline volatile int usWait(uint32_t us, CheckFunc func)
{
    if (func && func()) {
        return 1;
    }
    return wait(usToTicks(us), func);
}
*/
uint32_t calculateBufCRC(const void* aBuf, size_t bufsize)
{
    uint32_t* buf = (uint32_t*)aBuf;
    uint32_t* end = buf + (bufsize >> 2);
    CRC_CR |= CRC_CR_RESET;
    for (; buf < end; buf++) {
        CRC_DR = *buf;
    }
    uint8_t remain = bufsize % 4;
    if (remain) {
        uint32_t data = 0;
        memcpy(&data, (uint8_t*)end, remain);
        CRC_DR = data;
    }

    return CRC_DR;
}

void sendResponseWithData(uint8_t opcode, const uint8_t* buf, uint16_t bufsize)
{
    assert((opcode & 0x7f) == 0);
    sendByte(opcode);
    sendByte(bufsize & 0xff);
    sendByte(bufsize >> 8);
    sendBuf(buf, bufsize);
}

static inline int hasDataToReceive()
{
    return ((USART_SR(USART1) & USART_SR_RXNE) != 0);
}

uint16_t recvByteTimeout()
{
    if (!hasDataToReceive()) {
        if (!msWait(gRecvTimeoutMs, &hasDataToReceive)) {
            return ERR_TIMEOUT << 8;
        }
    }
    return usart_recv(USART1) & 0xff; // filter parity bit
}

uint8_t recvBufTimeout(void* aBuf, uint16_t bufsize)
{
    uint8_t* buf = (uint8_t*)aBuf;
    uint8_t* bufEnd = buf + bufsize;
    for (; buf < bufEnd; buf++) {
        uint16_t ret = recvByteTimeout();
        if (ret > 255) {
            LOG("recvButTimeout: error after recv %lu bytes", (uint32_t)buf - (uint32_t)aBuf);
            return ret >> 8;
        }
        *buf = ret & 0xff;
    }
    return 0;
}

uint8_t recvByte()
{
    return usart_recv_blocking(USART1);
}

uint8_t recvHello() {
    // first, get 2 bytes with short timeout, to see if someone is sending to us
    gRecvTimeoutMs = kHelloRecvTimeoutMs;
    uint16_t ch;
    for (int i = 0; i < 2; i++) {
        ch = recvByteTimeout();
        //LOG("rx %04x", ch);
        if (ch > 255) {
            return ch >> 8;
        }
    }
    // Obviously someone is sending to us, increase the timeout
    gRecvTimeoutMs = kRecvTimeoutMs;
    // read a number of repeating CMD_HELLO bytes. If another code breaks the sequence
    // start over
    for(;;) {
        // skip all non-hello bytes
        while(ch != CMD_HELLO) {
            ch = recvByteTimeout();
            //LOG("rx2 %04x", ch);
            if (ch > 255) {
                return ch >> 8;
            }
        }
        // read a number of repeating hello bytes
        for (uint8_t i = 0; ; i++) {
            ch = recvByteTimeout();
            //LOG("rx3 %04x", ch);

            if (ch != CMD_HELLO) {
                if (ch > 255) {
                    return (ch >> 8);
                } else {
                    break; // start over
                }
            }
            if (i >= 10) {
                return 0;
            }
        }
    }
}
void sendDeviceInfo(uint8_t cmd) {
    struct DeviceInfo info = {
        .bldrVersion = BOOTLOADER_VERSION,
        .chipId = CHIP_FAMILY,
        .flashPageSize = flashGetPageSize(),
        .writableFlashStart = (uint32_t)__FLASH_WRITABLE_START_ADDR,
        .appFlashAddr = USER_APP_START,
        .flashSize = ((uint32_t)__FLASH_WRITABLE_END_ADDR - (uint32_t)__FLASH_WRITABLE_START_ADDR) / 1024,
        .bldrSize = __BOOTLOADER_END_ADDR - __FLASH_WRITABLE_END_ADDR
    };
    info.crc = calculateBufCRC((uint32_t*)&info, sizeof(info)-sizeof(info.crc));
    sendByte(cmd);
    sendBuf((uint8_t*)&info, sizeof(info));
}

uint8_t handleWriteData()
{
    assert(sizeof(struct WriteChunkHeader) == 12);
    struct WriteChunkPacket packet;
    uint8_t err = recvBufTimeout(&packet.header, sizeof(packet.header));
    if (err) {
        return err;
    }
    if (calculateBufCRC(&packet, sizeof(packet.header)-4) != packet.header.crc) {
        LOG("Error verifying packet header CRC");
        return ERR_CRC;
    }
    uint32_t writeAddr = packet.header.startAddr;
    uint16_t dataSize = packet.header.dataSize;
    //LOG("received CMD_WRITE_DATA: startAddr = %08lx, size = %u, writeId = %lu", writeAddr, dataSize, hdr->writeId);

    if (writeAddr & 0b11) {
        return ERR_ADDR;
    }
    if (dataSize & 0b11) {
        return ERR_SIZE;
    }
    if (dataSize > kMaxRecvBufSize) {
        return ERR_TOOBIG;
    }
    if (writeAddr == 0) {
        writeAddr = USER_APP_START;
    } else {
        if (writeAddr < (uint32_t)__FLASH_WRITABLE_START_ADDR || writeAddr > (uint32_t)__FLASH_WRITABLE_END_ADDR) {
            return ERR_ADDR;
        }
    }
    err = recvBufTimeout(packet.data, dataSize);
    if (err) {
        LOG("Error receiving chunk data: %02x", err);
        return err;
    }
    uint32_t crc;
    err = recvBufTimeout(&crc, sizeof(crc));
    if (err) {
        return err;
    }
    if (calculateBufCRC(packet.data, dataSize) != crc) {
        return ERR_CRC;
    }

    uint16_t pageSize = flashGetPageSize();
    uint16_t* wptr = (uint16_t*)writeAddr;
    uint16_t* writeEnd = (uint16_t*)(writeAddr + dataSize);
    uint16_t* rptr = packet.data;

    flashUnlockWrite();
    err = flashErasePage(wptr);
    if (err) {
        flashLockWrite();
        return err;
    } else {
        LOG("Erased flash page at %p", wptr);
    }

    while(wptr < writeEnd) {
        flash_program_half_word((size_t)wptr, *rptr);
        if (*wptr != *rptr) {
            flashLockWrite();
            LOG("Write verify error at byte %lu: expected %02x, got %02x",
                (size_t)wptr - writeAddr, *rptr, *wptr);
            return ERR_VERIFY;
        }
        wptr++;
        rptr++;
        if (((size_t)wptr % pageSize) == 0) {
            err = flashErasePage(wptr);
            if (err) {
                flashLockWrite();
                return err;
            } else {
                LOG("Erased flash page at %p", wptr);
                sendByte(CMD_WRITE_PAGE_ACK);
            }
        }
    }
    flashLockWrite();
    // just in case, verify written data by CRC
    if (calculateBufCRC((void*)writeAddr, dataSize) != crc) {
        LOG("Error verifying CRC of written data");
        return ERR_CRC;
    }
    // ack the write
    sendByte(CMD_WRITE_DATA);
    sendBuf(&packet.header.id, sizeof(packet.header.id));
    return 0;
}
void ledOff()
{
    gpio_set(GPIOC, GPIO13);
}
void ledOn()
{
    gpio_clear(GPIOC, GPIO13);
}

void ledBlink(uint8_t code)
{
    ledOff();
    msWait(1000, NULL);
    for (uint8_t i = 0; i < code; i++) {
        ledOn();
        msWait(250, NULL);
        ledOff();
        msWait(250, NULL);
    }
}

void crashWithLedBlink(uint8_t code)
{
    for (;;) {
        ledBlink(code);
    }
}

void deinitDevice()
{
    ledOff();
    usart_disable(USART1);
    rcc_periph_reset_pulse(RST_USART1);
    gpio_set_mode(GPIOA, GPIO_MODE_INPUT,
        GPIO_CNF_INPUT_FLOAT, GPIO_USART1_TX);
    gpio_set_mode(GPIOA, GPIO_MODE_INPUT,
        GPIO_CNF_INPUT_FLOAT, GPIO_USART1_RX);
    gpio_set_mode(GPIOC, GPIO_MODE_INPUT,
        GPIO_CNF_INPUT_FLOAT, GPIO13);
    rcc_periph_reset_pulse(RST_GPIOA);
    rcc_periph_reset_pulse(RST_GPIOC);

    DWT_CTRL &= ~DWT_CTRL_CYCCNTENA;
    DWT_CYCCNT = 0;
    SCS_DEMCR &= ~SCS_DEMCR_TRCENA;
}

void binExec(uint32_t addr){
    SCB_VTOR = addr;
    __asm__ (
    "mov   r1, r0        \n"
    "ldr   r0, [r1, #4]  \n" //I also tryed #5 but that doesn't work, too
    "ldr   sp, [r1]      \n"
    "blx   r0"
    );
}

void jumpToUserProgram(uint32_t* addr)
{
    if (!addr) {
        addr = (uint32_t*)USER_APP_START;
    }
    LOG("Booting....");
    LOG("new stack pointer: %08lx", *addr);
    LOG("new reset vector: %08lx", *(addr+1));
    deinitDevice();
    binExec((uint32_t)addr);
    /*
    register uint32_t sp asm("sp");
    sp = *addr;
    addr++;
    (*((JumpFunc*)addr))();
    */
}

void handleCmdSession()
{
    uint32_t uid = 0;
    recvBufTimeout(&uid, sizeof(uid));
    sendByte(CMD_SESSION);
    sendBuf(&uid, sizeof(uid));
}

uint8_t handleCmdBootAddr() {
    uint32_t addr;
    uint8_t err = recvBufTimeout((uint8_t*)&addr, sizeof(addr));
    if (err) {
        return err;
    }
    jumpToUserProgram((uint32_t*)addr);
    return 0; // never executed
}

uint8_t handleCmdBoot() {
    sendByte(CMD_BOOT);
    msWait(10, NULL);
    jumpToUserProgram(0);
    return 0; // never executed
}
uint8_t handleCmdDump() {
    struct ChunkInfo info;
    recvBufTimeout(&info, sizeof(info));
    if (calculateBufCRC(&info, sizeof(info) - sizeof(info.crc)) != info.crc) {
        return ERR_CRC;
    }
    if ((info.dataSize == 0) || ((info.dataSize + info.startAddr) > (uint32_t)__FLASH_WRITABLE_END_ADDR)) {
        return ERR_SIZE;
    }
    sendByte(CMD_DUMP);
    sendBuf(&info.id, sizeof(info.id));
    sendBuf((void*)info.startAddr, info.dataSize);
    uint32_t crc = calculateBufCRC((void*)info.startAddr, info.dataSize);
    sendBuf(&crc, sizeof(crc));
    LOG("Dump complete");
    return 0;
}
void handleCmdSetUart() {
    uint32_t baudrate;
    if (recvBufTimeout(&baudrate, sizeof(baudrate))) {
        LOG("Timed out receiving baud rate");
        return;
    }
    usart_disable(USART1);
    usart_set_baudrate(USART1, 38400);
    usart_set_parity(USART1, USART_PARITY_NONE);
    usart_set_databits(USART1, 9);
    usart_set_stopbits(USART1, USART_STOPBITS_1);
    usart_set_mode(USART1, USART_MODE_TX_RX);
    usart_set_flow_control(USART1, USART_FLOWCONTROL_NONE);
    usart_enable(USART1);
    LOG("Please restart HC-0x module in config mode...");
    for (int i=60; i>0; i--) {
        LOG("%d", i);
    }
    sendBuf("AT\r\n", 4);
    char rbuf[16];
    recvBufTimeout(rbuf, 2);
    rbuf[2] = 0;
    LOG("Sent AT, received %s", rbuf);

    char buf[32] = "AT+UART=";
    itoa(baudrate, buf+8, 10);
    uint8_t baudLen = strlen(buf+8);
    strcpy(buf+8+baudLen, ",1,2\r\n");
    LOG("Sending '%s'", buf);
    sendBuf(buf, strlen(buf));
    if (recvBufTimeout(buf, 4)) {
        LOG("Timed out waiting for response");
        goto restore;
    }
    buf[4] = 0;
    if (strcmp(buf, "OK")) {
        LOG("Received non-OK response: %s", buf);
        goto restore;
    }
    sendBuf("AT+UART=?\r\n", 11);
    recvBufTimeout(buf, 12 + baudLen);
    buf[12] = 0;
    LOG("recv: %s", buf);
restore:
    usart_disable(USART1);
    usart_set_baudrate(USART1, BOOTLOADER_UART_BITRATE);
    usart_set_parity(USART1, USART_PARITY_EVEN);
}

void recvAndProcessCommand()
{
    uint8_t cmd = recvByte();
    uint8_t err = 0;
    switch(cmd)
    {
    case CMD_HELLO:
        return; // Ignore, we process it only the first time
    case CMD_PING:
        sendByte(CMD_PONG);
        return;
    case CMD_SESSION:
        handleCmdSession();
        return;
    case CMD_BOOT:
        handleCmdBoot();
        return;
    case CMD_WRITE_DATA:
        gRecvTimeoutMs = 10000;
        err = handleWriteData();
        gRecvTimeoutMs = kRecvTimeoutMs;
        if (err) {
            LOG("error executing write command: %d", err);
        }
        break;
    case CMD_DEVICEINFO:
        sendDeviceInfo(CMD_DEVICEINFO);
        break;
    case CMD_DUMP:
        err = handleCmdDump();
        return;
    case CMD_SETBITRATE:
        handleCmdSetUart();
        return;
    default:
        err = ERR_UNKNOWN;
        LOG("Unknown command %02x", cmd);
        break;
    }
    if (err) {
        sendByte(cmd | CMD_FLAG_NACK);
        sendByte(err);
        LOG("sent error: nack %02x, errcode: %02x", cmd, err);
    }
}

int main(void)
{
#ifdef DEBUG_LOGGING
    initialise_monitor_handles();
#endif
    dwt_enable_cycle_counter();
    clock_setup();
    led_setup();
    ledOn();
    usart_setup();
    msWait(10, NULL);
    for (;;) {
        uint8_t err = recvHello();
        if (err) {
            if (err == ERR_TIMEOUT) {
                LOG("recvHello: Timeout");
            } else {
                LOG("recvHello error: %d", err);
            }
            jumpToUserProgram(0);
            return 0; // never executed
        }
        sendDeviceInfo(CMD_HELLO);
        for(;;)
        {
            recvAndProcessCommand(); // nonzero return means error
        }
    }
}
