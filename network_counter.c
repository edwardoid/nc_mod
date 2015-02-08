#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/stat.h>
#include <linux/socket.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <asm/errno.h>

#define FILE_NAME "network_counter"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Edward Sargsyan");
MODULE_DESCRIPTION("Network counting module");

#define RW_MODE_PARAM (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)
static int port = -1; // All
module_param(port, int, RW_MODE_PARAM);
MODULE_PARM_DESC(port, "Port to monitor. If value is less than 1, all ports will be monitored");

#define LOG_EVERY_N_SECS 30 
#define PROC_FS_BUFFER_LEN 1024

#define IFACE_NAME_MAX_LEN 80
static char* interface = "*";
static char iface[IFACE_NAME_MAX_LEN];
module_param(interface, charp, RW_MODE_PARAM);
MODULE_PARM_DESC(interface, "Interface to monitor. * for all available interfaces");

static int human_readable = 0;
module_param(human_readable, int, RW_MODE_PARAM);
MODULE_PARM_DESC(human_readable, "If human_readable = 0 then  output will be more human readable");

int is_tcp_soket(struct sk_buff* skb);

int get_port(   struct  sk_buff* skb,
                int     src_dest /* 0 == src, 1 == dest */);

#define skb_data_len(skb) ((int)(skb -> tail - skb -> data))
#define check_interface(interface, filter) ((strcmp(filter, "") == 0)  || \
                                            (strcmp(filter, "*") == 0) || \
                                            (strcmp(filter, interface) == 0))

#define check_port(port, filter) ((filter < 1) || (port == filter))


/*
 *  The function will be called when a packed has
 *  been arrived to the system.
 */
unsigned int hook_rx_fn(unsigned int hooknum,
                        struct sk_buff* skb,
                        const struct net_device* in,
                        const struct net_device* out,
                        int (*okfn)(struct sk_buff*));

/*
 *  The function will be called when packet
 *  is prepared ans is going to be sent.
 */
unsigned int hook_tx_fn(unsigned int hooknum,
                        struct sk_buff* skb,
                        const struct net_device* in,
                        const struct net_device* out,
                        int (*okfn)(struct sk_buff*));

int procfs_open_fn(struct inode *inode, struct file *fp);

/*
 * Writes to usage statistics to the buffer from userspace
/*/
ssize_t procfs_read_fn( struct file*    fp,
                        char __user *   buffer,
                        size_t          lenght,
                        loff_t*         offset);
/*
 * Reads parameters from user space.
 * Parameters format is: iface: <name> port: <num>
 * If value of parameter iface is * all interfaces will be accepted
 * If value of port is < 1, then all ports will be accepted
 */
ssize_t procfs_write_fn( struct file*        fp,
                         const char __user * buffer,
                         size_t              lenght,
                         loff_t*             offset);

/*
 * Closes file in procfs for user.
 */
static int procfs_release_fn(struct inode *inode, struct file *fp);

/*
 * Stores printable values of TX/XR traffic.
 */
struct hr_t
{
    u64 integer;
    u8  fractional;
};


/*
 * Convers bytes count to more readable format. For example 2500 -> 2.5KB
 */
void make_human_readable(const u64 bytes, const char** pf, struct hr_t* hr);


/* Counters: */
static u64 packets_received = 0;
static u64 data_received = 0;
static u64 packets_transmitted = 0;
static u64 data_transmitted = 0;


/* netfilter data */
static struct nf_hook_ops hook_tx;
static struct nf_hook_ops hook_rx;

/* procfs file */
static struct proc_dir_entry *proc_file;


/*
 * I/O buffers
 */
static char   proc_fs_buff_r[PROC_FS_BUFFER_LEN];
static char   proc_fs_buff_w[PROC_FS_BUFFER_LEN];
static int    proc_fs_file_opened = 0;


/*
 * Human readable postfixes.
 */
static const char* EMPTY_PF = "";
static const char* BYTES_PF = "b";
static const char* KBYTES_PF = "KB";
static const char* MBYTES_PF = "MB";
static const char* GBYTES_PF = "GB";

/*
 * Procfs file_ops. Open/Read/Wrtie/Close callbacks
 */
static const struct file_operations proc_file_ops = 
{
    .owner = THIS_MODULE,
    .open = procfs_open_fn,
    .read = procfs_read_fn,
    .write = procfs_write_fn,
    .release = procfs_release_fn
};

/*
 * Checks ne socket type.
 * Return 0 if socket is not TCP or input is invalid
 */
int is_tcp_soket(struct sk_buff* skb)
{   
    if(skb == NULL)
        return 0;
    if(ip_hdr(skb) == NULL)
        return 0;
    if(ip_hdr(skb)->protocol != IPPROTO_TCP)
        return 0;
    return 1;
}


/*
 * Extracts port info from socket data.
 * Returns 0 if input is invalid or port info is missed
 */
int get_port(   struct  sk_buff* skb,
                int     src_dest /* 0 == src, 1 == dest */)
{
    struct iphdr* iph = NULL;
    struct tcphdr* hdr = NULL;
    iph = ip_hdr(skb);
    if(skb == NULL || iph == NULL)
        return 0;
    hdr = (struct tcphdr*)((__u32 *)iph + iph->ihl);
    if(hdr == NULL)
        return 0;
    if(0 == is_tcp_soket(skb))
        return 0;

    if(src_dest == 0)
        return htons(hdr->source);
    return htons(hdr->dest);

    return 0;
}

unsigned int hook_tx_fn(unsigned int    hooknum,
                        struct sk_buff* skb,
                        const struct net_device* in,
                        const struct net_device* out,
                        int (*okfn)(struct sk_buff*))
{
    int src_port = get_port(skb, 0);
    
    if(check_port(src_port, port) && check_interface(out->name, iface))
    {
        ++packets_transmitted;
        data_transmitted += skb_data_len(skb);
    }
    
    return NF_ACCEPT;
}

unsigned int hook_rx_fn(unsigned int      hooknum,
                        struct sk_buff*   skb,
                        const struct net_device* in,
                        const struct net_device* out,
                        int (*okfn)(struct sk_buff*))
{
    
    int dst_port = get_port(skb, 1);
    
    if(check_port(dst_port, port) && check_interface(in->name, iface))
    {
        ++packets_received;
        data_received += skb_data_len(skb);
    }
    
    return NF_ACCEPT;
}

int procfs_open_fn(struct inode *inode, struct file *fp)
{
    if(proc_fs_file_opened)
    {
        printk(KERN_ERR "Can't open procfc file");
        return -EBUSY;
    }

    ++proc_fs_file_opened;
    
    return 0;
}

void make_human_readable(const u64 bytes, const char** pf, struct hr_t* hr)
{
    u64 b = bytes;
    if(bytes < (u64)1024)
    {
        *pf = BYTES_PF;
        hr->integer = b;
        hr->fractional = 0;
        return; 
	}

    b = bytes;
    do_div(b, (u64)1000);
	if(b < (u64)1024)
    {
        *pf = KBYTES_PF;
        hr->integer = b;
        b = bytes;
        do_div(b, (u64)100);
        hr->fractional = (unsigned int)b % 10;
        return;
    }

    b = bytes;
    do_div(b, (u64)1000000);
    if(b < (u64)1024)
    {
        *pf = MBYTES_PF;
        hr->integer = b;
        b = bytes;
        do_div(b, 100000);
        hr->fractional = (unsigned int)b % 10;
        return;
    }

    b = bytes;
    do_div(b, (u64)1000000000);
    hr->integer = b;
    b = bytes;
    do_div(b, (u64)100000000);
    hr->fractional = (unsigned int)b % 10;
    *pf = GBYTES_PF;
}

ssize_t procfs_read_fn( struct file*    fp,
                        char __user *   buffer,
                        size_t          length,
                        loff_t*         offset)
{
    static int finished = 0;
    char* pos;
    int buff_len;
    const char* TX_pf = EMPTY_PF;
    const char* RX_pf = EMPTY_PF;
    
    struct hr_t TX;
    struct hr_t RX;
    TX.integer = data_transmitted;
    TX.fractional = 0;
    RX.integer = data_received;
    RX.fractional = 0;

    if(finished)
    {
        finished = 0;
        return 0;
    }

    finished = 1;
    
    if(human_readable)
    {
        make_human_readable(TX.integer, &TX_pf, &TX);
        make_human_readable(RX.integer, &RX_pf, &RX);
    }


    printk("Bytes tx: %llu rx %llu\n", data_transmitted, data_received);
    
    
    if(human_readable)
    {
        buff_len = snprintf( proc_fs_buff_r, PROC_FS_BUFFER_LEN,
                             "iface:\t%s\tport:\t%d\nTX(packets):\t%llu\tRX(packets):\t%llu\nTX:\t%llu.%d%s\tRX:\t%llu.%d%s\n",
                             iface, port,
                             packets_transmitted, packets_received,
                             TX.integer, TX.fractional, TX_pf,
                             RX.integer, RX.fractional, RX_pf);

    }
    else
    {
        buff_len = snprintf( proc_fs_buff_r, PROC_FS_BUFFER_LEN,
                             "iface:\t%s\tport:\t%d\nTX(packets):\t%llu\tRX(packets):\t%llu\nTX:\t%llu%s\tRX:\t%llu%s\n",
                             iface, port,
                             packets_transmitted, packets_received,
                             TX.integer, TX_pf, RX.integer, RX_pf);
    }

    if(offset != NULL)
        buff_len -= *offset;
   
    if(buff_len < 1)
        return 0;

    if(length > buff_len)
        length = buff_len;

    pos = proc_fs_buff_r;
    
    if(offset != NULL)
        pos += *offset;

    if(copy_to_user((void*)buffer, (void*)pos, length))
        return -EFAULT;

    return length;
}


ssize_t procfs_write_fn( struct file*        fp,
                         const char __user * buffer,
                         size_t              length,
                         loff_t*             offset)
{
    int port_candidate = -1;
    char iface_candidate[IFACE_NAME_MAX_LEN];

    if(length > PROC_FS_BUFFER_LEN)
    {
        length = PROC_FS_BUFFER_LEN;
    }

    if(copy_from_user((void*) proc_fs_buff_w, (void*) buffer, length))
        return -EFAULT;

    if(proc_fs_buff_w == NULL)
        return -EINVAL;

    proc_fs_buff_w[length] = '\0';
    if(2 == sscanf(proc_fs_buff_w, "iface: %s port: %d", iface_candidate, &port_candidate))
    {
        if(check_interface(iface_candidate, iface) && check_port(port, port_candidate))
            return length;
        printk(KERN_INFO "Monitoring interface: %s and port %d", iface_candidate, port_candidate);
        strcpy(iface, iface_candidate);
        port = port_candidate;
        data_received = 0;
        data_transmitted = 0;
        packets_received = 0;
        packets_transmitted = 0;
    }
    else
    {
        return -EINVAL;
    }

    return length;
}

static int procfs_release_fn(struct inode *inode, struct file *fp)
{
    --proc_fs_file_opened;
    return 0;
}


/*
 * Initiazes the module
 */
static int __init cm_init(void)
{
    printk("Initing network_counter module");

    proc_file = proc_create(FILE_NAME, 0644, NULL, &proc_file_ops);

    if(proc_file == NULL)
    {
        printk(KERN_ERR "Can't cretae i/o file in proc directory");
        return -ENOMEM;
    }

    memset(iface, '\0', IFACE_NAME_MAX_LEN);
    strcpy(iface, interface);
    
    hook_tx.hook = hook_tx_fn;
    hook_tx.hooknum = NF_INET_POST_ROUTING;
    hook_tx.pf = PF_INET;
    hook_tx.priority = NF_IP_PRI_LAST;
    nf_register_hook(&hook_tx);

    hook_rx.hook = hook_rx_fn;
    hook_rx.hooknum = NF_INET_PRE_ROUTING;
    hook_rx.pf = PF_INET;
    hook_rx.priority = NF_IP_PRI_LAST;
    nf_register_hook(&hook_rx);
    return 0;
}


/*
 * Releases the module
 */ 
static void __exit cm_exit(void)
{
    nf_unregister_hook(&hook_rx);
    nf_unregister_hook(&hook_tx);

    if(proc_file != NULL)
        remove_proc_entry(FILE_NAME, proc_file);
}

module_init(cm_init);
module_exit(cm_exit);
