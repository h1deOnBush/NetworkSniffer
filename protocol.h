
/** protocol.h
structs of ethernet, ip, tcp, udp
*/
#define CAPTURE_PACKET_NUM 100
#define PCAP_HEADER_LEN 24
#define PACKET_HEADER_LEN 16

/* ============= Ethernet ============ */
#define ETHER_LEN           14
#define ETHER_ADDR_LEN      6
#define ETHER_TYPE_LEN      2

#define ETHER_DEST_OFFSET   (0 * ETHER_ADDR_LEN)
#define ETHER_SRC_OFFSET    (1 * ETHER_ADDR_LEN)
#define ETHER_TYPE_OFFSET   (2 * ETHER_ADDR_LEN)

typedef struct _ether_header{
    u_char host_dest[ETHER_ADDR_LEN];
    u_char host_src[ETHER_ADDR_LEN];
    u_short type;
#define ETHER_TYPE_MIN      0x0600
//ip协议
#define ETHER_TYPE_IP       0x0800
//ARP协议
#define ETHER_TYPE_ARP      0x0806
#define ETHER_TYPE_8021Q    0x8100
#define ETHER_TYPE_BRCM     0x886c
#define ETHER_TYPE_802_1X   0x888e
#define ETHER_TYPE_802_1X_PREAUTH 0x88c7
} ether_header;



/*============== IP ================*/
#define IP_LEN_MIN 20
//4字节的IP地址
typedef struct ip_address{
    unsigned char byte1;
    unsigned char byte2;
    unsigned char byte3;
    unsigned char byte4;
}ip_address;
/* IPv4 header */
typedef struct _ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short ident;          // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    #define IP_ICMP     1
    #define IP_IGMP     2
    #define IP_TCP      6
    #define IP_UDP      17
    #define IP_IGRP     88
    #define IP_OSPF     89
    unsigned short crc;                         //首部校验和   16位
    ip_address src_ip_address;                  //源IP地址     32位
    ip_address dest_ip_address;                 //目的IP地址    32位
    unsigned int option_padding;                // 选项与填充 32位
}ip_header;


/*=============== TCP ================*/
#define TCP_LEN_MIN 20
typedef struct _tcp_header
{
    u_short th_sport;          // source port
    u_short th_dport;          // destination port
    u_int   th_seq;            // sequence number field
    u_int   th_ack;            // acknowledgement number field
    u_char  th_len_x2;
    u_char  th_flags;
    #define TH_FIN	0x01
    #define TH_SYN	0x02
    #define TH_RST	0x04
    #define TH_PSH	0x08
    #define TH_ACK	0x10
    #define TH_URG	0x20
    u_short th_win;		    /* window */
    u_short th_sum;		    /* checksum */
    u_short th_urp;		    /* urgent pointer */
}tcp_header;  //*/

/*================ UDP ==================*/
#define UDP_LEN 8
typedef struct _udp_header{
    u_short uh_sport;          // Source port
    u_short uh_dport;          // Destination port
    u_short uh_len;            // Datagram length
    u_short uh_sum;            // Checksum
}udp_header;

/*================DNS===================*/
#define DNS_HEAD_LEN 12
typedef struct _dns_header{
    u_short dh_transcation_id;  //会话标识
    u_short dh_flags;           //标志
    u_short dh_questions;       //问题数
    u_short dh_answers;         //回答，资源记录数
    u_short dh_authority;       //授权，资源记录数
    u_short dh_additional;      //附加，资源记录数
}dns_header;

/*================DNS_QUERRY==============*/
typedef struct _dns_querry{
    u_char length;
}dns_querry;

/*===============DNS_QUERRY===============*/
typedef struct _dns_type_class{
    u_short type;
    u_short query_class;
}dns_type_class;

//timeval结构
typedef struct _shh_timeval{
    int tv_sec;        /* seconds 1900之后的秒数 */
    int tv_usec;      /* and microseconds */
}shh_timeval;

// pcap_next()方法执行后，pcap_pkthdr类型的指针指向抓包的信息
typedef struct _shh_pkthdr {
    shh_timeval ts;  /* time stamp 时间 */
    bpf_u_int32 caplen; /* length of portion present 包的数据长度？？ */
    bpf_u_int32 len;    /* length this packet (off wire) 包的实际长度  */
}shh_pkthdr;

//5元组结构体，含有源目ip，源目端口以及协议5个信息
typedef struct _net5set
{
    u_int       sip;
    u_short     sport;
    u_int       dip;
    u_short     dport;
    u_char      protocol;
}net5set;

//普通链表节点，含有上下行数据包的个数以及大小以及TCP状态，代表一个周期内或一个tcp连接时间内的统计值
typedef struct _net_link_node
{
    net5set nln_5set;
    int     nln_upl_size;
    int     nln_downl_size;
    int     nln_upl_pkt;
    int     nln_downl_pkt;
    u_char  nln_status;
    #define CLOSED      0x00
    #define SYN_SENT    0x01    // client sent SYN
    #define SYN_RECVD   0x02    // recieve SYN, and send SYN ACK
    #define ESTABLISHED 0x03    // client get SYN & ACK, server get ACK

    #define FIN_WAIT_1  0x04    // client send FIN
    #define CLOSE_WAIT  0x05    // server recv FIN, and send ACK
    #define FIN_WAIT_2  0x06    // client recv ACK
    #define LAST_ACK    0x07    // server send FIN
    #define TIME_WAIT   0x08    // client recv FIN
    // CLOSED: client send ACK, server recv ACK
    #define UNDEFINED   0xff
    //下一个普通链表节点
    struct  _net_link_node *next;
}net_link_node, *p_net_link;

//链表头节点，含有该链表所有节点的统计信息
typedef struct _net_link_header
{
    //连接数
    int count_conn;
    //上行的包的数量
    int count_upl_pkt;
    //下行的包的数量
    int count_downl_pkt;
    //上传字节数
    int count_upl;
    //下载字节数
    int count_downl;
    //下一个节点
    p_net_link link;
}net_link_header;
