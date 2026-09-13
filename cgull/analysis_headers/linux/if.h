/* Minimal name/flags/index parsing model; not a kernel ABI definition. */
#ifndef CGULL_ANALYSIS_LINUX_IF_H
#define CGULL_ANALYSIS_LINUX_IF_H
#define IFNAMSIZ 16
#define IF_NAMESIZE IFNAMSIZ
struct ifreq {
    char ifr_name[IFNAMSIZ];
    short ifr_flags;
    int ifr_ifindex;
    int ifr_mtu;
    char *ifr_data;
};
struct ifconf {
    int ifc_len;
    union {
        char *ifcu_buf;
        struct ifreq *ifcu_req;
    } ifc_ifcu;
};
#define ifc_buf ifc_ifcu.ifcu_buf
#define ifc_req ifc_ifcu.ifcu_req
#endif
