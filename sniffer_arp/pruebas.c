
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <pthread.h>

typedef struct ARP
{
    unsigned char destinoEthernet[6];
    unsigned char origenEthernet[6];
    unsigned short tipoEthernet;
    unsigned short tipoHardware;

    unsigned short tipoProtocolo;

    unsigned char longitudHardware;
    unsigned char longitudProtocolo;
    unsigned short tipoMensaje;
    unsigned char origenMAC[6];
    unsigned char origenIP[4];
    unsigned char destinoMAC[6];
    unsigned char dentinoIP[4];
} msgARP;

void printData(msgARP);

int main(int argc, const char* argv[]){
    printf("%d\n", argc);
    unsigned char sh[4];
    struct in_addr addr;
    
    inet_aton("63.161.169.137", &addr); //arpa/inet.h

    printf("%s\n", inet_ntoa(addr));
    printf("%x\n", addr.s_addr);
    bcopy(&addr.s_addr, sh, 4);

    for(int i=0; i<4; i++){
        printf("%d.", sh[i]);
    }
    printf("\n");

    // int optval = 0;
    // int sock = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ARP));
    // if(sock<0){
    //     fprintf(stderr, "Unable to open socket %d\n", sock);
    //     exit(EXIT_FAILURE);
    // }
    // setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval));

    // struct ifreq ifr;
    // //enp0s3
    // strcpy(ifr.ifr_name, "enp0s3");
    // if(ioctl(sock, SIOCGIFHWADDR, &ifr)==-1){
    //     fprintf(stderr, "Error en IOCTL\n");
    //     exit(EXIT_FAILURE);
    // }

    // msgARP msg;

    // bcopy(&ifr.ifr_hwaddr.sa_data, &msg.origenMAC, 6);
    // bcopy(&ifr.ifr_hwaddr.sa_data, &msg.origenEthernet, 6);

    // ioctl(sock, SIOCGIFADDR, &ifr);
    // bcopy(&ifr.ifr_addr.sa_data[2], &msg.origenIP, 4);

    // unsigned char dirdest[] = {192, 168, 100, 1};
    // bcopy(dirdest, &msg.dentinoIP, 4);

    // memset(&msg.destinoEthernet, 0xff, 6);

    // msg.longitudHardware = 6;
    // msg.longitudProtocolo = 4;
    // msg.tipoEthernet = htons(ETH_P_ARP);
    // msg.tipoHardware = htons(ARPHRD_ETHER);
    // msg.tipoProtocolo = htons(ETH_P_IP);
    // msg.tipoMensaje = htons(ARPOP_REQUEST);

    // bzero(&msg.destinoMAC, 6);

    // struct sockaddr saddr;
    // int size_saddr = sizeof(saddr);
    // char buffer[2000];
    // recvfrom(sock, 0, 0, 0, &saddr, &size_saddr);
    // int sent = sendto(sock, &msg, sizeof(msg), 0, &saddr, size_saddr);
        
    // msgARP msg1;
    // recvfrom(sock, &msg1, sizeof(msg1), 0, &saddr, &size_saddr);


    // printData(msg1);
    // for(int i=0; i<14; i++)
    //     printf("%02x: ", saddr.sa_data[i]);
    // printf("\n%d\n", sent);
    
    // close(sock);
}


void printData(msgARP pkt){
    int i;
    for(i=0; i<6; i++){
        printf("%02x:", pkt.destinoEthernet[i]);
    }
    printf(" MAC destino\n");
    for(i=0; i<6; i++){
        printf("%02x:", pkt.origenEthernet[i]);
    }
    printf(" MAC origen\n");

    printf("%04x: tipo Ethernet\n\n", pkt.tipoEthernet);

    printf("%04x: tipo HW\n", pkt.tipoHardware);
    printf("%04x: tipo Protocolo\n", pkt.tipoProtocolo);

    printf("%02x: L HW\n", pkt.longitudHardware);
    printf("%02x: L Protocolo\n", pkt.longitudProtocolo);
    printf("%04x: Tipo Mensaje (1 peticion)\n", pkt.tipoMensaje);


    for(i=0; i<6; i++){
        printf("%02x:", pkt.origenMAC[i]);
    }
    printf(" MAC origen\n");
    for(i=0; i<4; i++){
        printf("%d.", pkt.origenIP[i]);
    }
    printf(" IP origen\n");

    for(i=0; i<6; i++){
        printf("%02x:", pkt.destinoMAC[i]);
    }
    printf(" MAC destino\n");
    for(i=0; i<4; i++){
        printf("%d.", pkt.dentinoIP[i]);
    }
    printf(" IP destino\n");

}
// 08:00:27:57:d6:f1