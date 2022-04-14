// Para compilar: gcc  Hilos.c -lpthread -o Hilos

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>
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

FILE* archivo;
int leidos = 0;
int size = 0;
int eth1 = 0;
int eth2 = 0;
int ip4 = 0;
int ip6 = 0;
int arp = 0;
int flujo = 0;
int seg = 0;
int i;
int j;
int npack;

int main(int argc, const char* argv[]) {
       
    int optval = 0;
    int sock = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ARP));
    if(sock<0){
        fprintf(stderr, "Unable to open socket %d\n", sock);
        exit(EXIT_FAILURE);
    }
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval));
    
    struct ifreq ifr;
    //enp0s3
    strcpy(ifr.ifr_name, "enp0s3");
    if(ioctl(sock, SIOCGIFHWADDR, &ifr)==-1){
        fprintf(stderr, "Error en IOCTL\n");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "IP\t\tMAC\n");

    msgARP msg;

    bcopy(&ifr.ifr_hwaddr.sa_data, &msg.origenMAC, 6);
    bcopy(&ifr.ifr_hwaddr.sa_data, &msg.origenEthernet, 6);

    ioctl(sock, SIOCGIFADDR, &ifr);
    bcopy(&ifr.ifr_addr.sa_data[2], &msg.origenIP, 4);

    unsigned char dirdest[] = {192, 168, 100, 1};
    bcopy(dirdest, &msg.dentinoIP, 4);

    memset(&msg.destinoEthernet, 0xff, 6);

    msg.longitudHardware = 6;
    msg.longitudProtocolo = 4;
    msg.tipoEthernet = htons(ETH_P_ARP);
    msg.tipoHardware = htons(ARPHRD_ETHER);
    msg.tipoProtocolo = htons(ETH_P_IP);
    msg.tipoMensaje = htons(ARPOP_REQUEST);

    bzero(&msg.destinoMAC, 6);

    struct sockaddr saddr;
    int size_saddr = sizeof(saddr);
    recvfrom(sock, 0, 0, 0, &saddr, &size_saddr);
    int resp = sendto(sock, &msg, sizeof(msg), 0, &saddr, size_saddr);

    if (resp<=0){
        fprintf(stderr, "Error al enviar paquete\n");
        exit(EXIT_FAILURE);
    }

    msgARP msg1;
    for(j=0; j<10; j++){
        recvfrom(sock, &msg1, sizeof(msg1), 0, &saddr, &size_saddr);
        if(htons(msg1.tipoMensaje)!=2){
            printf("%d\n", htons(msg1.tipoMensaje));
            continue;
        }


        for(i=0; i<4; i++){
            fprintf(stdout, "%d.", msg1.origenIP[i]);
        }
        printf("\t");
        for(i=0; i<6; i++){
            fprintf(stdout, "%02x:", msg1.origenMAC[i]);
        }
        fprintf(stdout, "\n");
        break;
    }
    // if((archivo = fopen("sniffer.txt", "w"))==0){
    //     fprintf(stderr, "No se pudo abrir el archivo\n");
    //     exit(EXIT_FAILURE);
    // }

    // fclose(archivo);

    close(sock);

    exit(EXIT_SUCCESS);
}
