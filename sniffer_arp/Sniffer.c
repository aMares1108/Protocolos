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
#include <arpa/inet.h>
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
unsigned char hw_addr[6];
unsigned char pt_addr[4];
struct sockaddr saddr;
int size_saddr = sizeof(saddr);
int sock;
int ac;

void* init_packet(void* ip);
void* analize_packet();
void send_packet(msgARP msg);
void printData(msgARP msg);

int main(int argc, const char* argv[]) {
    ac = argc-2;
    if(argc<3){
        fprintf(stderr, "Expected more arguments. %d received.\n", argc-1);
        exit(EXIT_FAILURE);
    }
    int optval = 0;
    sock = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ARP));
    if(sock<0){
        fprintf(stderr, "Unable to open socket %d\n", sock);
        exit(EXIT_FAILURE);
    }
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval));
    
    struct ifreq ifr;
    //enp0s3
    strcpy(ifr.ifr_name, argv[1]);
    if(ioctl(sock, SIOCGIFHWADDR, &ifr)==-1){
        fprintf(stderr, "Error en IOCTL HW para %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }
    bcopy(&ifr.ifr_hwaddr.sa_data, hw_addr, 6);

    if(ioctl(sock, SIOCGIFADDR, ifr)==-1){
        fprintf(stderr, "Error en IOCTL Pt para %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }
    bcopy(&ifr.ifr_addr.sa_data[2], pt_addr, 4);
    
    if((archivo = fopen("sniffer.txt", "w"))==0){
        fprintf(stderr, "No se pudo abrir el archivo\n");
        exit(EXIT_FAILURE);
    }
    fprintf(archivo, "IP\t\tMAC\n");

    recvfrom(sock, 0, 0, 0, &saddr, &size_saddr);

    pthread_t *id_hilo = (pthread_t*) malloc((argc-2)*sizeof(pthread_t));
    if(id_hilo==NULL){
        fprintf(stderr, "Ocurrio un error al manipular memoria dinamica\n");
        exit(-1);
    }
    pthread_t hilo_analiza;
    if(pthread_create(&hilo_analiza, NULL, analize_packet, NULL)){
        fprintf(stderr, "Problema en la creacion del hilo\n");
        exit(EXIT_FAILURE);
    }
    for(int i=0; i<argc-2; i++){
        if(pthread_create(&id_hilo[i], NULL, init_packet, (void*)argv[2+i])){
            fprintf(stderr, "Problema en la creacion del hilo\n");
            exit(EXIT_FAILURE);
        }
        if(pthread_join(id_hilo[i], NULL)){
            fprintf(stderr, "Problema en la union del hilo\n");
            exit(EXIT_FAILURE);
        }
    }
    if(pthread_join(hilo_analiza, NULL)){
        fprintf(stderr, "Problema en la union del hilo\n");
        exit(EXIT_FAILURE);
    }
    
    fclose(archivo);
    close(sock);
    exit(EXIT_SUCCESS);
}

void* init_packet(void* ip_a){
    char *ip = (char*) ip_a;
    msgARP msg;
    bcopy(hw_addr, &msg.origenMAC, 6);
    bcopy(hw_addr, &msg.origenEthernet, 6);
    bcopy(pt_addr, &msg.origenIP, 4);

    struct in_addr addr;
    inet_aton(ip, &addr); //arpa/inet.h
    bcopy(&addr.s_addr, &msg.dentinoIP, 4);

    memset(&msg.destinoEthernet, 0xff, 6);

    msg.longitudHardware = 6;
    msg.longitudProtocolo = 4;
    msg.tipoEthernet = htons(ETH_P_ARP);
    msg.tipoHardware = htons(ARPHRD_ETHER);
    msg.tipoProtocolo = htons(ETH_P_IP);
    msg.tipoMensaje = htons(ARPOP_REQUEST);

    bzero(msg.destinoMAC, 6);

    send_packet(msg);
}

void send_packet(msgARP msg){
    if (sendto(sock, &msg, sizeof(msg), 0, &saddr, size_saddr)<=0){
        fprintf(stderr, "Error al enviar paquete a \n");
        for(int j=0; j<4; j++){
            fprintf(stderr, "%d.", msg.dentinoIP[j]);
        }
        fprintf(stderr, "\n");
    }
}

void* analize_packet(){
    int j;
    int read = 0;
    for(j=0; j<ac*10; j++){
        msgARP msg1;
        recvfrom(sock, &msg1, sizeof(msg1), 0, &saddr, &size_saddr);
        if(htons(msg1.tipoMensaje)!=2){
            continue;
        }
        // if(bcmp(&msg.dentinoIP, &msg1.origenIP, 4)!=0){
        //     fprintf(stderr, "Respuesta de otro host detectada. ");
        //     j=10;
        //     break;
        // }

        for(int i=0; i<4; i++){
            fprintf(archivo, "%d.", msg1.origenIP[i]);
        }
        fprintf(archivo, "\t");
        for(int i=0; i<6; i++){
            fprintf(archivo, "%02x:", msg1.origenMAC[i]);
        }
        fprintf(archivo, "\n");
        read++;
        if(read>=ac)
            break;
    }
    // if(j==10){
    //     // printData(msg);
    //     fprintf(stderr, "No se encontro la direccion ");
    //     for(j=0; j<4; j++){
    //         fprintf(stderr, "%d.", msg.dentinoIP[j]);
    //     }
    //     fprintf(stderr, "\n");
    // }

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
