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
#include <pthread.h>

typedef struct packet
{
    char *data;
    int size;
    struct packet* siguiente;
} Paquete;

typedef struct mac
{
    unsigned char direccion[6];
    unsigned int cuenta;
    struct mac *siguiente;
} Mac;

Mac* countMAC(Mac* lista, unsigned char *direccion);
Mac* liberarMAC(Mac* lista);
void printMAC(Mac* lista);
Paquete* addPacket(Paquete* paquete, char* buffer, int size);
Paquete* nextPacket(Paquete* paquete);
void *funcion_hilo(void *argumento);
void analizarPaquete(char * buffer, int size);
// void printData(char * data, int size);

Paquete *lista = NULL;
Mac* dirs = NULL;
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
    if(argc!=3){
        fprintf(stderr, "Expected 2 arguments. %d received.\n", argc-1);
        exit(EXIT_FAILURE);
    }
    npack = atoi(argv[1]);
    
    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock<0){
        fprintf(stderr, "Unable to open socket to %s %d\n", argv[1], sock);
        exit(EXIT_FAILURE);
    }
    
    struct ifreq ethreq;
    //enp0s3
    strncpy(ethreq.ifr_name, argv[2], IFNAMSIZ);
    if(ioctl(sock, SIOCGIFFLAGS, &ethreq)==-1){
        fprintf(stderr, "Error en SIOCGIFFLAGS\n");
        exit(EXIT_FAILURE);
    }
    ethreq.ifr_flags|= IFF_PROMISC;
    if(ioctl(sock, SIOCSIFFLAGS, &ethreq)==-1){
        fprintf(stderr, "Error en SIOCSIFFLAGS\n");
        exit(EXIT_FAILURE);
    }

    if((archivo = fopen("sniffer.txt", "w"))==0){
        fprintf(stderr, "No se pudo abrir el archivo\n");
        exit(EXIT_FAILURE);
    }

    //Hilo analizador
    pthread_t id_hilo;

    if(pthread_create(&id_hilo, NULL, funcion_hilo, NULL)){
        fprintf(stderr, "Problema en la creacion del hilo\n");
        exit(EXIT_FAILURE);
    }


    char buffer[2000];
    struct sockaddr saddr;
    int size_saddr = sizeof(saddr);
    

    for(j=0; j<npack; j++){
        size = recvfrom(sock, buffer, 2000, 0, &saddr, &size_saddr);
        if(size<0){
            fprintf(stderr, "Ocurrio un error al leer los paquetes\n");
            exit(EXIT_FAILURE);
        }
        
        lista = addPacket(lista, buffer, size);
    }

    close(sock);
    char command[50] = "/sbin/ifconfig ";
    strcat(command, argv[2]);
    strcat(command, " -promisc");
    system(command);

    if(pthread_join(id_hilo, NULL)){
        printf("Problema al crear el enlace con otro hilo\n");
        exit(EXIT_FAILURE);
    }

    fprintf(archivo, "Total(%d):  IEEE 802.3(%d)  Ethernet II(%d)\nIPv4: %d\tIPv6: %d\tARP: %d\tControl de flujo: %d\tSeguridad MAC: %d\n", leidos, eth1, eth2, ip4, ip6, arp, flujo, seg);
    printMAC(dirs);
    liberarMAC(dirs);

    fclose(archivo);

    exit(EXIT_SUCCESS);
}

void analizarPaquete(char * buffer, int size){
    unsigned short int proto;
    struct ethhdr *ethernet;

    ethernet = (struct ethhdr*) buffer;
    proto = ethernet->h_proto;
    proto = (proto&0xff00)>>8 | (proto&0x00ff)<<8;

    if(proto<=0x05dc){
        fprintf(archivo, "La trama es IEEE 802.3 y no puede ser analizada: %04x\n", proto);
        eth1++;
    } else if (proto>=0x0600) {
        fprintf(archivo, "La trama es Ethernet II ");
        eth2++;
        switch(proto){
            case 0x0800:
                fprintf(archivo, "IPv4");
                ip4++;
                break;
            case 0x86dd:
                fprintf(archivo, "IPv6");
                ip6++;
                break;
            case 0x0806:
                fprintf(archivo, "ARP");
                arp++;
                break;
            case 0x8808:
                fprintf(archivo, "Control de flujo Ethernet");
                flujo++;
                break;
            case 0x88e5:
                fprintf(archivo, "Seguridad MAC");
                seg++;
                break;
            default:
                fprintf(archivo, "Otro tipo");
        }
        fprintf(archivo, "\t");

        // printData(buffer+sizeof(struct ethhdr), size-sizeof(struct ethhdr));
        fprintf(archivo, "Frame Size: %d Util size: %ld\t", size, size-sizeof(struct ethhdr));

        fprintf(archivo, "Protocol: %04x\t", proto);
        fprintf(archivo, "Source: ");
        for(i=0; i<6; i++){
            fprintf(archivo, "%02x:", ethernet->h_source[i]);
        }
        fprintf(archivo, "\b ");

        fprintf(archivo, "Destination: ");
        for(i=0; i<6; i++){
            fprintf(archivo, "%02x:", ethernet->h_dest[i]);
        }
        fprintf(archivo, "\b  ");
        dirs = countMAC(dirs, ethernet->h_source);
        if(ethernet->h_dest[0]==0xff){
            unsigned short int dest = 0xff;
            for(i=0; i<6; i++){
                dest &= ethernet->h_dest[i];
            }
            if(dest==0xff)
                fprintf(archivo, "(Difusion)");
            else
                fprintf(archivo, "(Multidifusion)");
        } else if(ethernet->h_dest[0]&0x1){
            fprintf(archivo, "(Multidifusion)");
        } else {
            fprintf(archivo, "(Unidifusion)");
        }
        fprintf(archivo, "\n");

    } else {
        fprintf(archivo, "La trama no pudo ser identificada como Ethernet II ni como IEEE802.3\n");
    }
}

// void printData(char * data, int size){
//     int i;
//     int row_size = 16;
//     unsigned short int datum;
//     for(i=0; i<size; i++){
//         datum = data[i] & 0xff;
//         // printf("%02x ", datum);
//         if(datum>=32 && datum<=127)
//             printf("%c ", datum);
//         else
//             printf(". ");
//         if(i%row_size==row_size-1) printf("\n");
//     }
//     printf("\n");
//     for(i=0; i<size; i++){
//         printf("%02x ", data[i]&0xff);
//         if(i%row_size==row_size-1) printf("\n");
//     }
//     printf("\n");
// }

Paquete* crearPaquete(char* buffer, int size){
    Paquete *nuevo = (Paquete*) malloc(sizeof(Paquete));
    if(nuevo==NULL){
        fprintf(stderr, "Ocurrio un error al manipular memoria dinamica\n");
        exit(-1);
    }
    nuevo->data = (char*) malloc(sizeof(char)*size+1);
    if(nuevo->data==NULL){
        fprintf(stderr, "Error en la memoria dinamica\n");
        exit(EXIT_FAILURE);
    }
    for(i=0;i<size;i++)
        nuevo->data[i]=buffer[i];
    nuevo->size = size;
    nuevo->siguiente = NULL;
    return nuevo;
}

Paquete* addPacket(Paquete* paquete, char* buffer, int size){
    Paquete *nuevo = crearPaquete(buffer, size);
    if(paquete==NULL)
        return nuevo;
    Paquete *aux = paquete;
    while(aux->siguiente != NULL)
        aux = aux->siguiente;
    aux->siguiente = nuevo;
    return paquete;
}
Paquete* nextPacket(Paquete* paquete){
    if(paquete==NULL){
        fprintf(stderr, "La lista esta vacia\n");
        return paquete;
    }
    free(paquete->data);
    Paquete *aux = paquete->siguiente;
    free(paquete);
    return aux;
}

Mac* crearMAC(unsigned char *direccion){
    Mac *nuevo = (Mac*) malloc(sizeof(Mac));
    if(nuevo==NULL){
        fprintf(stderr, "Ocurrio un error al manipular memoria dinamica\n");
        exit(-1);
    }
    for(i=0;i<6;i++)
        nuevo->direccion[i] = direccion[i];
    nuevo->cuenta = 1;
    nuevo->siguiente = NULL;
    return nuevo;
}

Mac* countMAC(Mac* lista, unsigned char *direccion){
    Mac *aux = lista;
    unsigned short int bandera = 1;
    while(aux!=NULL){
        for(i=0;i<6;i++)
            bandera &= direccion[i]==aux->direccion[i];
        if(bandera==1){
            aux->cuenta++;
            return lista;
        }
        aux = aux->siguiente;
    }
    Mac *nuevo = crearMAC(direccion);
    if(lista==NULL)
        return nuevo;
    nuevo->siguiente = lista;
    return nuevo;
    
}

Mac* liberarMAC(Mac* lista){
    Mac* aux;
    while(lista!= NULL){
        aux = lista;
        lista = lista->siguiente;
        free(aux);
    }
    return NULL;
}

void printMAC(Mac* lista){
    Mac* aux = lista;
    while(aux!=NULL){
        for(i=0; i<6; i++)
            fprintf(archivo, "%02x:", aux->direccion[i]);
        fprintf(archivo, "\b   %d paquetes enviados\n", aux->cuenta);
        aux = aux->siguiente;
    }
}

void *funcion_hilo(void *argumento){
    while(leidos<npack){
        if(j<=leidos || lista==NULL){
            sleep(1);
            continue;
        }
        analizarPaquete(lista->data, lista->size);
        lista = nextPacket(lista);
        leidos++;
    }

    pthread_exit("Analisis terminado.");
}