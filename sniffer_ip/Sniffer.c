// Para compilar: gcc  Hilos.c -lpthread -o Hilos
// Para ejecutar: sudo ./Sniffer 2 enp0s10

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>
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
    struct in_addr direccion;
    unsigned int cuenta_s;
    unsigned int cuenta_d;
    struct mac *siguiente;
} Mac;

Mac* countMAC(Mac* lista, struct in_addr direccion, unsigned short int source);
Mac* liberarMAC(Mac* lista);
void printMAC(Mac* lista);
Paquete* addPacket(Paquete* paquete, char* buffer, int size);
Paquete* nextPacket(Paquete* paquete);
void *funcion_hilo(void *argumento);
void analizarPaquete(char * buffer, int size);
void printData(char * data, int size);

Paquete *lista = NULL;
Mac* dirs = NULL;
FILE* archivo;
int leidos = 0;
int size = 0;
int icmp = 0;
int igmp = 0;
int ip = 0;
int tcp = 0;
int udp = 0;
int ipv6 = 0;
int ospf = 0;
int sctp = 0;
// int flujo = 0;
// int seg = 0;
int count_size[] = {0, 0, 0, 0, 0};
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
        fprintf(stderr, "Unable to open socket to %s %d\n", argv[2], sock);
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
        fprintf(stderr, "Problema al crear el enlace con otro hilo\n");
        exit(EXIT_FAILURE);
    }

    // fprintf(archivo, "Total(%d):  IEEE 802.3(%d)  Ethernet II(%d)\nIPv4: %d\tIPv6: %d\tARP: %d\tControl de flujo: %d\tSeguridad MAC: %d\n", leidos, eth1, eth2, ip4, ip6, arp, flujo, seg);
    printMAC(dirs);
    liberarMAC(dirs);

    fprintf(archivo, "\n----Conteo de paquetes:----\n%d ICMP\n%d IGMP\n%d IP\n%d TCP\n%d UDP\n%d IPv6\n%d OSPF\n%d SCTP\n", icmp, igmp, ip, tcp, udp, ipv6, ospf, sctp);
    fprintf(archivo, "----Paquetes por tamano---\n0-159  %d\n160-639  %d\n640-1279  %d\n1280-5119  %d\n5120 o mayor  %d\n", count_size[0], count_size[1], count_size[2], count_size[3], count_size[4]);
    fprintf(archivo, "Total de paquetes analizados: %d\n",leidos);

    fclose(archivo);

    exit(EXIT_SUCCESS);
}

void analizarPaquete(char * buffer, int size){
    unsigned short int proto;
    struct ethhdr *ethernet;
    struct iphdr *iph;

    ethernet = (struct ethhdr*) buffer;
    proto = ethernet->h_proto;
    proto = (proto&0xff00)>>8 | (proto&0x00ff)<<8;

    if(proto==0x800){
        iph = (struct iphdr*) (buffer+sizeof(struct ethhdr));
        iph->tot_len = htons(iph->tot_len);
        iph->id = htons(iph->id);
        iph->check = htons(iph->check);
        iph->frag_off = htons(iph->frag_off);
        struct in_addr source;
        source.s_addr = iph->saddr;
        struct in_addr destiny;
        destiny.s_addr = iph->daddr;
        dirs = countMAC(dirs, source, 1);
        dirs = countMAC(dirs, destiny, 0);
        if((iph->tot_len-iph->ihl*4)<160){
            count_size[0]++;
        } else if((iph->tot_len-iph->ihl*4)<640){
            count_size[1]++;
        } else if((iph->tot_len-iph->ihl*4)<1280){
            count_size[2]++;
        } else if((iph->tot_len-iph->ihl*4)<5120){
            count_size[3]++;
        } else{
            count_size[4]++;
        }
        // printf("The IP address is %s\n", inet_ntoa(ip_addr));
        fprintf(archivo, "Saddr: %s,", inet_ntoa(source));
        fprintf(archivo, " Daddr: %s\n", inet_ntoa(destiny));
        fprintf(archivo, "HLen: %d Total_Len: %d ID: %d TTL: %d\n", iph->ihl*4, iph->tot_len, iph->id, iph->ttl);
        fprintf(archivo, "Procolo de capa superior(%d): ", iph->protocol);
        switch (iph->protocol) {
        case 1:
            fprintf(archivo, "ICMP");
            icmp++;
            break;
        case 2:
            fprintf(archivo, "IGMP");
            igmp++;
            break;
        case 4:
            fprintf(archivo, "IP");
            ip++;
            break;
        case 6:
            fprintf(archivo, "TCP");
            tcp++;
            break;
        case 17:
            fprintf(archivo, "UDP");
            udp++;
            break;
        case 41:
            fprintf(archivo, "IPv6");
            ipv6++;
            break;
        case 89:
            fprintf(archivo, "OSPF");
            ospf++;
            break;
        case 132:
            fprintf(archivo, "SCTP");
            sctp++;
            break;
        default:
            fprintf(archivo, "Protocolo no identificado");
        }
        fprintf(archivo, "\nCarga util: %d\nTipo de servicio(0x%02x): ", iph->tot_len-iph->ihl*4, iph->tos);
        switch (iph->tos>>5)
        {
        case 0:
            fprintf(archivo, "De rutina");
            break;
        case 1:
            fprintf(archivo, "Prioritario");
            break;
        case 2:
            fprintf(archivo, "Inmediato");
            break;
        case 3:
            fprintf(archivo, "Relampago (flash)");
            break;
        case 4:
            fprintf(archivo, "Invalidacion relampago (flash override)");
            break;
        case 5:
            fprintf(archivo, "Critico");
            break;
        case 6:
            fprintf(archivo, "Control de interred");
            break;
        case 7:
            fprintf(archivo, "Control de red");
            break;
        
        default:
            fprintf(archivo, "(Error) Precedencia no identificada");
            break;
        }
        fprintf(archivo, ", ");
        if ((iph->tos&0b11110)==0){
            fprintf(archivo, "Servicio normal");
        } else {
            if ((iph->tos&0b10000)!=0){
                fprintf(archivo, "Minimiza el retardo, ");
            }
            if ((iph->tos&0b01000)!=0){
                fprintf(archivo, "Maximiza el rendimiento, ");
            }
            if ((iph->tos&0b00100)!=0){
                fprintf(archivo, "Maximiza la fiabilidad, ");
            }
            if ((iph->tos&0b00010)!=0){
                fprintf(archivo, "Minimiza el coste monetario");
            }
        }
        fprintf(archivo, "\nFragmentacion: ");

        if ((iph->frag_off&0x2000)==0){
            if ((iph->frag_off&0x1fff)==0){
                fprintf(archivo, "Unico fragmento");
            } else{
                fprintf(archivo, "Ultimo fragmento");
            } 
        } else{
            if ((iph->frag_off&0x1fff)==0){
                fprintf(archivo, "Primer fragmento");
            } else{
                fprintf(archivo, "Fragmento intermedio");
            } 
        }
        fprintf(archivo, " (Primer byte: %d Ultimo byte: %d)\n\n", (iph->frag_off&0x1fff)*8, (iph->frag_off&0x1fff)*8 + iph->tot_len-1);
        
        // printData(buffer, size);
    }
}

void printData(char * data, int size){
    int i;
    int row_size = 4;
    unsigned short int datum;
    // for(i=0; i<size; i++){
    //     datum = data[i] & 0xff;
    //     // printf("%02x ", datum);
    //     if(datum>=32 && datum<=127)
    //         printf("%c ", datum);
    //     else
    //         printf(". ");
    //     if(i%row_size==row_size-1) printf("\n");
    // }
    printf("\n");
    for(i=14; i<34; i++){
        printf("%02x ", data[i]&0xff);
        if((i-14)%row_size==row_size-1) printf("\n");
    }
    printf("\n");
}

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

Mac* crearMAC(struct in_addr direccion){
    Mac *nuevo = (Mac*) malloc(sizeof(Mac));
    if(nuevo==NULL){
        fprintf(stderr, "Ocurrio un error al manipular memoria dinamica\n");
        exit(-1);
    }
    nuevo->direccion = direccion;
    nuevo->cuenta_s = 0;
    nuevo->cuenta_d = 0;
    nuevo->siguiente = NULL;
    return nuevo;
}

Mac* countMAC(Mac* lista, struct in_addr direccion, unsigned short int source){
    Mac *aux = lista;
    while(aux!=NULL){
        if(direccion.s_addr==aux->direccion.s_addr){
            if(source==0)
                aux->cuenta_d++;
            else
                aux->cuenta_s++;
            return lista;
        }
        aux = aux->siguiente;
    }
    Mac *nuevo = crearMAC(direccion);
    if(source==0)
        nuevo->cuenta_d++;
    else
        nuevo->cuenta_s++;
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
    fprintf(archivo, "----Resumen por direcciones----\n");
    while(aux!=NULL){
        fprintf(archivo, "%s", inet_ntoa(aux->direccion));
        fprintf(archivo, "  %d paquetes enviados, %d paquetes recibidos\n", aux->cuenta_s, aux->cuenta_d);
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