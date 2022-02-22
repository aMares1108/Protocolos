// Para compilar: gcc  Hilos.c -lpthread -o Hilos

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

void *funcion_hilo(void *argumento);
char mensaje[31] = "Este es un mensaje";

int main() {
    pthread_t id_hilo;
    void *valor_retorno;

    if(pthread_create(&id_hilo, NULL, funcion_hilo, (void*) mensaje)){
        printf("Problema en la creacion del hilo\n");
        exit(EXIT_FAILURE);
    }

    printf("Esperando a que termine el hilo hijo...\n");
    if(pthread_join(id_hilo, &valor_retorno)){
        printf("Problema al crear el enlace con otro hilo\n");
        exit(EXIT_FAILURE);
    }
    printf("El hilo que espera papa regreso!!\t%s\n",(char*)valor_retorno);
    printf("Nuevo mensaje: %s\n",mensaje);
    exit(EXIT_SUCCESS);
}

void *funcion_hilo(void *argumento){
    printf("El codigo de la funcion esta en ejecucion\n El argumento es: %s\n",(char*)argumento);
    printf("Proceso hijo: %li\n",pthread_self());
    sleep(3);
    strcpy(mensaje,"Mensaje cambiado por el hijo\n");
    pthread_exit("Hijo retorna. gracias");
}