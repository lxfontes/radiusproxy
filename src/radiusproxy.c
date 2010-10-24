/*
  *  Copyright 2010 Lucas Fontes
  * 
  *  Licensed under the Apache License, Version 2.0 (the "License"); you may
  *  not use this file except in compliance with the License. You may obtain
  *  a copy of the License at
  * 
  *     http://www.apache.org/licenses/LICENSE-2.0
  * 
  *  Unless required by applicable law or agreed to in writing, software
  *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
  *  License for the specific language governing permissions and limitations
  *  under the License.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <resolv.h>
#include "md5.h"

#include "radiusproxy.h"

#include "ev.c"


struct radius_server server;




static void getMD5string(unsigned char *digest)
{
  int   i;
  
  for(i=0;i<16;i++)
  {
    printf("%02x",digest[i]);
  }
  
  printf("\n");
}

unsigned char *makeMD5(unsigned char *digest,void *data,int dataLen)
{
  md5_state_t state;

  md5_init(&state);
  md5_append(&state,(const md5_byte_t *)data,dataLen);
  md5_finish(&state,digest);
  
  return digest;
}

static void consumer_cb(EV_P_ ev_io *w, int revents) {
  struct radius_peer *peer = (struct radius_peer *)w;
  struct sockaddr_in addr;
  int addr_len = sizeof(addr);

  struct radius_request packet;

  struct wire_header *header = (struct wire_header *)packet.buffer;

  packet.size = recvfrom(w->fd, packet.buffer, MAX_MSG_SIZE, MSG_DONTWAIT, (struct sockaddr*) &addr, &addr_len);

  struct radius_request *original_request;
  int id = header->id;
  HASH_FIND_INT(peer->pending,&id,original_request);
  assert(original_request != NULL);

  HASH_DEL(peer->pending,original_request);

  ev_timer_stop(EV_A_ &original_request->tmw);

  free(original_request);
}

static void send_request(struct radius_request *packet){

  sendto(packet->peer->iow.fd, packet->buffer, packet->size, 
      MSG_DONTWAIT, 
      (struct sockaddr*) &packet->peer->addr, sizeof(packet->peer->addr));

  packet->retries++;
  packet->tmw.repeat = server.retrysecs;

}

static void idle_cb(EV_P_ ev_timer *w, int revents){
  struct radius_request *packet = (struct radius_request *)w;
  struct wire_header *header = (struct wire_header *)packet->buffer;

  if(packet->retries >= server.retrycount){
    char ipstr[16];
    int port;
    struct sockaddr_in *s = (struct sockaddr_in *)&packet->peer->addr;
    port = ntohs(s->sin_port);
    inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof(ipstr));
    //delete packet. log.
    printf("%s:%d timed out...\n",ipstr,port);
    ev_timer_stop(EV_A_ &packet->tmw);
    HASH_DEL(packet->peer->pending,packet);
  }else{
    send_request(packet);
    ev_timer_again(EV_A_ &packet->tmw);
  }
}

  
static void producer_cb(EV_P_ ev_io *w, int revents) {
  struct sockaddr_in addr;
  int addr_len = sizeof(addr);

  struct radius_peer *peer = (struct radius_peer *)w;
  struct radius_request packet;
  packet.peer = peer;

  struct wire_header *header = (struct wire_header *)packet.buffer;

  packet.size = recvfrom(w->fd, packet.buffer, MAX_MSG_SIZE, MSG_DONTWAIT, (struct sockaddr*) &addr, &addr_len);


  //received from NAS, span multiple requests
  struct radius_peer *new_peer= NULL;
  LL_FOREACH(server.peers,new_peer){
    struct radius_request *new_packet = malloc(sizeof(struct radius_request));
    new_packet->size = packet.size;
    new_packet->retries = 0;
    new_packet->peer = new_peer;
    new_packet->id = header->id;
    memcpy(&new_packet->buffer,packet.buffer,packet.size);
    header =(struct wire_header *) new_packet->buffer;

    HASH_ADD_INT(new_peer->pending,id,new_packet);

    ev_init(&new_packet->tmw,idle_cb);
    send_request(new_packet);
    ev_timer_again(EV_A_ &new_packet->tmw);
  }

  {
    char hash[40]; //TODO , shouldnt be fixed size

    uint16_t rpos = 0;
    struct wire_header reply;

    bzero(&reply,sizeof(reply));
    reply.id = header->id;
    reply.code = 5;
    reply.length = htons(20);

    memcpy(&reply.auth,header->auth,sizeof(reply.auth));

    memcpy(&hash,&reply,sizeof(reply));
    memcpy(hash + 20,&server.secret,strlen(server.secret));

    makeMD5((unsigned char *)&reply.auth,hash, sizeof(reply) + strlen(server.secret));
    rpos = 20;

  sendto(w->fd, &reply,sizeof(reply) ,
      MSG_DONTWAIT, 
      (struct sockaddr*) &addr, sizeof(addr));
  }

}

struct radius_peer *new_radius_peer(char *name,char *port){
  struct radius_peer *ret;
  struct addrinfo hints, *res=NULL,*rp=NULL;
  int result = 0;

  ret = malloc(sizeof(struct radius_peer));

  memset(&hints, 0x00, sizeof(hints));
  hints.ai_flags    = AI_NUMERICSERV;
  hints.ai_family   = PF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  result = getaddrinfo(name, port, &hints, &res);

  if (result){
    fprintf(stderr,"Error looking up %s\n",name);
    return NULL;
  }

  int s = 0;

  for(rp = res;rp!=NULL;rp = rp->ai_next){
    s = socket(rp->ai_family,rp->ai_socktype,
        rp->ai_protocol);
    memcpy(&ret->addr,rp->ai_addr,sizeof(ret->addr));
    if(s == -1)
      continue;
    else
      break;
  }
  assert(s > 0);

  freeaddrinfo(res);

  ret->fd = s;
  ret->pending = NULL;
  return ret;
}

int main(int argc,char **argv){
  int c;
  char *host, *port;
  char *localhost,*localport;
  struct radius_peer *remote = NULL;

  opterr = 0;

  server.retrysecs = 1;
  server.retrycount = 3;
  server.peers = NULL;

  sprintf(server.secret,"testing123");
  localhost = "0.0.0.0";
  localport = "1813";

  struct ev_loop *loop = ev_default_loop(0);

  while ((c = getopt (argc, argv, "b:s:f:h")) != -1){
    switch(c){
      case 'b':
        localhost = optarg;
        localport = index(localhost,':');
        if(localport != NULL){
          *localport = '\0';
          localport++;
        }else{
          localport="1813";
        }
        break;
      case 's':
        snprintf(server.secret,16,"%s",optarg);
        break;
      case 'f':
        host = optarg;
        port = index(host,':');
        if(port != NULL){
          *port = '\0';
          port++;
        }else{
          port="1813";
        }

        printf("Adding watcher %s:%s\n",host,port);
        /* one watcher per server */
        remote = new_radius_peer(host,port);
        ev_io_init(&remote->iow, consumer_cb, remote->fd, EV_READ);
        ev_io_start(loop,&remote->iow);
        LL_APPEND(server.peers,remote);
        break;
      case 'h':
      default:
        printf("%s -b ip:port -s secret -f ip:port [-f ip:port]\n",argv[0]);
        printf("\t -b Local IP and port. Default %s:%s.\n",localhost,localport);
        printf("\t -s Shared secret. Default %s.\n",server.secret);
        printf("\t -f Remote IP and port. Can be repeated N times.\n");
        exit(0);
    }
  }
  
  if(server.peers == NULL){
    fprintf(stderr,"Missing remote peers\n");
    exit(1);
  }

  printf("Binding proxy on %s:%s\n",localhost,localport);
  server.local = new_radius_peer(localhost,localport);

  if (bind(server.local->fd, (struct sockaddr*) &server.local->addr, sizeof(server.local->addr)) != 0)
    perror("bind");

  ev_io udp_watcher;
  ev_io_init(&udp_watcher, producer_cb, server.local->fd, EV_READ);
  ev_io_start(loop, &udp_watcher);

  ev_loop(loop, 0);

  return EXIT_SUCCESS;
}
