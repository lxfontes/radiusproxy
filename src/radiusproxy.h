#ifndef __RADIUSPROXY_H__
#define __RADIUSPROXY_H__
#include "ev.h"
#include "packetheader.h"
#include "uthash.h"
#include "utlist.h"


struct radius_request;

struct radius_peer{
  ev_io iow;
  int fd;
  struct sockaddr addr;
  struct radius_request *pending;
  struct radius_peer *next;
};

struct radius_request{
  ev_timer tmw;
  int id;
  struct radius_peer *peer;
  size_t size;
  uint8_t retries;
  UT_hash_handle hh;
  unsigned char buffer[MAX_MSG_SIZE];
};


struct radius_server{
  struct radius_peer *peers;
  struct radius_peer *local;
  char secret[16];
  in_addr_t nasip;
  int retrysecs;
  int retrycount;
};

#endif

