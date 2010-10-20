#ifndef __PACKET_HEADER__
#include <stdint.h>

#define MAX_AVP_SIZE 4096
#define MAX_MSG_SIZE 40960

struct wire_header{
  uint8_t code;
  uint8_t id;
  uint16_t length;
  char auth[16];
};

struct wire_avp{
  uint8_t type;
  uint8_t length;
};


#endif

