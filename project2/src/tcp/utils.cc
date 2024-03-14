#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <ctime>

using namespace std;

int get_publichostname(std::string *hostname) {

  int fd;
  struct if_nameindex *curif, *ifs;
  struct ifreq req;
  char if_name_buff[20];
  char *ip_addr;
  char ip_addr_buff[18];

  if ( hostname == NULL ) {
    fprintf(stderr, "hostname is null");
    return -1;
  }

  if( (fd = socket(PF_INET, SOCK_STREAM, 0)) == -1 ) {
    perror("socket");
    return -1;
  } 

  ifs = if_nameindex();
  if( ifs == NULL ) {
    perror("if_nameindex");
    return -1;
  }

  for( curif = ifs; curif && curif->if_name ; curif++ ) {
    strncpy(req.ifr_name, curif->if_name, IFNAMSIZ);
    req.ifr_name[IFNAMSIZ] = 0;
    if (ioctl(fd, SIOCGIFADDR, &req) < 0) {
      // perror("ioctl");
      continue;
    }

    memset(if_name_buff, 0, 20);
    memset(ip_addr_buff, 0, 18);

    memcpy(if_name_buff, curif->if_name, strlen(curif->if_name));
    ip_addr = inet_ntoa( ((struct sockaddr_in*) &req.ifr_addr)->sin_addr);
    memcpy(ip_addr_buff, ip_addr, strlen(ip_addr));

    // skip the loopback and 192.x addresses 
    *hostname = "undefined";
    if ( strncmp(ip_addr_buff, "0.", 2) == 0 ) {
      continue;
    } else if ( strncmp(ip_addr_buff, "127.", 4) == 0 ) {
      continue;
    } else if ( strncmp(ip_addr_buff, "192.", 4) == 0 ) {
      continue;
    } else {
      *hostname = string(ip_addr_buff);
      break;
    }

  }

  if_freenameindex(ifs);
  if( close(fd) == -1 ) {
    perror("close");
    return -1;
  }

  return 0;
}

int get_datetime(std::string *datetime, const char* format) {
  if ( datetime == NULL || format == NULL ) {
    return -1;
  }

  time_t t = time(0);
  struct tm *now = localtime( &t );
  char buf[80] = "";
  strftime(buf, sizeof(buf), format, now);

  *datetime = string(buf);
  return 0;
}
