#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include <string>
#include <fstream>
#include <iostream>

#include "ssl_server.h"

using namespace std;

#define NUM_THREADS 2

void* handle_client(void* args) {
  SSL* ssl_cxn = (SSL*)args;

  if ( ssl_cxn != NULL ) {
    string recv_msg;
    int code = ssl_cxn->recv(&recv_msg);

    printf("s: received '%s'%d\n", recv_msg.c_str(), code);

  }

  pthread_exit(NULL);
}


int main() {
  SslServer *s = new SslServer();
  if ( s->start() != 0 ) {
    cout << "s: couldn't start server" << endl;
    return 1;
  }
  // cout << "a" << endl;

  string hostname = s->get_hostname();
  int port = s->get_port();

  cout << "s: started on " << hostname << " " << port << endl;

  ofstream addrfile;
  addrfile.open("address.txt");
  addrfile << hostname << endl << port << endl;
  addrfile.close();
  // cout << "b" << endl;

  pthread_t threads[NUM_THREADS];
  for( int i = 0 ; i < NUM_THREADS ; i += 1 ) {
    SSL* client = s->accept();

    if ( client == NULL ) {
      cerr << "Error: couldn't accept" << endl;
      exit(1);
    }

    cout << "s: accepted " << i+1 << " client(s)" << endl;

    int retcode;
    retcode = pthread_create(&threads[i], NULL, handle_client, (void *)client);
    if ( retcode != 0 ) {
      perror("Error: can't create thread.\n");
      exit(1);
    }
  }
  // cout << "c" << endl;

  void* status;
  for( int i = 0 ; i < NUM_THREADS ; i += 1 ) {
    int retcode;

    retcode = pthread_join(threads[i], &status);
    if (retcode){
      cerr << "Error:unable to join," << retcode << endl;
      exit(1);
    }

    // cout << "Main: completed thread id :" << i ;
    // cout << "  exiting with status :" << status << endl;
  }

  cout << "s: broadcasting " << endl;

  if ( s->broadcast("Server says \"HELLO ALL\"") < 0 ) {
    cerr << "Error: couldn't broadcast" << endl;
    exit(1);
  }

  cout << "s: shutting down " << endl;

  if ( s->shutdown() != 0 ) {
    cerr << "Error: couldn't shut down" << endl;
    exit(1);
  }

  cout << "s: free-ing " << endl;

  sleep(2);

  delete s;

  cout << "s: exiting " << endl;

  return 0;
}