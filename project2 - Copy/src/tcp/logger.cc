#include "logger.h"

#include <fstream>

#include "utils.h"

using namespace std;

Logger::Logger(const string& logfilename) {
  logfilename_ = logfilename;
}

Logger::~Logger() {

}

// log msg prepended with current time
int Logger::log(const string& msg) const {
  string datetime;
  get_datetime(&datetime, "%H:%M:%S:");
  string new_msg = datetime + msg;
  return log_raw(new_msg);
}

int Logger::log_raw(const string& msg) const {
  return log_raw(msg.c_str(), msg.length());
}

int Logger::log_raw(const char* msg, int msg_len) const {
  string msg_str = string(msg, msg_len);
  ofstream logfile;
  logfile.open(this->logfilename_.c_str(), ofstream::app);
  logfile << msg_str << endl;
  logfile.close();
  return 0;
}




