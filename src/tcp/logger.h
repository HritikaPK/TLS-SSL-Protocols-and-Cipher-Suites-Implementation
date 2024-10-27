#ifndef LOGGER_H
#define LOGGER_H

#include <string>

class Logger {
 public:
  Logger(const std::string& logfilename);
  virtual ~Logger();

  int log(const std::string& msg) const;
  int log_raw(const std::string& msg) const;
  int log_raw(const char* msg, int msg_len) const;

 private:
  std::string logfilename_;
};

#endif // LOGGER_H
