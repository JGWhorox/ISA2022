#include <string>

#include "pcapparser.h"

#ifndef EXPORTER_H
#define EXPORTER_H

bool exportFlow(std::string address, uint16_t port, flowcachevalue val);

#endif