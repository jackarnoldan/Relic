#ifndef SMART_CONTRACT_H
#define SMART_CONTRACT_H

#include "relic.h"
#include <lua.hpp>

bool execute_smart_contract(const Relic& relic, const std::vector<unsigned char>& input, std::vector<unsigned char>& output);

#endif