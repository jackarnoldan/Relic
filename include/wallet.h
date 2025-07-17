#ifndef WALLET_H
#define WALLET_H

#include "relic.h"
#include <sqlite3.h>
#include <zlib.h>

bool init_relic_wallet();
bool store_relic_to_wallet(const Relic& relic);
bool load_relic_from_wallet(const std::string& serial, Relic& relic);
bool compress_relic_data(const nlohmann::json& j, std::vector<unsigned char>& compressed);
bool decompress_relic_data(const std::vector<unsigned char>& compressed, nlohmann::json& j);

#endif