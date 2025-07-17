#ifndef PROFILE_H
#define PROFILE_H

#include "relic.h"
#include <sqlite3.h>

bool update_user_profile(const std::string& pubkey, const std::string& action, UserProfile& profile);

#endif