#include "profile.h"
#include <sqlite3.h>

bool update_user_profile(const std::string& pubkey, const std::string& action, UserProfile& profile) {
    if (!sanitize_input(pubkey) || !sanitize_input(action)) {
        log_audit_event("Invalid input for user profile: pubkey=" + pubkey + ", action=" + action);
        return false;
    }
    sqlite3* db;
    if (sqlite3_open("relic_profiles.db", &db) != SQLITE_OK) {
        log_audit_event("Failed to open profiles database: " + std::string(sqlite3_errmsg(db)));
        return false;
    }
    const char* create = "CREATE TABLE IF NOT EXISTS profiles (pubkey TEXT PRIMARY KEY, referrals INTEGER, transactions INTEGER, badges TEXT);";
    char* err_msg = nullptr;
    if (sqlite3_exec(db, create, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        log_audit_event("Failed to create profiles table: " + std::string(err_msg));
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return false;
    }
    sqlite3_stmt* select_stmt;
    const char* select = "SELECT referrals, transactions, badges FROM profiles WHERE pubkey = ?;";
    if (sqlite3_prepare_v2(db, select, -1, &select_stmt, nullptr) != SQLITE_OK) {
        log_audit_event("Failed to prepare profile select: " + std::string(sqlite3_errmsg(db)));
        sqlite3_close(db);
        return false;
    }
    if (sqlite3_bind_text(select_stmt, 1, pubkey.c_str(), -1, SQLITE_STATIC) != SQLITE_OK) {
        log_audit_event("Failed to bind profile select: pubkey=" + pubkey);
        sqlite3_finalize(select_stmt);
        sqlite3_close(db);
        return false;
    }
    profile.public_key = pubkey;
    profile.referrals = 0;
    profile.transactions = 0;
    if (sqlite3_step(select_stmt) == SQLITE_ROW) {
        profile.referrals = sqlite3_column_int(select_stmt, 0);
        profile.transactions = sqlite3_column_int(select_stmt, 1);
        const char* badges_json = (const char*)sqlite3_column_text(select_stmt, 2);
        if (badges_json) {
            try {
                nlohmann::json j = nlohmann::json::parse(badges_json);
                profile.badges = j.get<std::vector<std::string>>();
            } catch (...) {
                log_audit_event("Failed to parse badges JSON: pubkey=" + pubkey);
            }
        }
    }
    sqlite3_finalize(select_stmt);
    if (action == "referral") {
        profile.referrals++;
        if (profile.referrals >= 5) profile.badges.push_back("SuperReferrer");
        if (profile.referrals >= 50) profile.badges.push_back("EliteReferrer");
    } else if (action == "transaction") {
        profile.transactions++;
        if (profile.transactions >= 100) profile.badges.push_back("TopTrader");
        if (profile.transactions >= 1000) profile.badges.push_back("MasterTrader");
    } else {
        log_audit_event("Invalid profile action: " + action);
        sqlite3_close(db);
        return false;
    }
    sqlite3_stmt* stmt;
    const char* update = "INSERT OR REPLACE INTO profiles (pubkey, referrals, transactions, badges) VALUES (?, ?, ?, ?);";
    if (sqlite3_prepare_v2(db, update, -1, &stmt, nullptr) != SQLITE_OK) {
        log_audit_event("Failed to prepare profile update: " + std::string(sqlite3_errmsg(db)));
        sqlite3_close(db);
        return false;
    }
    nlohmann::json j_badges = profile.badges;
    std::string badges_str = j_badges.dump();
    if (sqlite3_bind_text(stmt, 1, pubkey.c_str(), -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 2, profile.referrals) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 3, profile.transactions) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 4, badges_str.c_str(), -1, SQLITE_STATIC) != SQLITE_OK) {
        log_audit_event("Failed to bind profile update: pubkey=" + pubkey);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        log_audit_event("Failed to execute profile update: pubkey=" + pubkey);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    log_audit_event("Updated user profile: pubkey=" + pubkey + ", action=" + action);
    return true;
}