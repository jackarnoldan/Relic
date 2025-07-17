#include "relic/wallet.h"
#include <sqlite3.h>
#include <zlib.h>
#include <sys/file.h>

static sqlite3* wallet_db = nullptr;

bool init_relic_wallet() {
    if (sqlite3_open("relic_wallet.db", &wallet_db) != SQLITE_OK) {
        log_audit_event("Failed to open wallet database: " + std::string(sqlite3_errmsg(wallet_db)));
        return false;
    }
    const char* create = "CREATE TABLE IF NOT EXISTS relics (serial TEXT PRIMARY KEY, data BLOB);";
    char* err_msg = nullptr;
    if (sqlite3_exec(wallet_db, create, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        log_audit_event("Failed to create wallet table: " + std::string(err_msg));
        sqlite3_free(err_msg);
        sqlite3_close(wallet_db);
        wallet_db = nullptr;
        return false;
    }
    log_audit_event("Initialized wallet database");
    return true;
}

bool store_relic_to_wallet(const Relic& relic) {
    if (!wallet_db && !init_relic_wallet()) {
        log_audit_event("Failed to initialize wallet for storing relic: serial=" + relic.serial);
        return false;
    }
    nlohmann::json j = relic_to_json(relic);
    std::vector<unsigned char> compressed;
    if (!compress_relic_data(j, compressed)) {
        log_audit_event("Failed to compress relic data: serial=" + relic.serial);
        return false;
    }
    sqlite3_stmt* stmt;
    const char* insert = "INSERT OR REPLACE INTO relics (serial, data) VALUES (?, ?);";
    if (sqlite3_prepare_v2(wallet_db, insert, -1, &stmt, nullptr) != SQLITE_OK) {
        log_audit_event("Failed to prepare SQL statement: " + std::string(sqlite3_errmsg(wallet_db)));
        return false;
    }
    if (sqlite3_bind_text(stmt, 1, relic.serial.c_str(), -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_blob(stmt, 2, compressed.data(), compressed.size(), SQLITE_STATIC) != SQLITE_OK) {
        log_audit_event("Failed to bind SQL parameters: serial=" + relic.serial);
        sqlite3_finalize(stmt);
        return false;
    }
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        log_audit_event("Failed to execute SQL insert: serial=" + relic.serial);
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    log_audit_event("Stored relic to wallet: serial=" + relic.serial);
    return true;
}

bool load_relic_from_wallet(const std::string& serial, Relic& relic) {
    if (!wallet_db && !init_relic_wallet()) {
        log_audit_event("Failed to initialize wallet for loading relic: serial=" + serial);
        return false;
    }
    sqlite3_stmt* stmt;
    const char* select = "SELECT data FROM relics WHERE serial = ?;";
    if (sqlite3_prepare_v2(wallet_db, select, -1, &stmt, nullptr) != SQLITE_OK) {
        log_audit_event("Failed to prepare SQL select: " + std::string(sqlite3_errmsg(wallet_db)));
        return false;
    }
    if (sqlite3_bind_text(stmt, 1, serial.c_str(), -1, SQLITE_STATIC) != SQLITE_OK) {
        log_audit_event("Failed to bind SQL parameter: serial=" + serial);
        sqlite3_finalize(stmt);
        return false;
    }
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        log_audit_event("Relic not found in wallet: serial=" + serial);
        sqlite3_finalize(stmt);
        return false;
    }
    const unsigned char* data = (const unsigned char*)sqlite3_column_blob(stmt, 0);
    int size = sqlite3_column_bytes(stmt, 0);
    std::vector<unsigned char> compressed(data, data + size);
    nlohmann::json j;
    if (!decompress_relic_data(compressed, j)) {
        log_audit_event("Failed to decompress relic data: serial=" + serial);
        sqlite3_finalize(stmt);
        return false;
    }
    try {
        relic = j.get<Relic>();
    } catch (const std::exception& e) {
        log_audit_event("Failed to parse relic JSON: serial=" + serial + ", error=" + e.what());
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    log_audit_event("Loaded relic from wallet: serial=" + serial);
    return true;
}

bool compress_relic_data(const nlohmann::json& j, std::vector<unsigned char>& compressed) {
    std::string json_str = j.dump();
    z_stream stream = {0};
    if (deflateInit(&stream, Z_BEST_COMPRESSION) != Z_OK) {
        log_audit_event("Failed to initialize zlib compression");
        return false;
    }
    stream.next_in = (Bytef*)json_str.data();
    stream.avail_in = json_str.size();
    std::vector<unsigned char> buffer(1024);
    do {
        stream.next_out = buffer.data();
        stream.avail_out = buffer.size();
        if (deflate(&stream, Z_FINISH) == Z_STREAM_ERROR) {
            log_audit_event("Zlib compression failed");
            deflateEnd(&stream);
            return false;
        }
        compressed.insert(compressed.end(), buffer.data(), buffer.data() + (buffer.size() - stream.avail_out));
    } while (stream.avail_out == 0);
    deflateEnd(&stream);
    log_audit_event("Compressed relic data: size=" + std::to_string(compressed.size()));
    return true;
}

bool decompress_relic_data(const std::vector<unsigned char>& compressed, nlohmann::json& j) {
    z_stream stream = {0};
    if (inflateInit(&stream) != Z_OK) {
        log_audit_event("Failed to initialize zlib decompression");
        return false;
    }
    stream.next_in = (Bytef*)compressed.data();
    stream.avail_in = compressed.size();
    std::vector<unsigned char> buffer(1024);
    std::string json_str;
    do {
        stream.next_out = buffer.data();
        stream.avail_out = buffer.size();
        if (inflate(&stream, Z_NO_FLUSH) == Z_STREAM_ERROR) {
            log_audit_event("Zlib decompression failed");
            inflateEnd(&stream);
            return false;
        }
        json_str.append((char*)buffer.data(), buffer.size() - stream.avail_out);
    } while (stream.avail_out == 0);
    inflateEnd(&stream);
    try {
        j = nlohmann::json::parse(json_str);
    } catch (const std::exception& e) {
        log_audit_event("Failed to parse decompressed JSON: " + std::string(e.what()));
        return false;
    }
    log_audit_event("Decompressed relic data: size=" + std::to_string(json_str.size()));
    return true;
}