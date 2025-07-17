CC = g++
   CFLAGS = -std=c++17 -Wall -O2 -g
   LIBS = -lssl -lcrypto -lsodium -lsqlite3 -lz -llua5.4 -lpaillier -ldilithium -lshamir -lqrencode -lnfc -lcudart
   INCLUDES = -Iinclude
   SOURCES = src/main.cpp src/relic.cpp src/merkle.cpp src/wallet.cpp src/crypto.cpp src/smart_contract.cpp src/profile.cpp
   TARGET = relic

   all: $(TARGET)

   $(TARGET): $(SOURCES)
       $(CC) $(CFLAGS) $(INCLUDES) $(SOURCES) -o $(TARGET) $(LIBS)

   clean:
       rm -f $(TARGET) *.o relic_wallet.db relic_burn_list.merkle relic_audit.log