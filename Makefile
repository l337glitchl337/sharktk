BIN := bin

all: $(BIN) cardshark sixshark sharkbait poolshark sharkdns

$(BIN):
	mkdir -p $(BIN)

cardshark: $(BIN)
	gcc -O2 -Wall -Wextra cardshark/cardshark.c -o $(BIN)/cardshark -lpthread
	cp cardshark/manuf $(BIN)/manuf

sixshark: $(BIN)
	gcc -O2 -Wall -Wextra -o $(BIN)/sixshark sixshark/sixshark.c

sharkbait: $(BIN)
	gcc -O2 -Wall -Wextra sharkbait/sharkbait.c -o $(BIN)/sharkbait

poolshark: $(BIN)
	gcc -O2 -Wall -Wextra -o $(BIN)/poolshark poolshark/poolshark.c -lpthread

sharkdns: $(BIN)
	gcc -Wall -Wextra -pedantic -std=c11 sharkdns/sharkdns.c -o $(BIN)/sharkdns

clean:
	rm -rf $(BIN)

TEST_BIN := tests/bin
CHECK_CFLAGS := $(shell pkg-config --cflags check)
CHECK_LIBS := $(shell pkg-config --libs check)

test: test-common test-cardshark test-sixshark test-sharkbait test-poolshark test-sharkdns

$(TEST_BIN):
	mkdir -p $(TEST_BIN)

test-common: $(TEST_BIN)
	gcc -Wall -Wextra $(CHECK_CFLAGS) tests/test_common.c -o $(TEST_BIN)/test_common $(CHECK_LIBS)
	$(TEST_BIN)/test_common

test-cardshark: $(TEST_BIN)
	gcc -Wall -Wextra $(CHECK_CFLAGS) tests/test_cardshark.c -o $(TEST_BIN)/test_cardshark $(CHECK_LIBS) -lpthread
	$(TEST_BIN)/test_cardshark

test-sixshark: $(TEST_BIN)
	gcc -Wall -Wextra $(CHECK_CFLAGS) tests/test_sixshark.c -o $(TEST_BIN)/test_sixshark $(CHECK_LIBS)
	$(TEST_BIN)/test_sixshark

test-sharkbait: $(TEST_BIN)
	gcc -Wall -Wextra $(CHECK_CFLAGS) tests/test_sharkbait.c -o $(TEST_BIN)/test_sharkbait $(CHECK_LIBS)
	$(TEST_BIN)/test_sharkbait

test-poolshark: $(TEST_BIN)
	gcc -Wall -Wextra $(CHECK_CFLAGS) tests/test_poolshark.c -o $(TEST_BIN)/test_poolshark $(CHECK_LIBS) -lpthread
	$(TEST_BIN)/test_poolshark

test-sharkdns: $(TEST_BIN)
	gcc -Wall -Wextra $(CHECK_CFLAGS) -pedantic -std=c11 tests/test_sharkdns.c -o $(TEST_BIN)/test_sharkdns $(CHECK_LIBS)
	$(TEST_BIN)/test_sharkdns

test-clean:
	rm -rf $(TEST_BIN)

.PHONY: all clean cardshark sixshark sharkbait poolshark sharkdns \
	test test-common test-cardshark test-sixshark test-sharkbait test-poolshark test-sharkdns test-clean
