BIN := bin

all: $(BIN) cardshark sixshark sharkbait poolshark sharkdns

$(BIN):
	mkdir -p $(BIN)

cardshark: $(BIN)
	gcc -O2 -Wall -Wextra cardshark/cardshark.c -o $(BIN)/cardshark -lpthread

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

.PHONY: all clean cardshark sixshark sharkbait poolshark sharkdns
