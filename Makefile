all: cardshark sixshark sharkbait poolshark sharkdns

cardshark:
	gcc cardshark/cardshark.c -o cardshark/cardshark -lpthread

sixshark:
	gcc -O2 -Wall -o sixshark/sixshark sixshark/sixshark.c

sharkbait:
	gcc sharkbait/sharkbait.c -o sharkbait/sharkbait

poolshark:
	gcc -o poolshark/poolshark poolshark/poolshark.c -lpthread

sharkdns:
	gcc -Wall -Wextra -pedantic -std=c11 sharkdns/sharkdns.c -o sharkdns/sharkdns

clean:
	rm -f cardshark/cardshark sixshark/sixshark sharkbait/sharkbait poolshark/poolshark sharkdns/sharkdns

.PHONY: all clean cardshark sixshark sharkbait poolshark sharkdns
