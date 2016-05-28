CC := gcc
EXE := 802.11
CFLAGS := -Wall

$(EXE): main.o cpack.o print-802_11.o oui.o util.o print-ascii.o
	$(CC) -o $@ $^

main.o: main.c
cpack.o: cpack.c
print-802_11.o: print-802_11.c
oui.o: oui.c
util.o: util.c
print-ascii.o: print-ascii.c

clean:
	rm -f *.o $(EXE)
