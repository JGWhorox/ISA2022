SHELL = /usr/bin/env bash
NAME = flow
LOGIN = xgawro00
#---------------
all: 
	g++ -std=c++17 *.cpp -o $(NAME)

zip:
	tar -zcvf $(LOGIN).tar.gz *.cpp *.h *.pdf Makefile

clean:
	rm -f *.o