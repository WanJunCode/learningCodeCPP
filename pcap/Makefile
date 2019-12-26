all: demo


demo: main.cpp HashCalc.cpp SessMgr.cpp
	clang++ main.cpp HashCalc.cpp SessMgr.cpp -o demo -lpcap -g


.PHONY:clean
clean:
	rm -rf demo core*
