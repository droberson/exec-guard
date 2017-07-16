all:
	gcc -shared -fPIC exec-guard.c -o exec-guard.so -ldl

clean:
	rm -rf *.so *~
