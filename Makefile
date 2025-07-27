build: ./src/*
	mkdir -p bin
	cc -O3 -o ./bin/kr ./src/*.c -w

clean:
	rm -f ./bin/*
