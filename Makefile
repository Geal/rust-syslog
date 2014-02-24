build:
	mkdir -p build
	rustc --out-dir build -O src/syslog/lib.rs

test: build
	rustc -L build -o build/test --test src/syslog/test.rs
	./build/test

clean:
	rm -rf build
