# valida_local_verifier

```sh
cd ./llvm-valida-alpha-mac-build

./clang -c -target delendum ./examples/fib.c -o output/fib.o

./ld.lld --script=valida.ld -o output/fib.out output/fib.o

valida run output/fib.out output/fib.log

valida prove output/fib.out output/fib.proof

valida verify output/fib.out output/fib.proof

cd ..

cargo run --release
```


