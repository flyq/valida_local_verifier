use std::fs;

pub mod valida;

fn main() {
    println!("Hello, world!");
    let proof_bytes = fs::read("./llvm-valida-alpha-mac-build/output/fib.proof").unwrap();
    let executable_file = fs::read("./llvm-valida-alpha-mac-build/output/fib.out").unwrap();

    let res = valida::verify_valida_proof(proof_bytes, executable_file, None, None);
    println!("res: {:?}", res);
}
