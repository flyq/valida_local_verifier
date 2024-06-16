use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_dft::Radix2DitParallel;
use p3_field::{extension::BinomialExtensionField, Field};
use p3_fri::{FriConfig, TwoAdicFriPcs, TwoAdicFriPcsConfig};
use p3_keccak::Keccak256Hash;
use p3_mds::coset_mds::CosetMds;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon::Poseidon;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
use rand_pcg::Pcg64;
use rand_seeder::Seeder;
use valida_basic::BasicMachine;
use valida_cpu::MachineWithCpuChip;
use valida_elf::{load_executable_file, Program};
use valida_machine::__internal::p3_commit::ExtensionMmcs;
use valida_machine::{GlobalAdviceProvider, Machine, MachineProof, StarkConfigImpl};
use valida_program::MachineWithProgramChip;
use valida_static_data::MachineWithStaticDataChip;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 5>;
type PackedChallenge = BinomialExtensionField<<Val as Field>::Packing, 5>;

type Mds16 = CosetMds<Val, 16>;
type Perm16 = Poseidon<Val, Mds16, 16, 5>;

type MyHash = SerializingHasher32<Keccak256Hash>;

type MyCompress = CompressionFunctionFromHasher<Val, MyHash, 2, 8>;

type ValMmcs = FieldMerkleTreeMmcs<Val, MyHash, MyCompress, 8>;

type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

type Dft = Radix2DitParallel;

type Challenger = DuplexChallenger<Val, Perm16, 16>;

type MyFriConfig = TwoAdicFriPcsConfig<Val, Challenge, Challenger, Dft, ValMmcs, ChallengeMmcs>;

type Pcs = TwoAdicFriPcs<MyFriConfig>;

type MyConfig = StarkConfigImpl<Val, Challenge, PackedChallenge, Pcs, Challenger>;

pub fn verify_valida_proof(
    proof_bytes: Vec<u8>,
    executable_file: Vec<u8>,
    stack_height: Option<u32>,
    advice: Option<String>,
) -> Result<(), ()> {
    let machine = init_machine(executable_file, stack_height, advice);

    let proof: MachineProof<MyConfig> =
        ciborium::from_reader(proof_bytes.as_slice()).expect("Proof deserialization failed");

    machine.verify(&init_config(), &proof)
}

pub fn init_config() -> MyConfig {
    let mut rng: Pcg64 = Seeder::from("validia seed").make_rng();

    let mds16 = Mds16::default();

    let perm16 = Perm16::new_from_rng(4, 22, mds16, &mut rng);

    let hash = MyHash::new(Keccak256Hash {});
    let compress = MyCompress::new(hash);

    let val_mmcs = ValMmcs::new(hash, compress);

    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let dft = Dft::default();

    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 40,
        proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };

    let pcs = Pcs::new(fri_config, dft, val_mmcs);

    let challenger = Challenger::new(perm16);

    MyConfig::new(pcs, challenger)
}

pub fn init_machine(
    executable_file: Vec<u8>,
    stack_height: Option<u32>,
    advice: Option<String>,
) -> BasicMachine<BabyBear> {
    let mut machine = BasicMachine::<BabyBear>::default();

    let Program {
        code,
        data,
        initial_program_counter,
    } = load_executable_file(executable_file);
    machine.program_mut().set_program_rom(&code);
    machine.cpu_mut().fp = stack_height.unwrap_or(16777216);
    machine.cpu_mut().pc = initial_program_counter;
    machine.cpu_mut().save_register_state();
    machine.static_data_mut().load(data);

    // Run the program
    machine.run(&code, &mut GlobalAdviceProvider::new(&advice));
    machine
}
