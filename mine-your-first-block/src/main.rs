use serde;
use serde_json;
use sha2;

// Transaction struct that may be overcomplicated right now. We will see
#[derive(Debug, Deserialize)]
struct Transaction {
    version: u32,
    locktime: u32,
    vin: Vec<Vin>,
    vout: Vec<Vout>,
}

#[derive(Debug, Deserialize)]
struct Vin {
    txid: String,
    vout: u32,
    prevout: Prevout,
    scriptsig: String,
    scriptsig_asm: String,
    witness: Vec<String>,
    is_coinbase: bool,
    sequence: u32,
}

#[derive(Debug, Deserialize)]
struct Prevout {
    scriptpubkey: String,
    scriptpubkey_asm: String,
    scriptpubkey_type: String,
    scriptpubkey_address: String,
    value: u64,
}

#[derive(Debug, Deserialize)]
struct Vout {
    scriptpubkey: String,
    scriptpubkey_asm: String,
    scriptpubkey_type: String,
    scriptpubkey_address: String,
    value: u64,
}

///
///

// TODO Make a deserialize_tx function with serde and serde_json
fn deserialize_tx() -> Result<Transaction, io::Error> {
    // code to deserialize a tx
}

// TODO Make a validate_tx function that returns true if tx is valid and throws out invalid tx
fn validate_tx(transaction: Transaction) -> bool {
    // Code to validate tx based
}

fn main() {
    println!("Hello, world!");
}

// Start processing transactions, validating them,
