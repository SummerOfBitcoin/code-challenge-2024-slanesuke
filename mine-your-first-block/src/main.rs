use serde::Deserialize;
use serde_json;
use sha2::{Digest as ShaDigest, Sha256};
use std::fs::File;
use std::io::Read;
use ripemd::{Digest as RipemdDigest, Ripemd160};


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

// Coinbase Transaction struct
// I'm reading that the txid of the coinbase tx is all zeros.
// The coinbase txid for input (VIN) is always "0000000000000000000000000000000000000000000000000000000000000000"
// The vout for Vin struct is "ffffffff"
// then lock the output to my own public key using a P2PK locking script (which is the typical
// locking script used for coinbase transactions early on in the blockchain).

// struct CoinbaseTx {
//     version: String,
//     locktime: String,
//     vin: Vec<Vin>,
//     vout: Vec<Vout>,
//
// }
///

// TODO Make a deserialize_tx function with serde and serde_json
// First just  working  with one tx so I can learn
fn deserialize_tx(filename: &str) -> Result<Transaction, Box<dyn std::error::Error>> {
    //  Open the file of a tx
    let mut file = File::open(filename)?;

    let mut json_string = String::new();
    file.read_to_string(& mut json_string)?;

    let tx: Transaction = serde_json::from_str(&json_string)?;

    Ok(tx)
}

// TODO Make a validate_tx function that returns true if tx is valid and throws out invalid tx
// A Valid transaction must have:::::::
// 1.  the sum of the input amounts must be greater than or equal to the sum of the output amounts.
       // The difference, if any, is called a transaction fee
// 2. the signatures are correct and match


fn validate_tx(transaction: &Transaction) -> bool {

    // If the input value in sats is less than the output value then the transaction is already
    // invalid. the sum of the input must be greater than the sum of the output the difference is
    // the transaction fee. need to filter out higher tx fees later to include in block
    let input_value: u64 = transaction.vin.iter().map(|vin| vin.prevout.value).sum();
    let output_value: u64 = transaction.vout.iter().map(|vout| vout.value).sum();
    if input_value < output_value {
        return false;
    }

    // Verify if scriptpubkey_asm returns true
    // will this work as for outputs in transaction outputs? verify if this is correct
    for vout in &transaction.vout {
        if !verify_script(&vout.scriptpubkey_asm) {
            return false;
        }
    }
    // if all verifications pass the transaction is validated and returns true or OK
    true
}

// TODO make a function that verifies if a script returns OK
fn verify_script(script: &str) -> bool {
    // Verify the script based off grokking bitcoin chapter 5
    // look over OP_CODES or operators
    true
}

fn main() {
    // Path to one transaction
    let path = "../mempool/0a3c3139b32f021a35ac9a7bef4d59d4abba9ee0160910ac94b4bcefb294f196.json";

    match deserialize_tx(path) {
        Ok(tx) => println!("Deserialized Transaction is \n {:#?}", tx),
        Err(e) => eprintln!("Error!!! {}", e),
    }
}

// TODO: Creating the block output.txt
// the script must generate an output file named output.txt with the following structure:
//
// First line: The block header.
// Second line: The serialized coinbase transaction.
// Following lines: The transaction IDs (txids) of the transactions mined in the block, in order.
//  The first txid should be that of the coinbase transaction

