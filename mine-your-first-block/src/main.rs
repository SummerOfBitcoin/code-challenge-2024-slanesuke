use std::fmt::Debug;
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

    // Making a stack for the op_code opperation
    let mut stack: Vec<Vec<u8>> = Vec::new();

    // Loop through the script and match the OP_CODEs
    for op in script.split_whitespace() {
        match op {
            "OP_DUP" => {
                // If the stack is empty return false
                // Otherwise clone the last item on the stack and push it to the stack
                if let Some(data) = stack.last() {
                    stack.push(data.clone())
                } else {
                    return false
                }
            }
            "OP_HASH160"  => {
                // If the stack is empty return false
                // Otherwise take the last item from the stack, hash it with sha256 then ripemd160
                // and push it to the stack
                if let Some(pubkey) = stack.pop() {
                    let hash = ripemd160(sha256(pubkey.clone()));
                    stack.push(hash);
                } else {
                    return false
                }
            }
            "OP_EQUALVERIFY" => {
                // if stack is less than 2 return false
                if stack.len() < 2 {
                    return false;
                }
                // Otherwise pop the last two items from the stack and compare them
                // if they are not equal return false, if they are just continue
                let stack_item1 = stack.pop().unwrap();
                let stack_item2 = stack.pop().unwrap();
                if stack_item1 != stack_item2 {
                    return false;
                }

            }
            _ => {
                // If it's not an operator,it'a ordinary data (like sig or pubkey) and push it onto the stack
                // Verify !!!
                let data = hex::decode(op).unwrap_or_default(); // Convert hex string to bytes
                stack.push(data);
            }
        }
    }
    // Check final result
    // If the stack has only one element and it's not empty, transaction is valid
    stack.len() == 1 && !stack.is_empty()
}

fn ripemd160(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn sha256(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn main() {
    // Path to one transaction
    let path = "../mempool/0a3fd98f8b3d89d2080489d75029ebaed0c8c631d061c2e9e90957a40e99eb4c.json";

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

