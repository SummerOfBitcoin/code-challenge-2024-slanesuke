/// TODO
/// FIGURE OUT HOW TO VERIFY THE SIGNATURE OF A TRANSACTION UGHH


use std::fmt::Debug;
use serde::Deserialize;
use serde_json;
use sha2::{Digest as ShaDigest, Sha256};
use std::fs::File;
use std::io::{self, Read, read_to_string, Write};
use ripemd::Ripemd160;
// use ripemd::{Digest as RipemdDigest, Ripemd160};
use std::fs::OpenOptions;


// Unsure if i need to use the extern crate for secp256k1
extern crate secp256k1;
use secp256k1::{PublicKey, Secp256k1, Message};
use std::error::Error;
use secp256k1::ecdsa::Signature;


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
    witness: Option<Vec<String>>,
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





// First just  working  with one tx so I can learn
fn deserialize_tx(filename: &str) -> Result<Transaction, Box<dyn Error>> {
    //  Open the file of a tx
    let mut file = File::open(filename)?;

    let mut json_string = String::new();
    file.read_to_string(& mut json_string)?;

    let tx: Transaction = serde_json::from_str(&json_string)?;

    // return a transaction if the deserialization is successful
    Ok(tx)
}








fn validate_tx(transaction: &Transaction) -> Result<bool, Box<dyn Error>> {

    // If the input value in sats is less than the output value then the transaction is already
    // invalid. the sum of the input must be greater than the sum of the output the difference is
    // the transaction fee. need to filter out higher tx fees later to include in block
    let input_value: u64 = transaction.vin.iter().map(|vin| vin.prevout.value).sum();
    let output_value: u64 = transaction.vout.iter().map(|vout| vout.value).sum();
    if input_value < output_value {
        return Ok(false);
    }

    // // if all verifications pass the transaction is validated and returns true or OK
     Ok(true)
}



/// This serialize_tx function only works for legacy transactions
/// I believe i need to add 00 for an empty witness field?
fn serialize_tx(transaction: &Transaction) -> Result<String, Box<dyn Error>> {
    // This function needs to serialize the transaction into bytes


    // Returning the serialized tx as a string
    let mut serialized_tx = String::new();

    // Serialize version field, little endian
    let version = transaction.version.to_le_bytes();
    serialized_tx.push_str(&hex::encode(version));

    // Serialize vin count
    let vin_count = transaction.vin.len() as u64;
    serialized_tx.push_str(&format!("{:02x}", vin_count));

    // Sereialize txid
    for vin in &transaction.vin {
        serialized_tx.push_str(&vin.txid);

        let vout = &vin.vout.to_le_bytes();
        serialized_tx.push_str(&hex::encode(vout));


        // Serialize scriptSig size I kept getting trailing zeros after my compactsize hex
        let scriptsig_size = vin.scriptsig.len() / 2;

        // So I had to do this to remove the trailing zeros
        // It basically converts the u64 to bytes then to a vec then removes the trailing zeros
        let mut scriptsig_size_bytes = (scriptsig_size as u64).to_le_bytes().to_vec();

        if let Some(last_non_zero_position) = scriptsig_size_bytes.iter().rposition(|&x| x != 0) {
            scriptsig_size_bytes.truncate(last_non_zero_position + 1);
        }

        let scriptsig_size_hex = hex::encode(&scriptsig_size_bytes);
        serialized_tx.push_str(&scriptsig_size_hex);

        // Now push scriptsig itself
        serialized_tx.push_str(&vin.scriptsig);

        // push sequence
        let sequence = &vin.sequence.to_le_bytes();
        let sequence_hex = hex::encode(sequence);
        serialized_tx.push_str(&sequence_hex);
    }

    //  The output count has to be outside the vout loop because it's a single byte before it
    // was inside
    let vout_count = transaction.vout.len() as u64;
    serialized_tx.push_str(&format!("{:02x}", vout_count));

    // Now serialize vout count
    for vout in &transaction.vout {

        // Next push the amount of satoshis
        let value = &vout.value.to_le_bytes();
        serialized_tx.push_str(&hex::encode(value));

        // Now push the scriptpubkey cpmpact size

        // Just like above I had to remove the trailing zeros}
        let scriptpubkey_size = vout.scriptpubkey.len() / 2;
        let mut scriptpubkey_size_bytes = (scriptpubkey_size as u64).to_le_bytes().to_vec();
        if let Some(last_non_zero_position) = scriptpubkey_size_bytes.iter().rposition(|&x| x != 0) {
            scriptpubkey_size_bytes.truncate(last_non_zero_position + 1);
        }
        let scriptpubkey_size_hex = hex::encode(&scriptpubkey_size_bytes);
        serialized_tx.push_str(&scriptpubkey_size_hex);
        serialized_tx.push_str(&vout.scriptpubkey);
    }

    let lock = &transaction.locktime.to_le_bytes();
    let lock_hex = hex::encode(lock);
    serialized_tx.push_str(&lock_hex);

    Ok(serialized_tx)
}


/// Segwit tx serialization function
fn serialized_segwit_tx(transaction: &Transaction) -> Result<String, Box<dyn Error>> {
    let mut serialized_tx = String::new();

    let version = transaction.version.to_le_bytes();
    serialized_tx.push_str(&hex::encode(version));

    // In a segwit transaction I have to add a marker and a flag
    // Marker is always 00 and flag is always 01
    serialized_tx.push_str("00");
    serialized_tx.push_str("01");

    // Serialize vin count and push the numb of inputs
    let vin_count = transaction.vin.len() as u64;
    serialized_tx.push_str(&format!("{:02x}", vin_count));


    for vin in &transaction.vin {
        // Serialize txid and push
        serialized_tx.push_str(&vin.txid);

        // Serialize vout and push
        let vout = &vin.vout.to_le_bytes();
        let vout_hex = hex::encode(vout);
        serialized_tx.push_str(&vout_hex);

        // If its strictly a segwit tx, scriptsig field is empty so push zero
        if vin.scriptsig.is_empty() {
            serialized_tx.push_str("00");
        } else {
            /// Otherwise it's a tx with both legacy and segwit inputs so I have to add the scriptsig
            // Coppied from the legacy serialize_tx function
            // Serialize scriptSig size I kept getting trailing zeros after my compactsize hex
            let scriptsig_size = vin.scriptsig.len() / 2;

            // So I had to do this to remove the trailing zeros
            // It basically converts the u64 to bytes then to a vec then removes the trailing zeros
            let mut scriptsig_size_bytes = (scriptsig_size as u64).to_le_bytes().to_vec();

            if let Some(last_non_zero_position) = scriptsig_size_bytes.iter().rposition(|&x| x != 0) {
                scriptsig_size_bytes.truncate(last_non_zero_position + 1);
            }

            let scriptsig_size_hex = hex::encode(&scriptsig_size_bytes);
            serialized_tx.push_str(&scriptsig_size_hex);

            // Now push scriptsig itself
            serialized_tx.push_str(&vin.scriptsig);
        }

        let sequence = &vin.sequence.to_le_bytes();
        let sequence_hex = hex::encode(sequence);
        serialized_tx.push_str(&sequence_hex);

    }

    let vout_count = transaction.vout.len() as u64;
    serialized_tx.push_str(&format!("{:02x}", vout_count));


    // Serialize vout count and push the numb of outputs
    // I copied it from the legacy serialize_tx function
    for vout in &transaction.vout {

        // Next push the amount of satoshis
        let value = &vout.value.to_le_bytes();
        serialized_tx.push_str(&hex::encode(value));

        // Now push the scriptpubkey cpmpact size

        // Just like above I had to remove the trailing zeros}
        let scriptpubkey_size = vout.scriptpubkey.len() / 2;
        let mut scriptpubkey_size_bytes = (scriptpubkey_size as u64).to_le_bytes().to_vec();
        if let Some(last_non_zero_position) = scriptpubkey_size_bytes.iter().rposition(|&x| x != 0) {
            scriptpubkey_size_bytes.truncate(last_non_zero_position + 1);
        }
        let scriptpubkey_size_hex = hex::encode(&scriptpubkey_size_bytes);
        serialized_tx.push_str(&scriptpubkey_size_hex);
        serialized_tx.push_str(&vout.scriptpubkey);
    }

    // Now time for the witness fields
    for vin in &transaction.vin {
        if let Some(witness) = &vin.witness {
            // Serialize the number of stack items for the witness!
            let stack_items = witness.len() as u64;
            serialized_tx.push_str(&format!("{:02x}", stack_items));

            for witness_feild in witness {
                // Get compact size
                // Why does script_sig have trailing zeros but none here in compact size
                let compact_size = witness_feild.len() / 2;
                serialized_tx.push_str(&format!("{:02x}", compact_size));
                serialized_tx.push_str(witness_feild);

            }
        }
    }

    // Finally add the locktime
    let lock = &transaction.locktime.to_le_bytes();
    let lock_hex = hex::encode(lock);
    serialized_tx.push_str(&lock_hex);




     Ok(serialized_tx)
}





// TO get The message for verifying the signature
// serialize the transaction as per the input address type (scriptpubkey_type in the prevout)
// append the sighash_type (present at the end of the signature you are verifying) at the end of the trimmed tx byte sequence
// double hash 256(trimmed_tx)
// parse the signature, publickey, tx_hash into SIGNATURE, PUBLIC KEY and MESSAGE objects using Secp256k1 libraries,
// then verify the message against the public key and signature  using ecdsa verification functions
//
// basic procedure is this, you have do research for the whole thing.
// TODO Make a function that validates the signature of a transaction

// to get the sighash_type, its the last two bytes;
// let sighash_type = &signature[signature.len()-2..];

// 0x01 = SIGHASH_ALL
// 0x02 = SIGHASH_NONE
// 0x03 = SIGHASH_SINGLE
// 0x81 = SIGHASH_ANYONECANPAY | SIGHASH_ALL
// 0x82 = SIGHASH_ANYONECANPAY | SIGHASH_NONE
// 0x83 = SIGHASH_ANYONECANPAY | SIGHASH_SINGLE

// Left off Needing to serialize the p2pkh transaction to get the message and verify the sig

/// Working on p2pkh first
fn verify_signature(
    signature: Vec<u8>,
    pubkey: Vec<u8>,
    mut serialized_tx: String) -> Result<bool, Box<dyn Error>> {
    // Need to append the sighash_type to the serialized_tx
    // let sighash_type = &signature[signature.len() - 2..];
    // serialized_tx.push_str(&hex::encode(sighash_type));

    // I think i'm only appending 2 bytes but it may be 4 bytes i need, 01000000 instead of 01
    // This is a roundabout way  of doing it and i should fix it or send it the correct value in the first place
    // let sighash_type = &signature[signature.len() - 2..signature.len()];
    // let sighash_type_str = std::str::from_utf8(&sighash_type).unwrap();
    // let sighash_type = u8::from_str_radix(sighash_type_str, 16).unwrap();
    // let sighash_type_bytes = sighash_type.to_le_bytes();
    // serialized_tx.push_str(&hex::encode(sighash_type_bytes));

    // I think i'm only appending 2 bytes but it may be 4 bytes i need, 01000000 instead of 01

    // Hashing the serialized tx or message in a Hash256
    // But first I need to convert the serialized_tx to bytes
    let hashed_message_bytes = hex::decode(serialized_tx).expect("Decoding failed");
    let hashed_message = sha256(sha256(hashed_message_bytes));
    //let hash = hex::encode(hashed_message);

    //  Creating a new secp256k1 object
    let secp = Secp256k1::verification_only();

    // Creating a message, public key and signature

    let message_result = Message::from_digest_slice(&hashed_message).unwrap();
    // let message_result = Message::from_digest_slice(&Sha256::digest(&serialized_tx.as_bytes()));
    let public_key =  PublicKey::from_slice(&pubkey).unwrap();
    let signature = Signature::from_der(&signature).unwrap();



    // Return Ok(true) if the signature is valid, Ok(false) if it's invalid
    match secp.verify_ecdsa(&message_result, &signature,  &public_key) {
        Ok(_) => {
            Ok(true)
        },
        Err(e) => {
            Err(Box::new(e))
        },
    }
}


// This function gets the signature and public key from the scriptsig of a legacy transaction
fn get_signature_and_publickey_from_scriptsig_legacytx(scriptsig: &str) -> Result<(String, String), Box<dyn Error>> {
    // Convert the scriptsig hex string to bytes
    let scriptsig_bytes = hex::decode(scriptsig)?;

    let mut index = 0;
    let mut sig_and_pubkey_vec = Vec::new();

    // Loop through the scriptsig bytes to parse
    while index < scriptsig_bytes.len() {
        if index+1 >= scriptsig_bytes.len() {
            break;
        }

        let length = scriptsig_bytes[index] as usize; // This byte is the length of data to push (sig or pub)
        index += 1; // Move to the next byte

        // Checks if the length is greater than the remaining bytes in the scriptsig
        if index + length > scriptsig_bytes.len() {
            break;
        }

        // Get the data of the opcode length
        let data = &scriptsig_bytes[index..index+length];
        index+=length; // Move the index to the next opcode

        sig_and_pubkey_vec.push(hex::encode(data));
    }
    // Checking if the sig_and_pubkey_vec has two elements if not fail
    if sig_and_pubkey_vec.len() != 2 {
        return Err("Failed to parse scriptsig".into());
    }


    Ok((sig_and_pubkey_vec[0].clone(), sig_and_pubkey_vec[1].clone()))
}






// TODO make a function that verifies if a script returns OK
// Need to send in scriptpubkey_asm and verify it, I believe the scriptpubkey_type will
// tell me witch script to use  and match against. I will need to add a few more operators

// For example if scriptpubkey_type == p2ms then check if OP_0 is first and OP_CHECKMULTISIG ect.
// https://learnmeabitcoin.com/technical/transaction/input/scriptsig/

fn verify_script(scriptpubkey_asm: &str,
                 script_type: &str,
                 scriptsig: &str,
                 transaction: &Transaction
                 ,serialized_tx: String) -> Result<bool, Box<dyn Error>> {
    // Verify the script based off grokking bitcoin chapter 5
    // look over OP_CODES or operators

    // Making a stack for the op_code opperation
    let mut stack: Vec<Vec<u8>> = Vec::new();

    // First I want to check the scriptpub_key type so I preform the right script verification.
    // for each case.
    // Include v1_p2tr , v0_p2wpkh , p2sh , p2pkh,  and p2wsh

    //  P2PK, P2PKH, P2MS, P2SH, OP_RETURN  Are all unlocked via the scriptsig field
    // P2WPKH, P2WSH, P2TR are all unlocked via the witness field


    // A locking script (ScriptPubKey) is placed on every output you create in a transaction

    // An unlocking script (ScriptSig or Witness) is provided for every input you want to spend in a transaction

    match script_type {
        "p2pkh" => {
            let (signature, pubkey) = match get_signature_and_publickey_from_scriptsig_legacytx(scriptsig) {
                Ok((sig, pk)) => (sig, pk),
                Err(e) => {
                    return Err(e);
                }
            };

            // First push the scriptsig to the stack (sig and pubkey)
            stack.push(hex::decode(signature).unwrap());
            stack.push(hex::decode(pubkey).unwrap());

            for op in scriptpubkey_asm.split_whitespace() {
                match op {
                    "OP_DUP" => {
                        // If the stack is empty return false
                        // Otherwise clone the last item on the stack and push it to the stack
                        if let Some(data) = stack.last() {
                            stack.push(data.clone())
                        } else {
                            return Err("Stack underflow in OP_DUP".into())
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
                            return Err("Stack underflow in OP_HASH160".into())
                        }
                    }
                    "OP_EQUALVERIFY" => {
                        // if stack is less than 2 return false
                        if stack.len() < 2 {
                            return Err("Stack underflow in OP_EQUALVERIFY".into())
                        }
                        // Otherwise pop the last two items from the stack and compare them
                        // if they are not equal return false, if they are just continue
                        let stack_item1 = stack.pop().unwrap();
                        let stack_item2 = stack.pop().unwrap();
                        if stack_item1 != stack_item2 {
                            return Ok(false);
                        }
                    }
                    "OP_CHECKSIG" => {
                        // If the stack has less than two items return false
                        if stack.len() < 2 {
                            return Err("Stack underflow in OP_CHECKSIG".into());
                        }
                        // otherwise pop the last two items from the stack (pubkey and signature)
                        // and validate the signature
                        let pubkey = stack.pop().unwrap();
                        let signature = stack.pop().unwrap();

                        // using a place-holder for transaction data for now
                        let serialized_tx = serialize_tx(transaction).unwrap();
                        let is_valid_signature = verify_signature(signature, pubkey, serialized_tx);

                        // verify_signature will return true if the signature is valid
                        // otherwise false
                        if is_valid_signature.is_err() {
                            return Ok(false);
                        }  else {
                            continue
                        }
                        //return is_valid_signature;
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
             if stack.len() == 1 && !stack.is_empty() {
                 return Ok(true)
             }
        }
        "p2sh" => {
            todo!()
        }
        "v0_p2wpkh" => {
            todo!()
        }
        "p2wsh" => {
            todo!()
        }
        "v1_p2tr" => {
            todo!()
        }
        _ => {
            // If the script type is not recognized return false
            return Ok(false);
        }
    }

    Ok(stack.len() == 1 && !stack.is_empty())
}

// TODO
// Implement the BlockHeader function! Need to add the serialized block header to output.txt



// TODO Before I turn it in
// Implement the CoinbaseTx function! Need to add the serialized coinbase tx to output.txt
// If the coinbase tx has a segwit tx according to BIP 141: all coinbase transactions since the segwit
// upgrade need to include a witness reserved value in
// the witness field for the input, and then use that along with a witness root hash to put a wTXID
// commitment in the ScriptPubKey of one of the outputs in the transaction.
fn create_coinbase_tx (total_tx_fee: u64) -> String {
    // Hard coding the current block height I see on mempool.space and current block reward
    let block_height: u32 = 837122;
    let block_height_bytes = block_height.to_le_bytes();
    let block_height_hex = hex::encode(block_height_bytes);


    let block_sub_plus_fees: u64 = 625000000 + total_tx_fee; // Block reward in satoshis
    let block_reward_bytes = block_sub_plus_fees.to_le_bytes();
    let block_reward_hex = hex::encode(block_reward_bytes);

    // adding an address to pay the block reward to
    let address = String::from("36tvL5nHzSffbx4v9UhBfyGLWAkBUKyoxn");
    // Same address converted to hex for serialization
    let address = "053918f36132b92f65c11de2deeccf2f0b35177df3297ed5db".to_string();


    let extra_nonce = String::from("SlanesukeSOBIntern2024");
    let extra_nonce_hex = hex::encode(extra_nonce.as_bytes());

    // Adding the block height and extra nonce to the coinbase input scriptSig
    // the block height is in little endian byte order then encoding in hex
    let block_scriptsig = format!("{}{}", block_height_hex, extra_nonce_hex);



    // Finish manually serializing the coinbase tx.
    // Left off concantingating the scriptPubKey SIze
    // The address might need to be in hex
    let version = "01000000".to_string();
    let input_count = "01".to_string();
    let txid = "0000000000000000000000000000000000000000000000000000000000000000";
    let vout = "ffffffff";
    let scriptsig_size = format!("{:02x}", block_scriptsig.len()/2);
    let sequence = "ffffffff";
    let output_count = "01".to_string();
    let scriptpubkey_size = format!("{:02x}", address.len()/2);
    let locktime = "00000000";


    let serialized_coinbase_tx = format!("{}{}{}{}{}{}{}{}{}{}{}{}", version, input_count, txid,
        vout, scriptsig_size, block_scriptsig, sequence, output_count, block_reward_hex, scriptpubkey_size,
    address, locktime);

    serialized_coinbase_tx
}

// TODO
// Need to get my head together and figure out how to simplify and verify the .json transactions. After
// that i need to write a mining algo to efficiently fit the transactions with the highest fees into a block
// and pass the block fees to coinbase tx so I can add it to the block reward.
// Need to then just get there txid's and put them in a vec to add to output.txt




// Takes in data and returns a ripemd160 hash
fn ripemd160(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// Takes in data and returns a sha256 hash
fn sha256(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}





/// Creating the file
// This function will create a file with the given filename and write contents to it
fn append_to_file(filename: &str, contents: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(filename)?;

    writeln!(file, "{}", contents)?;
    Ok(())
}

fn generate_output_file(block_header: &str, coinbase_tx: String, txids_vec: &Vec<&str>)
    -> io::Result<()> {
    let file = "../output.txt";

    std::fs::write(file, "")?;

    // FOrmatting the block header
    let header_border = "+------------------------------------------------------------------+";
    append_to_file(file, header_border)?;
    let block_header = format!("|{:^66}|", block_header);
    append_to_file(file, &block_header)?;
    append_to_file(file, header_border)?;

    // Formatting the coinbase transaction
    let coinbase_tx = format!("|{:^66}|", coinbase_tx);
    append_to_file(file, &coinbase_tx)?;
    append_to_file(file, header_border)?;

    // Formatting the txids
    for txids in txids_vec {
        let txid = format!("|{:^66}|", txids);
        append_to_file(file, &txid)?;
    }
    append_to_file(file, header_border)?;

    Ok(())
}



fn main() {
    // Path to one transaction
    //let path = "../mempool/0a70cacb1ac276056e57ebfb0587d2091563e098c618eebf4ed205d123a3e8c4.json";
    let path= "../mempool/5e26eb673e26370b7bfb149f07cd03cba741e7ddc44748ec42c5b89b0d6a650e.json";

    // Deserialize the transaction
    let tx = match deserialize_tx(path) {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("Error!!! {}", e);
            return;
        },
    };

    // Serialize the transaction
    let serialized_tx = match serialize_tx(&tx) {
        Ok(stx) => stx,
        Err(e) => {
            eprintln!("Error!!! {}", e);
            return;
        },
    };

    // Verify the script for each input in the transaction
    for vin in &tx.vin {
        let scriptpubkey_asm = &vin.prevout.scriptpubkey_asm;
        let script_type = &vin.prevout.scriptpubkey_type;
        let scriptsig = &vin.scriptsig;

        let is_valid_script = match verify_script(scriptpubkey_asm, script_type, scriptsig, &tx, serialized_tx.clone()) {
            Ok(is_valid) => is_valid,
            Err(e) => {
                eprintln!("Error!!! {}", e);
                return;
            },
        };

        println!("Is valid script: {}", is_valid_script);
    }
}



// fn main() {
//     // Path to one transaction
//     // Test for a p2pkh transaction
//     let path = "../mempool/0a70cacb1ac276056e57ebfb0587d2091563e098c618eebf4ed205d123a3e8c4.json";
//
//     // Test for a v0_p2wpkh transaction
//     //let path = "../mempool/0aac03973f3d348fffb25fd7b802b22b120b0d276d655e557aee0a993ed4c0b7.json";
//
//     // match deserialize_tx(path) {
//     //     Ok(tx) => println!("Deserialized Transaction is \n {:#?}", tx),
//     //     Err(e) => eprintln!("Error!!! {}", e),
//     // }
//     let tx = deserialize_tx(path).unwrap();
//
//     // Test for serialized legacy tx
//     let serialized_tx = serialize_tx(&tx).unwrap();
//     //let serialized_segwit_tx = serialized_segwit_tx(&tx).unwrap();
//
//     eprintln!("Serialized Transaction is \n {:#?}", serialized_tx);
//     //eprintln!("Serialized Transaction is \n {:#?}", serialized_tx);
//
//
// }
// fn main() -> io::Result<()> {
//
//
//
//     let serialized_block_header = "Block header place holder for now";
//
//     let total_tx_fee = 0; // Place-holder for now because I need to somehow calculate the tx fee
//     let coinbase_tx: String = create_coinbase_tx(total_tx_fee);
//
//
//
//     let txid_list = vec!["txid1 test ", "txid2 test ", "txid3 testtttt"];
//
//     // generate_output_file(serialized_block_header, serialized_coinbase_tx, &txid_list)?;
//     generate_output_file(serialized_block_header, coinbase_tx, &txid_list)?;
//
//     Ok(())
// }


