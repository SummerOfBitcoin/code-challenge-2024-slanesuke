/// TODO
/// FIGURE OUT HOW TO VERIFY THE SIGNATURE OF A TRANSACTION UGHH


use std::fmt::{Debug, format};
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
#[derive(Debug, Deserialize, Clone)]
struct Transaction {
    version: u32,
    locktime: u32,
    vin: Vec<Vin>,
    vout: Vec<Vout>,
    sighash: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
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

#[derive(Debug, Deserialize, Clone)]
struct Prevout {
    scriptpubkey: String,
    scriptpubkey_asm: String,
    scriptpubkey_type: String,
    scriptpubkey_address: String,
    value: u64,
}

#[derive(Debug, Deserialize, Clone)]
struct Vout {
    scriptpubkey: String,
    scriptpubkey_asm: String,
    scriptpubkey_type: String,
    scriptpubkey_address: Option<String>,
    value: u64,
}

// TODO Before I turn it in
// Implement the CoinbaseTx function! Need to add the serialized coinbase tx to output.txt
// If the coinbase tx has a segwit tx according to BIP 141: all coinbase transactions since the segwit
// upgrade need to include a witness reserved value in
// the witness field for the input, and then use that along with a witness root hash to put a wTXID
// commitment in the ScriptPubKey of one of the outputs in the transaction.

// This function will create a coinbase transaction
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

// TODO
// Implement the BlockHeader function! Need to add the serialized block header to output.txt






// First just  working  with one tx so I can learn
fn deserialize_tx(filename: &str) -> Transaction {
    //  Open the file of a tx
    let mut file = File::open(filename).unwrap();

    let mut json_string = String::new();
    file.read_to_string(& mut json_string).unwrap();

    let tx: Transaction = serde_json::from_str(&json_string).unwrap();

    // return a transaction if the deserialization is successful
    tx
}

/// This function will serialize a transaction into a string of hex bytes
fn serialize_tx(transaction: &Transaction) -> String {
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

    if transaction.sighash.is_some() {
        serialized_tx.push_str(&<std::option::Option<std::string::String> as Clone>::clone(&transaction.sighash).unwrap());
    }

    serialized_tx
}


/// This function will serialize a segwit transaction into a string of hex bytes
fn serialized_segwit_tx(transaction: &Transaction) -> String {
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
            // Otherwise it's a tx with both legacy and segwit inputs so I have to add the scriptsig
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

    // Unsure if segwit tx's need a sighash type so will keep it commented for now
    // if transaction.sighash.is_some() {
    //         serialized_tx.push_str(&<std::option::Option<std::string::String> as Clone>::clone(&transaction.sighash).unwrap());
    //     }



     serialized_tx
}

/// This function will verify the signature of a transaction when passed into OP_CHECKSIG
fn verify_signature(
    signature: Vec<u8>,
    pubkey: Vec<u8>,
    mut serialized_tx: Vec<u8>) -> Result<bool, Box<dyn Error>> {

    // Removing the sighash type from the signature
    let signature = &signature[..signature.len()-1];
    let secp = Secp256k1::new();


    let hash_array: [u8; 32] = double_sha256(serialized_tx);
    let message_result = Message::from_digest_slice(&hash_array).unwrap();
    let public_key =  PublicKey::from_slice(&pubkey).expect("Failed to create public key");
    let signature = Signature::from_der(&signature).unwrap();



    // Return Ok(true) if the signature is valid, Ok(false) if it's invalid
    match secp.verify_ecdsa(&message_result, &signature,  &public_key) {
        Ok(_) => {
            Ok(true)
        },
        Err(e) => {
            Ok(false)
        },
    }
}

/// This function gets the signature and public key from the scriptsig of a legacy transaction
// Would it be easier to get the signature and pubkey from the scriptsig_asm field?
fn get_signature_and_publickey_from_scriptsig(scriptsig: &str) -> Result<(String, String), Box<dyn Error>> {
    // Convert the scriptsig hex string to bytes
    let scriptsig_bytes = hex::decode(scriptsig)?;

    let mut index = 0;
    let mut sig_and_pubkey_vec = Vec::new();

    // Loop through the scriptsig bytes to parse
    while index < scriptsig_bytes.len() {
        if index+1 >= scriptsig_bytes.len() {
            return Err("Unexpected end of scriptSig".into());
        }

        let length = scriptsig_bytes[index] as usize; // This byte is the length of data to push (sig or pub)
        index += 1; // Move to the next byte

        // Checks if the length is greater than the remaining bytes in the scriptsig
        if index + length > scriptsig_bytes.len() {
            return Err("ScriptSig length byte exceeds remaining data".into());
        }

        // Get the data of the opcode length
        let data = &scriptsig_bytes[index..index+length];
        index+=length; // Move the index to the next opcode

        sig_and_pubkey_vec.push(hex::encode(data));
    }
    // Checking if the sig_and_pubkey_vec has two elements if not fail
    if sig_and_pubkey_vec.len() != 2 {
        return Err(format!("Expected 2 elements, found {}", sig_and_pubkey_vec.len()).into());
    }


    Ok((sig_and_pubkey_vec[0].clone(), sig_and_pubkey_vec[1].clone()))
}

/// This function will get the tx ready for signing by removing the scriptsig and adding the
/// scriptpubkeyto the scriptsig field and adding the sighash to the transaction
fn get_tx_readyfor_signing_legacy(transaction : &mut Transaction) -> Transaction {

    let scriptsig = &transaction.vin[0].scriptsig;
    let (signature, pubkey) = get_signature_and_publickey_from_scriptsig(scriptsig).unwrap();

    let sighash_type = &signature[signature.len()-2..];

    // Hard coding the sighash type for now
     let sighash = format!("{}000000", sighash_type);


    // Adding the sighash to the transaction
    // It turns a string into a u32
    transaction.sighash = Some(sighash);


    // Emptying the scriptsig fields for each input
    for vin in transaction.vin.iter_mut() {
        // Empty
        vin.scriptsig = String::new();

        // Copy the scriptpubkey to the scriptsig field
        vin.scriptsig  = vin.prevout.scriptpubkey.clone();
    }

    // Return the tx
    Transaction {
        version: transaction.version,
        locktime: transaction.locktime,
        vin: transaction.vin.clone(),
        vout: transaction.vout.clone(),
        sighash: transaction.sighash.clone(),
    }
}

/// This function will validate a P2PKH transaction
fn p2pkh_tx_validation(transaction: &mut Transaction) -> Result<bool, Box<dyn Error>> {

    // Create a stack to hold the data
    let mut stack: Vec<Vec<u8>> = Vec::new();

    for (i,vin) in transaction.vin.iter().enumerate() {

        // Clearing the stack
        stack.clear();

        // Get ScriptSig and ScriptPubKey
        // Should i just do this from the ScriptSig_asm???
        let  scriptsig = &vin.scriptsig;
        let scriptPubKey = &vin.prevout.scriptpubkey_asm.clone();

        let (signature, pubkey) = get_signature_and_publickey_from_scriptsig(scriptsig)
            .map_err(|e| format!("Error getting signature and public key from scriptsig for input {}: {}", i, e))?;

        // Prepare the transaction for signing
        let mut tx_for_signing = transaction.clone();
        tx_for_signing.vin = vec![vin.clone()];
        let message_tx = get_tx_readyfor_signing_legacy(&mut tx_for_signing);
        let serialized_tx_for_message = serialize_tx(&message_tx);

        // Convert the serialized tx into bytes for the message
        let message_in_bytes = hex::decode(serialized_tx_for_message)
            .map_err(|e| format!("Failed to decode the hex string for input: {}", i))?;

        let decoded_signature = hex::decode(signature).map_err(|e| format!("Failed to decode signature: {}", e))?;
        let decoded_pubkey = hex::decode(pubkey).map_err(|e| format!("Failed to decode pubkey: {}", e))?;
        stack.push(decoded_signature);
        stack.push(decoded_pubkey);

        let mut hash_result: String = "".to_string();
        for op in scriptPubKey.split_whitespace() {
            match op {
                "OP_DUP" => {
                    // If the stack is empty return false
                    // Otherwise clone the last item on the stack and push it to the stack
                    if stack.last().is_none() {
                        return Err(format!("Stack underflow in OP_DUP for input {}", i).into());
                    }
                    stack.push(stack.last().unwrap().clone());
                }
                "OP_HASH160" => {
                    // If the stack is empty return false
                    // Otherwise take the last item from the stack, hash it with sha256 then ripemd160
                    // and push it to the stack
                    if let Some(pubkey) = stack.pop() {
                        let sha256_hash = sha256(pubkey);
                        let ripemd160_hash = ripemd160(sha256_hash);
                        stack.push(ripemd160_hash.clone());
                        hash_result = format!("{}",hex::encode(&ripemd160_hash));
                    } else {
                        return Err(format!("Stack underflow in OP_HASH160 for input {}", i).into());
                    }
                }
                "OP_EQUALVERIFY" => {
                    // if stack is less than 2 return false
                    if stack.len() < 2 {
                        return Err(format!("Stack underflow in OP_EQUALVERIFY for input {}", i).into());
                    }
                    // Otherwise pop the last two items from the stack and compare them
                    // if they are not equal return false, if they are just continue
                    let stack_item1 = stack.pop().unwrap();
                    let stack_temp = stack.pop().unwrap();
                    let stack_item2 = stack.pop().unwrap();
                    if stack_item1 != stack_item2 {
                        return Err(format!("Stackitem1: {} aND Stackitem 2: {} and Hash: {} .OP_EQUALVERIFY failed for input {}",hex::encode(stack_item1), hex::encode(stack_item2),hash_result, i).into());
                    }
                }
                "OP_CHECKSIG" => {
                    // If the stack has less than two items return false
                    if stack.len() < 2 {
                        return Err(format!("Stack underflow in OP_CHECKSIG for input {}", i).into());
                    }
                    // otherwise pop the last two items from the stack (pubkey and signature)
                    // and validate the signature
                    let pubkey = stack.pop().unwrap();
                    let signature = stack.pop().unwrap();

                    // using a place-holder for transaction data for now
                    //let serialized_tx = serialize_tx(transaction).unwrap();
                    let is_valid_signature = verify_signature(signature, pubkey, message_in_bytes.clone());

                    // verify_signature will return true if the signature is valid
                    // otherwise false
                    if is_valid_signature.is_err() {
                        return Err(format!("Invalid signature for input {}", i).into());
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

        if stack.len() != 1 || stack.is_empty() {
            return Err(format!("Final stack validation failed for input {}", i).into());
        }
    }
    Ok(true)
}


/// Hashing Functions
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

fn double_sha256(input: Vec<u8>) -> [u8; 32] {
    let first_hash = sha256(input);
    let second_hash = sha256(first_hash);
    second_hash.try_into().expect("Expected a Vec<u8> of length 32")
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

/// This function will generate the output file
// May remove the formatting
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

    // Each of these is a p2pkh  tx
    let filename = "../mempool/02c2897472e47228381f399d5303d9f64e91348e78ec0fd8f2da5835cf2cd303.json";
    let filename ="../mempool/0b9e15adfefab6416bef64ca1fa37516f89f7d8cd106103c67c6f55a3c7565ad.json";
    let filename ="../mempool/0bb03d9b895da867f0c76fd45c4d3d8998a8cb9b70ea56e32087f9f78cfd13e5.json";

    // Deserialize the transaction from the file.
    let mut transaction = deserialize_tx(filename);

    // Validate the transaction
    match p2pkh_tx_validation(&mut transaction) {
        Ok(is_valid) => {
            if is_valid {
                println!("The transaction is valid.");
            } else {
                println!("The transaction is not valid.");
            }
        }
        Err(e) => {
            println!("An error occurred during validation: {}", e);
        }
    }

}



// This main fuction is for testing things and seeing sigantues, pubkeys, and transactions
// fn main() {
//     // The file containing the JSON representation of the transaction.
//     let filename = "../mempool/02c2897472e47228381f399d5303d9f64e91348e78ec0fd8f2da5835cf2cd303.json";
//
//     // Deserialize the transaction from the file.
//     let mut transaction = deserialize_tx(filename);
//
//
//     let scriptsig = transaction.vin[0].scriptsig.clone();
//     let (signature, pubkey) = get_signature_and_publickey_from_scriptsig(&scriptsig).unwrap();
//     println!("Signature: {}", signature);
//     let signature = &signature[..signature.len()-2];
//     println!("ScriptSig: {}", scriptsig);
//     println!("Signature without sighash_type: {}", signature);
//     println!("Pubkey: {}", pubkey);
//
//
//
//     let message_tx = get_tx_readyfor_signing_legacy(&mut transaction);
//     let serialized_tx_for_message = serialize_tx(&message_tx);
//     println!();
//     println!("Transaction JSON for signing: {:#?}", message_tx);
//
//     println!();
//     println!("Serialized for signing TX: {}", serialized_tx_for_message);
//     println!();
//     let message_tx_bytes = hex::decode(serialized_tx_for_message).expect("Failed to decode hex string");
//     let hash_array: [u8; 32] = double_sha256(message_tx_bytes);
//
//
//
//     let secp = Secp256k1::new();
//
//     // Creating a message, public key and signature
//
//
//     let sig_bytes = hex::decode(&signature).unwrap();
//     let pubkey_bytes = hex::decode(&pubkey).unwrap();
//
//
//     let message_result = Message::from_digest_slice(&hash_array).unwrap();
//     let public_key =  PublicKey::from_slice(&pubkey_bytes).expect("Failed to create public key");
//     let signature = Signature::from_der(&sig_bytes).unwrap();
//
//
//
//     // Return Ok(true) if the signature is valid, Ok(false) if it's invalid
//     match secp.verify_ecdsa(&message_result, &signature,  &public_key) {
//         Ok(_) => {
//             println!("The signature is valid");
//         },
//         Err(e) => {
//             println!("The signature is invalid: {}", e);
//         },
//     }
//
// }



