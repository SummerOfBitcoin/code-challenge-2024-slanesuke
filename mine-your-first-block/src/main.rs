// TODO
// 1. Start by cleaning up and corectingg the verify_script function.



use std::fmt::Debug;
use serde::Deserialize;
use serde_json;
use sha2::{Digest as ShaDigest, Sha256};
use std::fs::File;
use std::io::{self, Read, read_to_string, Write};
use ripemd::{Digest as RipemdDigest, Ripemd160};
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

    // Verify if scriptpubkey_asm returns true
    // will this work as for outputs in transaction outputs? verify if this is correct
    // I also added in the sciptpubkey_type to verify the scriptpubkey_asm, I hope this makes sense\
    // The for loop may need changing.
    // I need to send in the script sig to verify that is why there is an  error because scriptsig
    // is in vin
    for vout in &transaction.vout {
        if !verify_script(&vout.scriptpubkey_asm, &vout.scriptpubkey_type, ) {
            return Ok(false);
        }
    }

    // Use  validate_signature function to verify the signature of the transaction
    for vin in &transaction.vin {
        // Parse signature, pubkey and data


        // let signed_data = create_sighash(transaction, vin.vout as usize);
        let (signature, public_key, sighash_type) = get_signature_and_pubkey_and_sighash_type(&vin.scriptsig_asm)?;
        let signed_data = create_sighash(transaction, vin.vout as usize, sighash_type as u32)?;



        if !verify_signature(signature, public_key, signed_data) {
            return Err("Signature verification failed".into())
        }
    }

    // if all verifications pass the transaction is validated and returns true or OK
    Ok(true)
}

// THis function is wrong and lamee
fn get_signature_and_pubkey_and_sighash_type(scriptsig_asm: &str) -> Result<(Vec<u8>, Vec<u8>, u8), Box<dyn Error>> {
    // Parse the scriptsig_asm to get the signature and pubkey
    // The signature is the first element in the scriptsig_asm
    // The pubkey is the second element
    let parts: Vec<&str> = scriptsig_asm.split_whitespace().collect();

    if parts.len() < 2 {
        return Err("scriptsig_asm format is invalid".into());
    }

    // Remove the OP_PUSHBYTES_71 or OP_PUSHBYTES_72 prefix if it's there
    let signature_hex = parts[0].trim_start_matches("OP_PUSHBYTES_71    ")
        .trim_start_matches("OP_PUSHBYTES_72");
    let pubkey_hex = parts[1].trim_start_matches("OP_PUSHBYTES_33");

    let signature = hex::decode(signature_hex)?;
    let pubkey = hex::decode(pubkey_hex)?;

    let sighash_type = signature.last().clone().unwrap_or(&0);

    Ok((signature.clone(), pubkey, *sighash_type))
}



fn create_sighash(transaction: &Transaction, input_index: usize, sighash_type: u32) -> Result<Vec<u8>, Box<dyn Error>> {
    // This function needs to create a sighash for a transaction


    //STILL NEED TO VERIFY THIS AND WORK ON SERIALIZATION

    let serialized_tx = serialize_tx(transaction).unwrap();

    let modified_tx = modify_tx_for_sighash(serialized_tx, input_index,  sighash_type).unwrap();

    let sighash = sha256(sha256(modified_tx));

    Ok(sighash)
}

fn serialize_tx(transaction: &Transaction) -> Result<Vec<u8>, Box<dyn Error>> {
    // This function needs to serialize the transaction into bytes

    let mut serialized_tx = Vec::new();

    // Serialize version field, little endian
    serialized_tx.write_all(&transaction.version.to_le_bytes())?;

    // Serialize vin count
    write_varint(transaction.vin.len() as u64, &mut serialized_tx)?;

    // Serialize each vin {
    for vin in &transaction.vin {
        // convert txid from hex to bytes
        let txid_bytes = hex::decode(&vin.txid)?;
        serialized_tx.write_all(&txid_bytes)?;

        // Serialize vout, little endian
        serialized_tx.write_all(&vin.vout.to_le_bytes())?;

        // Serialize scriptSig
        let scriptsig_bytes = hex::decode(&vin.scriptsig)?;
        serialized_tx.write_all(&scriptsig_bytes)?;

        serialized_tx.write_all(&vin.sequence.to_le_bytes())?;
    }


    // Serialize  vout count
    write_varint(transaction.vout.len() as u64, &mut serialized_tx)?;

    for vout in &transaction.vout {
        let scriptpubkey_bytes = hex::decode(&vout.scriptpubkey)?;
        serialized_tx.write_all(&scriptpubkey_bytes)?;

        // Write value to serialized_tx
        serialized_tx.write_all(&vout.value.to_le_bytes())?;
    }

    // Serialize locktime
    serialized_tx.write_all(&transaction.locktime.to_le_bytes())?;


    Ok(serialized_tx)
}

// Helper function to write variable length integers
// Got help from chatgpt

fn write_varint(value: u64, buf: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
    if value < 0xFD {
        buf.write_all(&[value as u8])?;
    } else if value <= 0xFFFF {
        buf.write_all(&[0xFD])?;
        buf.write_all(&value.to_le_bytes())?;
    } else if value <= 0xFFFFFFFF {
        buf.write_all(&[0xFE])?;
        buf.write_all(&value.to_le_bytes())?;
    } else {
        buf.write_all(&[0xFF])?;
        buf.write_all(&value.to_le_bytes())?;
    }
    Ok(())
}

// Helper function to modify the transaction for the sighash
// This function will be used in the create_sighash function AHHH

fn modify_tx_for_sighash(serialized_tx: Vec<u8>, input_index: usize, sighash_type: u32) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut modified_tx = serialized_tx.clone();

    // match sighash_type {
    //     SIGHASH_ALL => {
    //         // For SIGHASH_ALL, all inputs and outputs are signed, so no modification is needed
    //     }
    //     SIGHASH_NONE => {
    //         // For SIGHASH_NONE, none of the outputs are signed
    //         // You need to remove the outputs from the serialized transaction
    //     }
    //     SIGHASH_SINGLE => {
    //         // For SIGHASH_SINGLE, only the output with the same index as the input is signed
    //         // You need to remove all other outputs from the serialized transaction
    //     }
    //     SIGHASH_ALL | SIGHASH_ANYONECANPAY => {
    //         // For SIGHASH_ALL | SIGHASH_ANYONECANPAY, all outputs and only one input is signed
    //         // You need to remove all other inputs from the serialized transaction
    //     }
    //     _ => {
    //         // For other sighash types, you need to implement the appropriate modifications
    //     }
    // }

    Ok(modified_tx)
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
fn verify_signature(signature: Vec<u8>, pubkey: Vec<u8>, data: Vec<u8>) -> bool {
    //  Creating a new secp256k1 object
    let secp = Secp256k1::verification_only();

    // Creating a message, public key and signature


    let message_result = Message::from_digest_slice(&Sha256::digest(&data));
    let public_key =  PublicKey::from_slice(&pubkey).unwrap();
    let signature = Signature::from_der(&signature).unwrap();

    // iff getting message fails
    if message_result.is_err() {
        return false;
    }
    let message = message_result.unwrap();

    // Return Ok(true) if the signature is valid, Ok(false) if it's invalid
    match secp.verify_ecdsa(&message, &signature,  &public_key) {
        Ok(_) => true,
        Err(_) => false,
    }
}



fn get_signature_and_publickey_from_scriptsig_legacytx(scriptsig: &str) -> Option<(String, String)> {
    //
    let scriptsig_bytes = match hex::decode(scriptsig) {
        Ok(bytes) => bytes,
        Err(_) => return None,
    };

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
    if sig_and_pubkey_vec.len() == 2 {
        Some((sig_and_pubkey_vec[0].clone(), sig_and_pubkey_vec[1].clone()))
    } else {
        None
    }
}






// TODO make a function that verifies if a script returns OK
// Need to send in scriptpubkey_asm and verify it, I believe the scriptpubkey_type will
// tell me witch script to use  and match against. I will need to add a few more operators

// For example if scriptpubkey_type == p2ms then check if OP_0 is first and OP_CHECKMULTISIG ect.
// https://learnmeabitcoin.com/technical/transaction/input/scriptsig/

fn verify_script(scriptpubkey_asm: &str, script_type: &str, scriptsig: &str) -> bool {
    // Verify the script based off grokking bitcoin chapter 5
    // look over OP_CODES or operators

    // Making a stack for the op_code opperation
    let mut stack: Vec<Vec<u8>> = Vec::new();

    // First I want to check the scriptpub_key type so I preform the right script verification.
    // for each case.
    // Include v1_p2tr , v0_p2wpkh , p2sh , p2pkh,  and p2wsh

    //  P2PK, P2PKH, P2MS, P2SH, OP_RETURN  Are all unlocked via the scriptsig field
    // P2WPKH, P2WSH, P2TR are all unlocked via the witness field

    //A script is valid if the only element left on the stack is a OP_1 or greater.
    //
    // A script is invalid if:
    // The final stack is empty
    // The only element left on the stack is OP_0
    // There is more than one element left on the stack at the end of execution.
    // The script exits prematurely (e.g. OP_RETURN).

    // A locking script (ScriptPubKey) is placed on every output you create in a transaction

    // An unlocking script (ScriptSig or Witness) is provided for every input you want to spend in a transaction

    //Every node will then combine and run these two scripts for each input in every transaction
    // they receive to make sure they validate. If the unlocking scripts on inputs do not successfully
    // unlock the locking scripts on the outputs being spent, then the transaction is considered invalid
    // and will not be relayed or mined in to a block.

    //Even though the unlocking script is provided after the initial locking script (in terms of raw
    // transactions), we actually put the unlocking script first when we execute the full script
    match script_type {
        "p2pkh" => {
            let (signature, pubkey) = match get_signature_and_publickey_from_scriptsig_legacytx(scriptsig) {
                Some((sig, pk)) => (sig, pk),
                None => {
                    eprintln!("Failed to parse scriptsig");
                    return false
                },
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
                    "OP_CHECKSIG" => {
                        // If the stack has less than two items return false
                        if stack.len() < 2 {
                            return false;
                        }
                        // otherwise pop the last two items from the stack (pubkey and signature)
                        // and validate the signature
                        let pubkey = stack.pop().unwrap();
                        let signature = stack.pop().unwrap();

                        // using a place-holder for transaction data for now
                        let is_valid_signature = verify_signature(signature, pubkey, Vec::new());

                        // verify_signature will return true if the signature is valid
                        // otherwise false
                        return is_valid_signature;
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
            return false;
        }
    }

    // Loop through the script and match the OP_CODEs
    // Need to add a few like OP_CHECKSIG and OP_CHECKMULTISIG
    // for op in scriptpubkey_asm.split_whitespace() {
    //     match op {
    //         "OP_DUP" => {
    //             // If the stack is empty return false
    //             // Otherwise clone the last item on the stack and push it to the stack
    //             if let Some(data) = stack.last() {
    //                 stack.push(data.clone())
    //             } else {
    //                 return false
    //             }
    //         }
    //         "OP_HASH160"  => {
    //             // If the stack is empty return false
    //             // Otherwise take the last item from the stack, hash it with sha256 then ripemd160
    //             // and push it to the stack
    //             if let Some(pubkey) = stack.pop() {
    //                 let hash = ripemd160(sha256(pubkey.clone()));
    //                 stack.push(hash);
    //             } else {
    //                 return false
    //             }
    //         }
    //         "OP_EQUALVERIFY" => {
    //             // if stack is less than 2 return false
    //             if stack.len() < 2 {
    //                 return false;
    //             }
    //             // Otherwise pop the last two items from the stack and compare them
    //             // if they are not equal return false, if they are just continue
    //             let stack_item1 = stack.pop().unwrap();
    //             let stack_item2 = stack.pop().unwrap();
    //             if stack_item1 != stack_item2 {
    //                 return false;
    //             }
    //         }
    //         "OP_CHECKSIG" => {
    //             // If the stack has less than two items return false
    //             if stack.len() < 2 {
    //                 return false;
    //             }
    //             // otherwise pop the last two items from the stack (pubkey and signature)
    //             // and validate the signature
    //             let pubkey = stack.pop().unwrap();
    //             let signature = stack.pop().unwrap();
    //
    //             // using a place-holder for transaction data for now
    //             let is_valid_signature = validate_signature(signature, pubkey, Vec::new());
    //
    //             // verify_signature will return true if the signature is valid
    //             // otherwise false
    //             return is_valid_signature;
    //
    //         }
    //         "OP_CHECKMULTISIG" => {
    //             // TODO
    //         }
    //
    //         _ => {
    //             // If it's not an operator,it'a ordinary data (like sig or pubkey) and push it onto the stack
    //             // Verify !!!
    //             let data = hex::decode(op).unwrap_or_default(); // Convert hex string to bytes
    //             stack.push(data);
    //         }
    //     }
    // }
    // Check final result
    // If the stack has only one element and it's not empty, transaction is valid
    stack.len() == 1 && !stack.is_empty()
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







// fn main() {
//     // Path to one transaction
//     let path = "../mempool/0a3fd98f8b3d89d2080489d75029ebaed0c8c631d061c2e9e90957a40e99eb4c.json";
//
//     match deserialize_tx(path) {
//         Ok(tx) => println!("Deserialized Transaction is \n {:#?}", tx),
//         Err(e) => eprintln!("Error!!! {}", e),
//     }
// }
fn main() -> io::Result<()> {



    let serialized_block_header = "Block header place holder for now";

    let total_tx_fee = 0; // Place-holder for now because I need to somehow calculate the tx fee
    let coinbase_tx: String = create_coinbase_tx(total_tx_fee);



    let txid_list = vec!["txid1 test ", "txid2 test ", "txid3 testtttt"];

    // generate_output_file(serialized_block_header, serialized_coinbase_tx, &txid_list)?;
    generate_output_file(serialized_block_header, coinbase_tx, &txid_list)?;

    Ok(())
}


