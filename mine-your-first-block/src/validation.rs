use crate::transactions::{Transaction, Vout,  TransactionForProcessing};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};
extern crate secp256k1;
use secp256k1::{PublicKey, Secp256k1, Message};
use std::error::Error;
use std::fs;
use secp256k1::ecdsa::Signature;
use primitive_types::U256;
use crate::utils::{deserialize_tx, double_sha256, get_segwit_tx_message, get_signature_and_publickey_from_scriptsig, get_tx_readyfor_signing_legacy, reverse_bytes, ripemd160, serialize_tx, serialized_segwit_tx, serialized_segwit_wtx, sha256};

/// This function will read through the mempool folder and validate the transactions before adding
/// them to a transaction for processing vector
pub fn process_mempool(mempool_path: &str) -> io::Result<Vec<TransactionForProcessing>> {
    let mut valid_txs: Vec<TransactionForProcessing> = Vec::new();
    for tx in fs::read_dir(mempool_path)? {
        let tx = tx?;
        let path = tx.path();
        if path.is_file() {
            if let Some(path_str) = path.to_str() {
                let mut transaction = deserialize_tx(path_str);

                let mut is_valid = false;
                let mut txid = String::new();
                let mut wtxid = None;

                // Check script type and validate accordingly
                match transaction.vin[0].prevout.scriptpubkey_type.as_str() {
                    "v0_p2wpkh" => {
                        // If it's a p2wpkh transaction validate it
                        match p2wpkh_script_validation(&mut transaction) {
                            Ok((valid, wtx_id, tx_id)) if valid => {
                                is_valid = true;
                                wtxid = Some(wtx_id);
                                txid = tx_id;

                            },
                            _ => continue,
                        }
                    },
                    "p2pkh" => {
                        // If it's a p2pkh transaction validate it
                        match p2pkh_script_validation(&mut transaction) {
                            Ok((valid, tx_id)) if valid => {
                                is_valid = true;
                                txid = tx_id;
                            },
                            _ => continue,
                        }
                    },
                    _ => continue,
                }

                if !is_valid {
                    //eprintln!("Transaction is not valid: {:?}", path);
                }

                // Check if locktime is valid by comparing it to the current time
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs() as u32;
                if transaction.locktime > current_time && transaction.locktime >= 500_000_000 {
                    continue;
                }


                // Get the fee if valid so  i can add it to my vec
                let fee = verify_tx_fee(&transaction);

                // Check for double spending
                if !check_double_spending(&transaction, &valid_txs) {
                    continue;
                }

                // Add the transaction to the list of valid transactions
                valid_txs.push(TransactionForProcessing {
                    transaction,
                    txid,
                    wtxid: wtxid.clone(),
                    fee,
                    is_p2wpkh: wtxid.is_some(),
                });
            }else {
                //eprintln!("Failed to convert path to string: {:?}", path);
            }
        }
    }
    Ok(valid_txs)
}


/// This function will verify the signature of a transaction when passed into OP_CHECKSIG
pub fn verify_signature(
    signature: Vec<u8>,
    pubkey: Vec<u8>,
    serialized_tx: Vec<u8>) -> Result<bool, Box<dyn Error>> {

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
        Err(_e) => {
            Ok(false)
        },
    }
}

// Transaction validation
/// This function will validate P2WPKH transactions
pub fn p2wpkh_script_validation(transaction: &mut Transaction) -> Result<(bool, String, String), Box<dyn Error>> {
    // Create a stack to hold the data
    let mut stack: Vec<Vec<u8>> = Vec::new();

    for (i, vin) in transaction.vin.iter().enumerate() {
        stack.clear();

        let witness = vin.witness.clone().ok_or("Witness data not found")?;
        if witness.len() < 2 {
            return Err("Witness data is missing elements".into());
        }
        let signature = hex::decode(witness[0].clone())?;
        if signature.is_empty(){
            return Err("Signature is empty".into());
        }

        // sighash type off sig
        let sighash_type = signature[signature.len()-1];

        let pubkey= hex::decode(witness[1].clone())?;
        stack.push(signature);
        stack.push(pubkey);

        // Get the pubkey hash from script_pubkey_asm
        let script_pubkey = vin.prevout.scriptpubkey_asm.clone();
        let parts: Vec<&str> = script_pubkey.split_whitespace().collect();
        let pubkey_hash = parts.last().unwrap();

        // Message hash
        let message_hash = get_segwit_tx_message(
            &mut transaction.clone(),
            i,
            pubkey_hash,
            sighash_type.clone()
        )?;
        let message_in_bytes = hex::decode(&message_hash)?;

        // Now it execute like a p2pkh locking script where the pubkeyhah is pushed after ophash160
        let script_pubkey_asm = format!("OP_DUP OP_HASH160 OP_PUSHBYTES_20 {} OP_EQUALVERIFY OP_CHECKSIG", pubkey_hash);

        for op in script_pubkey_asm.split_whitespace(){
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
                    // unsure why but i diregard an extra item on the stack
                    // then it compares the top two items
                    let _stack_temp = stack.pop().unwrap();
                    let stack_item2 = stack.pop().unwrap();
                    if stack_item1 != stack_item2 {
                        return Err(format!("Stackitem1: {} aND Stackitem 2: {} and Hash: {} .OP_EQUALVERIFY failed for input",hex::encode(stack_item1), hex::encode(stack_item2), i).into());
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


                    match verify_signature(signature.clone(), pubkey.clone(), message_in_bytes.clone()) {
                        Ok(true) => {
                            // If the signature is valid, push a truthy value onto the stack to indicate success
                            stack.push(vec![1]);
                        },
                        Ok(false) => {
                            // The signature verification was successful but reported the signature as invalid
                            let pubkey_hex = hex::encode(&pubkey);
                            let signature_hex = hex::encode(&signature);
                            return Err(format!(
                                "Signature verification failed for input {}. The signature does not match the provided public key and message. PubKey: {}, Signature: {}",
                                i, pubkey_hex, signature_hex
                            ).into());
                        },
                        Err(e) => {
                            // An error occurred during the signature verification process
                            return Err(format!(
                                "An error occurred while verifying the signature for input {}: {}",
                                i, e
                            ).into());
                        }
                    }
                }
                _ => {
                    // If it's not an operator, it's an ordinary data (like sig or pubkey) and push it onto the stack
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

    // May need to change this a bit...
    // FOR WTXID
    let serialized_validwtx = serialized_segwit_wtx(transaction);
    let wtx_bytes = hex::decode(serialized_validwtx.clone())?;
    let wtxid_be = double_sha256(wtx_bytes);
    let wtxid = reverse_bytes(wtxid_be.to_vec());

    // FOR TXID
    let serialized_validtx = serialized_segwit_tx(transaction);
    let tx_bytes = hex::decode(serialized_validtx).unwrap();
    let txid_be = double_sha256(tx_bytes);
    let txid = reverse_bytes(txid_be.to_vec());

    Ok((true, wtxid, txid))
}

/// This function will validate a P2PKH transaction
pub fn p2pkh_script_validation(transaction: &mut Transaction) -> Result<(bool, String), Box<dyn Error>> {

    // Create a stack to hold the data
    let mut stack: Vec<Vec<u8>> = Vec::new();

    for (i,vin) in transaction.vin.iter().enumerate() {

        // Clearing the stack
        stack.clear();

        // Get ScriptSig and ScriptPubKey
        let scriptsig = &vin.scriptsig;
        let script_pub_key = &vin.prevout.scriptpubkey_asm.clone();

        let (signature, pubkey) = get_signature_and_publickey_from_scriptsig(scriptsig)
            .map_err(|e| format!("Error getting signature and public key from scriptsig for input {}: {}", i, e))?;

        // Prepare the transaction for signing
        let mut tx_for_signing = transaction.clone();
        tx_for_signing.vin = vec![vin.clone()];
        let message_tx = get_tx_readyfor_signing_legacy(&mut tx_for_signing);

        // Update the serialized tx
        let serialized_tx_for_message = serialize_tx(&message_tx);

        // Convert the serialized tx into bytes for the message
        let message_in_bytes = hex::decode(serialized_tx_for_message)
            .map_err(|_e| format!("Failed to decode the hex string for input: {}", i))?;

        let decoded_signature = hex::decode(signature).map_err(|e| format!("Failed to decode signature: {}", e))?;
        let decoded_pubkey = hex::decode(pubkey).map_err(|e| format!("Failed to decode pubkey: {}", e))?;
        stack.push(decoded_signature);
        stack.push(decoded_pubkey);

        for op in script_pub_key.split_whitespace() {
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
                    // unsure why but i diregard an extra item on the stack
                    // then it compares the top two items
                    let _stack_temp = stack.pop().unwrap();
                    let stack_item2 = stack.pop().unwrap();
                    if stack_item1 != stack_item2 {
                        return Err(format!("Stackitem1: {} aND Stackitem 2: {} and Hash: {} .OP_EQUALVERIFY failed for input",hex::encode(stack_item1), hex::encode(stack_item2), i).into());
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


                    match verify_signature(signature.clone(), pubkey.clone(), message_in_bytes.clone()) {
                        Ok(true) => {
                            // If the signature is valid, push a truthy value onto the stack to indicate success
                            stack.push(vec![1]);
                        },
                        Ok(false) => {
                            // The signature verification was successful but reported the signature as invalid
                            let pubkey_hex = hex::encode(&pubkey);
                            let signature_hex = hex::encode(&signature);
                            return Err(format!(
                                "Signature verification failed for input {}. The signature does not match the provided public key and message. PubKey: {}, Signature: {}",
                                i, pubkey_hex, signature_hex
                            ).into());
                        },
                        Err(e) => {
                            // An error occurred during the signature verification process
                            return Err(format!(
                                "An error occurred while verifying the signature for input {}: {}",
                                i, e
                            ).into());
                        }
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
        if stack.len() != 1 || stack.is_empty() {
            return Err(format!("Final stack validation failed for input {}", i).into());
        }
    }

    let serialized_validtx = serialize_tx(transaction);
    let tx_bytes = hex::decode(serialized_validtx).unwrap();
    let txid_be = double_sha256(tx_bytes);
    let txid = reverse_bytes(txid_be.to_vec());

    Ok((true, txid))
}


/// Function to get the tx amount so
pub fn verify_tx_fee(transaction: &Transaction) -> u64 {
    let total_input_amount: u64 = transaction.vin.iter()
        .map(|input| input.prevout.value)
        .sum();

    let total_output_amount: u64 = transaction.vout.iter()
        .map(|output| output.value)
        .sum();

    total_input_amount - total_output_amount
}

// Check double spend
pub fn check_double_spending(transaction: &Transaction, mempool: &Vec<TransactionForProcessing>) -> bool {
    // Loop through mempool
    for tx in mempool {
        let tx = &tx.transaction;
        // Loop through the vin of the transaction
        for vin in &tx.vin {
            // Loop through the vin of the mempool tx
            for vin2 in &transaction.vin {
                // If the txid and vout match return false
                if vin.txid == vin2.txid && vin.vout == vin2.vout {
                    return false; // DOuble spent!!
                }
            }
        }
    }
    true
}

/// This function takes the target and hash, converts them to a big int, then compares
pub fn hash_meets_difficulty_target(hash: &str) -> bool {
    let target_string = "0000ffff00000000000000000000000000000000000000000000000000000000";
    let target = U256::from_str_radix(target_string, 16).unwrap();
    let hash_as_num = U256::from_str_radix(hash, 16).unwrap();
    hash_as_num < target
}


