# Solution for the Summer of Bitcoin Dev Assignment

## Design Approach
In code-challenge-2024-slanesuke/mine-your-first-block/src, I've written a script to read transactions, verify they are valid, and use them to fill and construct a valid block. I decided to start with the bare minimum to get a score. Since you need valid transactions and a witness commitment to mine a valid block, I began with verifying p2pkh and p2wpkh transactions.

To begin with transaction verification, I needed to set up a few helper functions. For each transaction type, I had to create functions that would serialize the transaction data in a specific way so I could replicate the message for signature verification in OP_CHECKSIG. Next, I had to get the signature and the public key. Getting the signature and public key for each transaction differed a bit because of the witness data in p2wpkh transactions. So, in p2pkh transactions, I needed to build a function that parses the signature and public key from the scriptsig in the Vin (each input). For p2wpkh I was able to hardcode the signature and public key because the witness field holds the signature at index 0 and the public key at index 1 (for each input). The last important helper function for transaction verification was the verify signature function which took the message, public key, and signature (in der encoding) and would return true if the signature matched.  

Throughout the project, I had the help of small functions that would complete one task I had to do many times. I built a reverse byte function because there were many occurrences where you needed to change the input to big-endian or little. I needed to display the txids in little-endian in the block but before I calculated the merkle or witness root I needed to reverse the bytes to get the correct root. I used a compact size function for a similar use. For example, in the serialization of transaction data, I had to get the compact size of witness fields or the scriptsig size before pushing the actual item. Last and probably the most important was the use of my hashing functions. I had a RIPEMD160, SHA256, and DOUBLESHA256 functions. These little functions were small but played an important role in the design of my script because they were used so often.

The design for block construction was one of the simple parts of this script, because once the block header, coinbase transaction, and transactions are verified and collected. I just needed to write a bit of code to add all that information to the block once the block hash was less than (or equal to) the difficulty target.

When I was writing the script I never really had any design principles. I'm a relatively new developer and I've never worked on such a large and complex program. So, when I began, I just wanted to build something that scored more than 60 points. I even had all my code in main for the majority of April. I had about 1600 lines of code in one clunky mess until I was able to finally pass with a 62. Finally, I was able to organize and modulize the program. Of course, while writing the code, as messy as it was, I kept in mind the need to build an efficient, reliable program. I went from upwards of 10 minutes to mine my block to around 1-2 minutes. The script was also reliable, If something broke it would be easy to find the bug because of how the functions were designed.

As a high-level overview, I wanted to discuss the main components of the script and how they interacted with each other. This all starts with the Transaction Struct. The Transaction struct is where the transaction data goes after the deserialze_tx() function. For each transaction, the deserialize _tx() function takes a tx.json file as an argument, reads the file, deserializes the JSON data into a Transaction object then returns the object. This allows me to access the properties of each transaction, pass the transaction object to other functions, and use the object to perform operations, like script validation. I first would pass the Transaction objects to a serialization function (serialize_tx(), serialize_segwit_tx(), and serialize_segwit_wtx()). In bitcoin serializing a transaction is extremely important, it's used to verify signatures in p2pkh transactions as well as get the txids in both legacy and segwit transactions. The Transaction objects are also passed into the p2pkh (p2pkh_script_validation()) and p2wpkh (p2wpkh_script_validation()) script validation functions where the locking and unlocking script execution is run through the program and if all checks pass the functions return true, the txid, and wtxid if applicable. After verifying the valid transactions, they are sent in a process_mempool() function that does several smaller validations before adding them to another struct named TransactionForProcessing. These are the transactions being added to the block. I needed to make a separate object for these transactions to parse the txids from the wtxids in the mining section in main. I did this to get a correct merkle root and witness root. I have a get_merkle_root() function that receives a vector of txids, reverses them, and then calculates the merkle root. I obtain my merkle root and witness root from the same function. Now that we have our valid transactions in a vector of TransactionForProcessing we can create the merkle root (for the block header function) and witness root so we can construct out coinbase transactions. The coinbase construction function (create_coinbase_tx()) is essential to the script design. It receives the total transaction fees as well as a vector of wtxids so it can successfully create the 2nd output, the witness commitment. This is the reason I verified p2wpkh transactions, I needed to create a witness commitment to have a valid coinbase transaction. The next main component of the script design was the construct_block_header() function. It's the function that requires the merkle root. Creating a valid block header is the most important part of the script because obtaining a block hash that is less than the difficulty target is what is the deciding factor for mining a successful block. When I call the block header in my mining loop in the main. The block header is changed each iteration with a 1 added to the nonce value then hashed and compared. The block hash is then passed to the hashz-meets_difficulty_target() function to check if the hash as an integer is less than the difficulty target as an integer. If so, the block is successfully mined and the serialized blockheader, serialized coinbase transaction, and valid txids are added to the block.
## Implementation details
I've described how my script works and now I want to go a bit deeper into key concepts, components, and important functions that went into the creation of my valid block. I have a few modules, so I'll go through each one at a time explaining these components.

### transaction.rs
I mentioned the transaction.rs module and how the Transaction struct worked but I skipped over the BlockHeader struct. This struct creates a BlockHeader object with the data passed into it from the construct_block_header() function. It helps me keep all the data in one place before serializing it all before adding it to the block.

### utils.rs
Next, I'll look into my utils.rs module. This module keeps all the utility functions that help me in many ways throughout the script.
Starting from the top, I made my get_merkle_root() function. The merkle root function is necessary for creating the block because it's what I use to calculate my merkle and witness root. To make a merkle root you have to change the txids from little endian to big endian. I do this first in the get_merkle_root() function by mapping over each txid in the vector, decoding it from a hex string to bytes, reversing the bytes, and collecting it before pushing it into a 32-byte array. I then collect the byte arrays in a vector where I move them to the next operation in the function. If the merkle root has an odd number of txids (in bytes) I duplicate the last txid and push it into the vector. I'll then iterate over the vector in chunks of two, taking both byte arrays, pushing them into a SHA256 hash function (concatenating them together) then hashing them. This process continues until there is one 32-byte array left. I'll encode the array of bytes into a hex string and return it. I use this function twice. Once in the main.rs where I collect all the txids, create the blocks merkle root, then pass it into the construct_block_header() function, then in the create_coinbase_tx() function where I pass in a vector of wtxids and call the merkle root function there to construct the witness root.
##### Pseudo code:
-	Initialize a mutable variable be_txid (big endian txid) as an empty vector to store the txids.
-	Iterate over each txid in the input vector txid.
     o	For each txid, decode it from hex to bytes.
     o	Reverse the bytes to convert them from little-endian to big-endian.
     o	Copy the reversed bytes into a new array of size 32 and add it to be_txid.
-	While the length of the be_txid vector is greater than 1:
     o	If the length of be_txid is odd, duplicate the last element and add it to the end of the vector.
     o	Split be_txid into chunks of 2 elements each.
     o	For each pair of elements:
     o	Initialize a new SHA256 hasher.
     o	Update the hasher with the first and the second elements concatenating them.
     o	Double SHA256 the hasher
     o	Replace the pair in be_txid with the second hash.
-	The first element of be_txid is the Merkle root in big-endian format. Reverse the bytes.
-	Encode the Merkle root in hexadecimal and return it as the result.

The next few key functions are my transaction serialization functions. These are necessary for block construction because they provide me the serialized data that when hashed gives me the txid or wtxid (depending on the function). So, for legacy transactions, my serialize_tx() function starts by converting the version to little endian bytes before I encode it back into a hex and push it to my serialized transaction string. The input (vin) count is pushed next as 1 byte. Next, for each input, I loop over and reverse the txid and push, convert the vout to little endian and push, calculate the scriptsigs compact size and push it as a byte, then followed by the actual scriptsig, and finally finish with converting the sequence to little endian and push before exiting the for loop. I move on to the outputs (vout) and run a similar process. Push the little-endian output count, then in a for loop for each output, I push the little-endian value (in sats), the scriptpubkeys compact size followed by the actual scriptpubkey. Outside of the loop, I push the locktime in little-endian and if there is a sighash type, I push it onto the end of the serialized transaction. A note to add, when I say reverse to little endian and push or convert to little endian and push, I mean reverse its byte order to little endian, convert it to a hexadecimal then push to the serialized_tx string.
##### Pseudo code:
-	Initialize an empty string serialized_tx to store the serialized transaction.
-	Convert the transaction version to little endian bytes and encode it to hex. Append this to serialized_tx.
-	Get the count of transaction inputs (vin) and append its hex.
-	For each transaction input (vin) in the transaction:
     o	Decode the txid from hex to bytes, reverse the bytes to get the txid in big-endian, and append its hex.
     o	Convert the output index (vout) to little endian bytes and append its hex.
     o	Calculate the compact size of the unlocking script (scriptsig), convert it to hex, and append.
     o	Append the scriptsig.
     o	Convert the sequence number to little endian bytes and append its hex representation to serialized_tx.
-	Get the count of transaction outputs (vout) and append its hex.
-	For each transaction output (vout) in the transaction:
     o	Convert the output value to little endian bytes and append its hex.
     o	Calculate the compact size of the locking script (scriptpubkey), convert it to hex.
     o	Append the scriptpubkey itself to serialized_tx.
-	Convert the locktime to little endian bytes and append its hex.
-	If the transaction has a sighash, append it to serialized_tx.
-	Return serialized_tx.

The process is the same for my serialized_segwit_tx() function except I push 00 and 01, after the version number. These values are the marker and flag. They're used to identify the segwit transactions. Segwit transactions hold their signature and public keys in the witness so if the input is a p2wpkh transaction the scriptsig is 00 otherwise the scripting is pushed to the serialized string like in legacy transactions. I also have the witness reserve value pushed to the serialized transaction function if it's a coinbase transaction (this is only for the coinbase tx) a 01 stack value is pushed, then 20 compact size is pushed before the reserve value. These changes are necessary to serialize a segwit transaction to get a valid transaction ID.
##### Pseudo code:
-	Initialize an empty string serialized_tx to store the serialized transaction.
-	Convert the transaction version to little endian bytes and encode it to hex and append (Same as the previous function)
-	If the first transaction input (vin) is a coinbase transaction, append 0001 to serialized_tx.
-	Get the count of transaction inputs (vin) and append its hex. (Same as the previous function)
-	For each transaction input (vin) in the transaction, do the following:
     o	Decode the txid from hex to bytes, reverse the bytes to get the txid in big-endian, and append its hex. (Same as the previous function)
     o	Convert the output index (vout) to little endian bytes and append the hex. (Same as the previous function)
     o	If the unlocking script (scriptsig) is empty, append 00 to serialized_tx. Otherwise, calculate the compact size of the scriptsig, convert it to hex, and append it to serialized_tx, followed by the scriptsig itself. (Same as the previous function)
     o	Convert the sequence number to little endian bytes and append its hex. (Same as the previous function)
-	Get the count of transaction outputs (vout) and append its hex. (Same as the previous function)
-	For each transaction output (vout) in the transaction, do the same as previous function.
-	For each transaction input (vin) in the transaction, if it has a witness field that equals "0000000000000000000000000000000000000000000000000000000000000000", append 01, 20, and the witness field to serialized_tx.
-	Convert the locktime to little endian bytes and append its hex. (Same as the previous function)
-	Return serialized_tx.

Serializing a segwit transaction to get a wtxid is also a bit different. In serialized_segwit_wtx() everything is again the same as above. However, the witness data is being serialized after the outputs are. For each transaction, you first get the number of stack items with the compact size function and push in hexadecimal format. Next, for each witness item in the witness vector, you get its compact size and push, then push the actual value in the current witness index. That completes the transaction serialization functions. They all have a lot of similarities but the segwit transactions differ a bit when getting their txid and wtxid!
##### Pseudo code:
Everything is the same as the previous transaction except:
-	Append 00 and 01 (after version) to serialized_tx to represent the marker and flag of a segwit transaction.
-	For each transaction input (vin) in the transaction everything is again the same as the previous function but:
     o	Append 00 to serialized_tx to represent an empty scriptsig.
-	After the serialized outputs (vout), for each transaction input (vin) in the transaction, if it has a witness field:
     o	Calculate the compact size of the witness field, convert it to hex then append.
     o	For each item in the witness field, decode it from hex to bytes, calculate its compact size, convert it back to hex, and append it to serialized_tx, followed by the item itself.
-	Return serialized_tx.

The next key component, I want to talk about is preparing the transactions for signing! I'll start with a legacy (p2pkh) function and then move to the segwit function. In the get_tx_readyfor_signing_legacy() function I construct the transaction in a specific way and then use my normal serialize_tx() function to serialize it for the message. This is just a bit different from my get_segwit_message() function where I return the serialized message itself. The get_tx_readyfor_signing_legacy() function starts by extracting the signature and public key from the scriptsig of the first input of the transaction. Then, for each input in the transaction, it clears the scriptsig and replaces it with the scriptpubkey from the previous output (prevout). This is because, in the process of signing a legacy transaction, the scriptsig of the input being signed is replaced with the scriptpubkey of the output being spent! The function then pulls the last two bytes of the signature, which are the sighash type, and adds it to the transaction. After that, the function iterates over each input in the transaction again, clearing the scriptsig and replacing it with the scriptpubkey from the previous output. Finally, the function returns a new Transaction object with the updated version, locktime, inputs, outputs, and sighash type!
##### Pseudo code:
-	Get the scriptsig of the first transaction input (vin).
-	Extract the signature and public key from the scriptsig using the get_signature_and_publickey_from_scriptsig() function.
-	For each transaction input (vin) in the transaction, do the following:
     o	Clear the scriptsig.
     o	Copy the scriptpubkey of the previous output (prevout) to the scriptsig.
-	Extract the last two bytes of the signature to use as the sighash type.
-	Format the sighash type by appending 000000 to it.
-	Set the sighash of the transaction to the formatted sighash type.
-	For each transaction input (vin) in the transaction:
     o	Clear the scriptsig.
     o	Copy the scriptpubkey of the previous output (prevout) to the scriptsig.
-	Return a new transaction.

This next function is a lot different than the previous legacy function. The get_segwit_tx_message() function is used to construct the message that is needed to validate a signature in a segwit transaction. It's a lot different than the legacy message construction. I created this function to return a string of the pre-image (or message). You start by pushing the 4-byte little endian version number. Next, for each input, you concatenate the little-endian txid and vout then push them to a variable named input_bytes, then do the same thing for sequence and a sequence_bytes variable. After the loop breaks, the input_hash variable with the txid+vouts and sequence_bytes variable is hashed and pushed to the preimage string. The next step is to serialize the txid+vout of the input we're checking the signature on, hashing like before, and pushing to the preimage. Afterward, I formatted the scriptcode by passing in the public key hash (from p2wpkh_script_validation()) into the function so I could format it into a specific structure that looks like this 1976a914{publickeyhash}88ac afterwards it pushed to preimage. Up next, we convert the amount to little-endian and sequence then push them one after the other to the preimage variable. For each output, I made an output_bytes variable to push data in so I could hash it afterward. The amount in sats is pushed as little-endian first, the scriptpubkey_size compact size, then scriptpubkey itself is pushed. Once all the output data is pushed it is double-hashed and pushed to the preimage variable (in hex). The last couple of values needed for the preimage are the locktime and sighash and of course, they're byte order is reversed and encoded in hex! Finally, the segwit preimage for signature validation is created and can be sent to the p2wpkh script validation to verify signatures.
##### Pseudo code:
-	Clone the transaction to a new variable tx.
-	Convert the transaction version to little-endian bytes and encode it to hex. Store this in version.
-	Initialize two empty byte vectors input_bytes and sequences_bytes.
-	For each transaction input (vin) in the transaction:
     o	Decode the txid from hex to bytes, reverse the bytes to get the txid in big-endian, and append these bytes to input_bytes.
     o	Convert the output index (vout) to little-endian bytes and append to input_bytes.
     o	Convert the sequence number to little-endian bytes and append to sequences_bytes.
-	Double SHA256 hash the input_bytes and sequences_bytes. Store these in input_hash and sequences_hash.
-	Get the transaction input (vin) at the specified index from vin_index.
-	Decode the txid of this input from hex to bytes, reverse the bytes to get the txid in big-endian, and encode this to hex. Store in. txid.
-	Convert the output index (vout) of this input to little endian bytes and encode this to hex. Store in vout.
-	Format txid and vout into a string input.
-	Format the public key hash pubkey_hash into a script code scriptcode.
-	Get the value of the previous output (prevout) of this input, convert it to little-endian bytes, and encode this to hex. Store in amount_le.
-	Convert the sequence number of this input to little-endian bytes and encode this to hex. Store in sequence.
-	Initialize an empty byte vector output_bytes.
-	For each transaction output (vout) in the transaction:
     o	Convert the output value to little-endian bytes and append to output_bytes.
     o	Calculate the compact size of the locking script (scriptpubkey), convert it to bytes, and append to output_bytes.
     o	Decode the locking script (scriptpubkey) from hex to bytes and append to output_bytes.
-	Double SHA256 hash the output_bytes and store this in output_hash.
-	Convert the locktime of the transaction to little-endian bytes and encode this to hex. Store in locktime.
-	Convert the sighash type sighash_type to a 32-bit integer, convert this to little-endian bytes, and encode to hex. Store in formatted_sighash.
-	Format all the variables into one preimage string (concatenating them)
-	Return preimage.

The last key function I want to talk about from util.rs is the get_signature_and_publickey_from_scriptsig() function. This function is designed to pull the signature and public key from the scriptsig of a p2pkh transaction. It takes a scriptsig (in hex), as input and decodes it into bytes. It then iterates through these bytes, checking for the end of the scriptsig and the length of the data to be pushed onto the stack. It reads the data of the specified length from the scriptsig bytes and advances the index by the length of the data. The data is then encoded back into a hexadecimal string and pushed onto a vector. After the loop, the function checks if the vector contains exactly two elements (the signature and the public key). Finally, the function returns the signature and public key as a tuple of strings.
##### Pseudo code:
-	Decode the scriptsig string from hex to bytes. Store in scriptsig_bytes.
-	Initialize an index to 0.
-	Initialize an empty vector sig_and_pubkey_vec.
-	While index is less than the length of scriptsig_bytes:
     o	If index plus 1 is greater than or equal to the length of scriptsig_bytes, return an error indicating an unexpected end of scriptsig.
     o	Get the byte at index in scriptsig_bytes as an integer length. This byte represents the length of data to push (either a signature or a public key).
     o	Increment index += 1.
     o	If index plus length is greater than the length of scriptsig_bytes, return an error indicating that the scriptsig length byte exceeds the remaining data.
     o	Get the slice of scriptsig_bytes from index to index plus length as data.
     o	Increment index += length.
     o	Encode data to hex and append to sig_and_pubkey_vec.
-	If the length of sig_and_pubkey_vec isn't 2, return an error indicating that 2 elements were expected.
-	Return the first and second elements of sig_and_pubkey_vec (signature and public key).
     
### validation.rs
My validations.rs module is full of functions that need to check if something is valid, and if so, they return true and return the valid variable or variables.
The first function in this module is process_mempool() this function is what checks each transaction (after they are verified in their respective functions) and adds them to a vector that will be the final transactions in the block! The function begins by accepting a path to the mempool as input and initializing an empty vector valid_txs to store valid transactions. It then iterates over each transaction in the mempool directory. For each transaction, it checks if the path is a file and if so, it deserializes the transaction. It then checks the script type of the transaction and validates it accordingly. If the script type is v0_p2wpkh, it validates the transaction using the p2wpkh_script_validation() function. If the script type is p2pkh, it validates the transaction using the p2pkh_script_validation() function. If the transaction isn't valid, it skips the current function and moves on to the next check. Next, the function checks if the locktime of the transaction is valid by comparing it to the current time. If the locktime is greater than the current time it breaks from the loop and moves to the next transaction. Next, the function calculates the transaction fee using the verify_tx_fee() function and checks for double spending using the check_double_spending() function. If the transaction is a double spend, it again breaks the loop and moves on to the next transaction. Finally, if the transaction passes all the checks, it is added to the valid_txs vector. The function returns the vector containing all the valid transactions with the txid, wtxid, and fee.
##### Pseudo code:
-	Initialize an empty vector valid_txs to store valid transactions.
-	Iterate over each transaction in mempool.
-	For each transaction, check if the path is a file.
-	If the path is a file, convert the path to a string.
-	Deserialize the transaction from the file.
-	Initialize is_valid, txid, and wtxid variables.
-	Check the script type of the transaction's first input's previous output.
-	If the script type is v0_p2wpkh, validate the transaction using the p2wpkh_script_validation function. If the transaction is valid, set is_valid to true and update wtxid and txid.
-	If the script type is p2pkh, validate the transaction using the p2pkh_script_validation function. If the transaction is valid, set is_valid to true and update txid.
-	If the transaction isn't valid, skip the current iteration and move to the next transaction.
-	Check if the transaction's locktime is valid by comparing it to the current time.
-	Calculate the transaction fee using the verify_tx_fee function.
-	Check for double spending using the check_double_spending function.
-	If the transaction passes all the checks, add it to the valid_txs vector.
-	Finally, return the valid_txs vector containing all the valid transactions.

Another key component is the verify_signature() function. This function is called in my p2pkh_script_validation() when the script gets to the OP_CHECKSIG match arm. The function is used to verify the signature of both p2pkh and p2wpkh transactions. It takes three parameters: the signature, the public key, and the serialized transaction. The function first removes the sighash type from the der encoded signature. It then creates a new instance of the secp256k1. The function proceeds to hash the serialized transaction using the double_sha256() function and creates a Message from the hash. It then creates a PublicKey from the provided public key bytes and a Signature from the provided der encoded signature (in bytes). Finally, it verifies the signature against the message and the public key using the verify_ecdsa method of the Secp256k1 crate. If the signature is valid, it returns true, otherwise it returns false!
##### Pseudo code:
-	Remove the sighash type from the signature.
-	Create a new instance of the secp256k1.
-	Hash the serialized transaction using the double_sha256 function.
-	Create a Message from the hash.
-	Create a PublicKey from the provided public key bytes.
-	Create a Signature from the provided signature bytes.
-	Verify the signature against the message and the public key using the verify_ecdsa method of the secp256k1.
-	If the signature is valid, return true, otherwise return false.

The next two functions are some of the most important functions. They are the functions that find valid transactions. Side note, I duplicated the code where it executed the scriptpubkey_asm OP codes just because of time and the need to focus on my proposal. I should have made it a function and called it in each transaction validation function because it is the same logic but I didn't get to it unfortunately.

Anyway,  p2wpkh_script_validation() is the function that successfully checks and verifies if p2wpkh transactions are valid or not. It uses a stack to hold data and iterates over each input in the transaction. For each input, it pulls the witness data, which includes the signature and the public key. It then executes the locking script, which is similar to a P2PKH locking script. The function performs different operations such as duplicating the top item on the stack, hashing the top item on the stack, comparing the top two items on the stack, and verifying the signature. If the signature is valid, it pushes a 1 onto the stack. If the stack is not empty or does not contain exactly one item, it returns an error. Finally, it serializes the transaction and then hashes them to get the wtxid and the txid. It reverses the bytes for both and returns them along with the validity of the transaction!
##### Pseudo code:
-	First initialize an empty stack.
-	Iterate over each input in the transaction.
-	Clear the stack for each input.
-	Extract the witness data from the input. If the witness data is missing, return an error.
-	Remove the signature and the public key from the witness data and push them onto the stack.
-	Extract the scriptpubkey from the prevout of the input and split it into parts to get the public key hash.
-	Generate the message hash by serializing the transaction and hashing it twice using SHA256.
-	Execute the scriptpukey_asm. For each operation in the script:
     o	If the operation is OP_DUP, duplicate the top item on the stack.
     o	If the operation is OP_HASH160, pop the top item from the stack, hash it using SHA256, and then RIPEMD160, and push the result back onto the stack.
     o	If the operation is OP_EQUALVERIFY, pop the top two items from the stack and compare them. If they are not equal, return an error.
     o	If the operation is OP_CHECKSIG, pop the top two items from the stack (the public key and the signature), and verify the signature. If the signature is invalid, return an error.
     o	If the operation is not an operator, it's data (like a signature or a public key), so decode it from hex and push it onto the stack.
-	If the stack is empty or does not contain exactly one item, return an error.
-	Serialize the transaction to get the wtxid and txid and return them with either true or false.
     
The p2pkh_script_validation() function validates p2pkh transactions. It uses a stack to hold data and iterates over each input in the transaction. For each input, it extracts the scriptsig and scriptpubkey. It then prepares the transaction for signing by cloning it and replacing its inputs with the current input. The function performs various operations like the previous function, including duplicating the top item on the stack, hashing the top item on the stack, comparing the top two items on the stack, and verifying the signature. If the signature is valid, it pushes a 1 onto the stack. If the stack is empty or doesn't hold one item, it returns an error. Finally, it serializes the transaction, hashes it twice, reverses the bytes and hex encodes to return a txid and true or false.
##### Pseudo code:
-	Initialize an empty stack.
-	Iterate over each input in the transaction.
-	Clear the stack for each input.
-	Extract the scriptsig and scriptpubkey from the input.
-	Extract the signature and the public key from the scriptsig and push them onto the stack.
-	Prepare the transaction for signing by replacing its inputs with the current input.
-	Serialize the transaction and convert it into bytes to get the message.
-	Execute the scriptpubkey_asm. For each operation in the script execute just like the previous function.
-	If the stack is empty or does not contain exactly one item, return an error.
-	Serialize the transaction, hash it twice, reverse the bytes, and return it in hex encoding along with either true or false.
### block.rs
My second to last module has two important functions I want to explain, the create_coinbase_tx() function and the construct_block_header() function.

The create_coinbase_tx() function is used to create a coinbase transaction, the serialized coinbase transaction (in the block) and the first txid in the block. The function takes two parameters: total_tx_fee, which represents the total transaction fees in the block, and witness_root_vec, a vector of strings representing the witness root wtxids. It begins by initializing a new Transaction object, coinbase_tx, with default values. The block subsidy (the reward for mining a new block) is calculated as 6.25 (I made this before the halving sats plus the total transaction fees. A p2pkh scriptpubkey is created for the return address. The scriptsig for the block is also created, which includes the block height. Next, the function adds the input to the coinbase_tx transaction. This input has a txid of all zeros. The scriptsig for this input is set to the block scriptsig created earlier. Next, the function adds an output to the coinbase_tx transaction. This output has a scriptpubkey set to the scriptpubkey created earlier, and its value is set to the block subsidy plus fees. The function then calculates the witness root hash and concatenates it with the txid to create the witness commitment. The commitment is hashed and encoded into hex. A second output is added to the coinbase_tx transaction, with a scriptpubkey that includes the witness commitment. This output has a value of 0, as it is used for the witness commitment and does not transfer any sats. Finally, the function returns the coinbase_tx transaction object.
##### Pseudo code:
-	Initialize a new Transaction object coinbase_tx with version 0, locktime 0, empty vectors for vin and vout, and None for sighash.
-	Calculate the block subsidy plus fees as 625000000 (I made this before the halving) plus total_tx_fee. Store this in block_sub_plus_fees.
-	Define a scriptpubkey for the return address. Store this in scriptpubkey.
-	Define a scriptsig for the block that includes the block height. Store in block_scriptsig.
-	Set the version of coinbase_tx to 0.
-	Define a txid of all zeros.
-	Add an input to coinbase_tx with the following properties:
     o	txid.
     o	vout is 0xffffffff.
     o	prevout is a Prevout object with empty strings for scriptpubkey, scriptpubkey_asm, scriptpubkey_type, scriptpubkey_address, and 0 for value.
     o	scriptsig is block_scriptsig.
     o	scriptsig_asm is OP_PUSHBYTES_3 837122.
     o	witness is a vector containing txid (zeros).
     o	is_coinbase is true.
     o	sequence is 0xffffffff.
-	Add an output to coinbase_tx with the following properties:
     o	scriptpubkey is scriptpubkey.
     o	scriptpubkey_asm is OP_DUP OP_HASH160 OP_PUSHBYTES_20 06f1b66fd59a34755c37a8f701f43e937cdbeb13 OP_EQUALVERIFY OP_CHECKSIG.
     o	scriptpubkey_type is p2pkh.
     o	scriptpubkey_address is None.
     o	value is block_sub_plus_fees.
-	Calculate the witness root hash from witness_root_vec. Store this in witness_root_hash.
-	Concatenate witness_root_hash and txid (same as witness reserve value). Store in concant_items.
-	Decode concant_items from hex to bytes. Store in wtxid_items_bytes.
-	Calculate the double SHA256 hash of wtxid_items_bytes. Encode in hex. Store in wtxid_commitment.
-	Format a scriptpubkey for the witness commitment. Store inscriptpubkey_for_wtxid_test.
-	Add a second output to coinbase_tx:
     o	scriptpubkey is scriptpubkey_for_wtxid_test.
     o	scriptpubkey_asm is OP_RETURN OP_PUSHBYTES_36 aa21a9ed plus wtxid_commitment.
     o	scriptpubkey_type is op_return.
     o	scriptpubkey_address is None.
     o	value is 0.
-	Return coinbase_tx.

Finally, the construct_block_header() function. This function constructs a blockheader so I could be serialized and then hashed to compare to the difficulty target. The function takes two parameters: nonce, a 32-bit unsigned integer, and merkle_root, a string. I created a BlockHeader struct with default values, including a version number, an empty previous block hash, the provided merkle root, a timestamp of 0, a hardcoded bits value, and a nonce of 0. Next, it decodes the previous block hash from hex to bytes, reverses the byte order, and encodes it back to a hex string. This reversed hex string is then set as the prev_block_hash in the BlockHeader struct. Then the function gets the current system time, calculates the duration since the UNIX_EPOCH in seconds, and sets this value as the timestamp in the BlockHeader struct. Finally, it sets the nonce in the BlockHeader struct to the nonce passed into the function (the nonce is incremented by one in main until the hash <= target) and returns the BlockHeader struct.
##### Pseudo code:
-	Define a function construct_block_header that takes two parameters: nonce and merkle_root.
-	Initialize a BlockHeader struct with:
     o	version set to 0x20000000
     o	prev_block_hash set to an empty string
     o	merkle_root set to the input merkle_root
     o	timestamp set to 0
     o	bits` set to 0x1f00ffff (this is a hardcoded value)
     o	nonce set to 0
-	Define a string prev_block_hash with the block hash from the block that came before mine.
-	Decode prev_block_hash from hex to bytes.
-	Reverse the byte order of the decoded prev_block_hash.
-	Encode the reversed byte array back to a hex string.
-	Set the prev_block_hash property of the BlockHeader struct to the reversed hex string.
-	Get the current system time and calculate the duration since UNIX_EPOCH in seconds.
-	Set the timestamp property of the BlockHeader struct to the calculated duration.
-	Set the nonce property of the BlockHeader struct to the input nonce.
-	Return the BlockHeader struct.

### main.rs
Finally, in main.rs, the driver function mines the block. Main begins by initializing a handful of variables and pulling the helper functions I created in the other modules to help construct and mine the block. It starts by defining the path to the mempool folder and initializing the nonce value to 0. The valid_txs variable calls the process_mempool() function that returns a vector of valid transactions. Then initializes an empty vector block_txs to store the transactions for the block, as well as total_weight to keep track of the total weight of the transactions. The maximum block weight is set to 4000000. Next, the total_fees variable is initialized to 0 to keep track of the total transaction fees, and the valid transactions are sorted in descending order by fee. The function then iterates over the sorted transactions, calculating the weight of each transaction. If adding the weight of a transaction to the total weight would exceed the maximum block weight, the loop breaks. Otherwise, the transaction is added to block_txs, and its weight and fee are added to total_weight and total_fees. The transactions in block_txs are then sorted in descending order by fee. A vector wtx_ids_for_witness_root is initialized to store the wtxid for the witness root. The function iterates over block_txs, and for each transaction, if it's a p2wpkh transaction, the wtxid is added to wtx_ids_for_witness_root. Otherwise, the txid is added. The function then generates the coinbase transaction is called and the total_fees and wtx_ids_for_witness_root variables are passed in before I serialize it. The serialized coinbase transaction is decoded from hex to bytes. The txid of the coinbase transaction is calculated, reversed to little-endian format, and encoded to hex. The coinbase transaction is then inserted at the beginning of block_txs. The merkle root is generated next from the txids in block_txs. Finally, the function then enters a mining loop. In each iteration, it constructs the block header with the nonce, the merkle root, and serializes it. It calculates the hash of the serialized block header, reverses it to little-endian format, and encodes it to hex. If the hash meets the difficulty target, the block is written to a file a success message is printed, and the loop breaks. Otherwise, the nonce is incremented and the loop continues until a block is found.
##### Pseudo code for main.rs
-	Define the path to the mempool folder.
-	Initialize the nonce value to 0.
-	Get the valid transactions from the mempool.
-	Initialize an empty vector block_txs to store the transactions for the block.
-	Initialize total_weight to 0 to keep track of the total weight of the transactions.
-	Set the maximum block weight to 4000000.
-	Initialize total_fees to 0 to keep track of the total transaction fees.
-	Sort the valid transactions in descending order by fee.
-	For each transaction in the sorted transactions:
     o	Calculate the weight of the transaction.
     o	If adding this transaction would exceed the maximum block weight, break the loop.
     o	Otherwise, add the transaction to block_txs, and add its weight and fee to total_weight and total_fees.
-	Sort block_txs in descending order by fee.
-	Initialize a vector wtx_ids_for_witness_root to store the witness wtxid for the witness root.
-	For each transaction in block_txs:
     o	If the transaction is a p2wpk transaction and has a wtxid, add the wtxid to wtx_ids_for_witness_root.
     o	Otherwise, add the txid to wtx_ids_for_witness_root.
-	Generate the coinbase transaction with total_fees and wtx_ids_for_witness_root and serialize it.
-	Decode the serialized coinbase transaction from hex to bytes.
-	Calculate the txid of the coinbase transaction, reverse it to little-endian format, and encode it to hex.
-	Insert the coinbase transaction at the beginning of block_txs.
-	Generate the Merkle root from the txids in block_txs.
-	Start the mining loop:
     o	Construct the block header with the nonce and merkle root and serialize it.
     o	Calculate the hash of the serialized block header, reverse it to little-endian format, and encode it to hex.
     o	If the hash is <= difficulty target, write the block to a file and print a success message, then break the loop.
     o	Otherwise, increment the nonce and continue the loop.

## Results and Performance
The results of my project have been promising, earning a score of 88! However, I still have a lot of room for improvement. I would have liked to validate p2sh or p2wsh transactions, so I had enough valid transactions to better test the efficiency of my code. In the current state, my script validates every valid p2pkh and p2wpkh transaction and after I add them all to the block, I still have around 500k weight units left over. So, in the future, I'd wish to improve the number of transaction types I could validate. Throughout the project, I significantly optimized the mining process, reducing the average mining time from nearly 10 minutes to just 1.5 minutes. This improvement stemmed from a key modification in how I handled mempool data: I implemented a buffer in the deserialize_tx() function, which allowed for bulk reading of mempool files. This approach is more efficient than processing data byte-by-byte or in small chunks, as it minimizes read operations and speeds up JSON parsing by serde.
Further efficiency gains were achieved with the serialize_block_header() function, which directly writes header data into a pre-allocated 80-byte buffer using in-place operations. This method significantly speeds up the preparation of new block headers for hashing, reducing the interval between hash attempts. This stands in contrast to my transaction serialization approach, which serializes fields individually and accumulates them in a vector. Moving forward, I plan to refine these serialization processes to further enhance the efficiency and performance of my mining script.
## Conclusion
Over the past few months during the Summer of Bitcoin boot camp and proposal process, I’ve experienced significant growth as a developer, particularly in my Rust programming skills which I've been honing for almost a year now. The challenge of constructing a valid block not only enhanced my technical proficiency but also deepened my appreciation for the meticulous efforts of long-time bitcoin (and lightning) developers.
This project was a comprehensive learning journey. Writing script validation code and operating on OP codes was particularly enlightening. Each successful operation was a success, and each failure was a valuable lesson for me. This led to my improved ability to write great tests in Rust. Although I didn't utilize Rust's existing test frameworks, the tests I developed played a crucial role in identifying issues with signature validations and stack operations, in turn enhancing my debugging skills. Another essential learning experience was the importance of thorough research and effective communication. Early in the project, I encountered numerous challenges that could have been mitigated with better prep research or by seeking advice from Discord.
Despite the progress, there are areas requiring future improvement. Notably, the serialization process revealed frequent errors. Often from redundant encoding operations or incorrect byte handling. These experiences have highlighted the necessity of a meticulous approach to writing code and the importance of understanding when and where to apply specific operations. The sole reliance on resources like learnmeabitcoin.com, while immensely helpful, sometimes led to confusion, particularly with byte reversal operations. In such instances, turning to ChatGPT proved helpful, providing quick resolutions and clarifications that were critical to my progress once I got stuck. This project has not only strengthened my technical skills but also reinforced my desire to pursue a career in bitcoin and more specifically lightning development. The insights gained are too numerous to condense into a single report, but each one has prepared me better for future challenges. I'm looking forward to the possibility of contributing to LDK and continuing my growth in the Summer of Bitcoin internship!


#### References
•	https://learnmeabitcoin.com/technical/




