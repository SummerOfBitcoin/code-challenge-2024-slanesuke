# Solution for the Summer of Bitcoin Dev Assignment

## Design Approach
In the project **code-challenge-2024-slanesuke/mine-your-first-block/**, I wrote a Rust script tasked with reading and verifying the validity of transactions to construct a single, valid block. The script's main objective was to score well initially, requiring the incorporation of valid transactions and a witness commitment as essential components for mining a block (amongst many other requirements). So, I started by focusing on verifying Pay-to-Public-Key-Hash (p2pkh) and Pay-to-Witness-Public-Key-Hash (p2wpkh) transactions in order to cover the two required transaction types.

To begin transaction verification, I implemented several helper functions crucial for processing different types of transactions. These functions primarily focused on serializing transaction data appropriately for signature verification using the OP_CHECKSIG operation. Specifically, each transaction required the retrieval of the signature and the public key. The methods to get these elements varied between transaction types due to witness data in p2wpkh transactions.
For p2pkh transactions, I developed a function to parse the signature and public key from the scriptsig within each transaction input (vin). Conversely, for p2swpkh transactions, extraction was more straightforward. I could directly access and hardcode the signature and public key from the witness field, which consistently stores the signature at index 0 and the public key at index 1.
The culmination of these initial steps was the **verify_signature** function. This function accepted the serialized message, the public key, and the DER-encoded signature, returning true only if the signature verification succeeded, ensuring transaction authenticity.

Throughout the project, I also relied on several small, specialized functions to perform repetitive tasks efficiently. One function was the **reverse_byte** function, which was essential for converting data between big-endian and little-endian formats. This functionality was particularly crucial for displaying txids in little-endian within the block and for accurately computing the merkle and witness roots, where byte reversal was necessary to obtain the correct values.
Another key function was the **compact_size** function, used to determine the size of witness fields and the scriptsig before appending the actual data during transaction serialization.
But, the most essential functions could have been the hashing functions—**ripemd160**, **sha256**, and **double_sha256**. Despite their simplicity, these functions played a huge role in the script’s architecture and design due to their frequent use throughout the transaction processing and verification stages.

The design of the block construction process was straightforward. Once the block header, coinbase transaction, and transactions were verified and collected, the remaining task was relatively simple. I made the **write_block_to_file** function to write all this information into the block (output.txt file). This function was called once the calculated block hash met or fell below the difficulty target, effectively finishing the block construction.

When I began writing this Rust script, I lacked a formal set of design principles, primarily due to my inexperience with large, complex projects. My initial goal was to create a solution that scored above 60 points to pass. For most of April, this meant managing around 1600 lines of code contained within the **main**. However, as I progressed, I managed to refine and modularize the code, which not only helped me surpass the minimum score but also significantly improved the script's efficiency and reliability.
Initially, mining a block could take upwards of ten minutes, but through continuous work and optimization, I reduced this time to just 1-2 minutes. Despite the early disorganization, I designed the functions in such a way that if an issue arose, pinpointing and resolving the bug was straightforward. This approach ensured the script remained hardy under various conditions.

As a high-level overview, the script is organized around several key components and their interactions, beginning with the **Transaction** struct. This struct holds the transaction data processed by the **deserialize_tx** function, which reads transactions from JSON files, deserializes the data into a **Transaction** object, and returns this object. This setup allows for the manipulation of transaction properties and facilitates operations like transaction script validation.
Each **Transaction** object undergoes serialization through functions such as **serialize_tx**, **serialize_segwit_tx**, and **serialize_segwit_wtx**. Serialization is crucial in bitcoin for verifying signatures in p2pkh transactions and obtaining txids in both legacy and segwit transactions. These objects are then passed to script validation functions—**p2pkh_script_validation** for p2pkh transactions and **p2wpkh_script_validation** for p2wpkh transactions. These functions execute the locking and unlocking scripts, returning true along with the txid and, if applicable, the wtxid upon successful verification.
Validated transactions are handled by the **process_mempool** function, which conducts additional validations before encapsulating them in a **TransactionForProcessing** struct. This struct is crucial for mining, as it differentiates txids from wtxids to accurately calculate the merkle root and witness root, achieved from the **get_merkle_root** function. This function takes a vector of txids (or wtxids), reverses them, and calculates the root.
With valid transactions in the **TransactionForProcessing** vector, the script can construct the merkle root (for the block header) and the witness root needed for the coinbase transactions. The **create_coinbase_tx** function is crucial here. It receives the total transaction fees and a vector of wtxids to create the second output, the witness commitment, essential for a valid coinbase transaction in the scenario where a p2wpkh is in the block.
The next major component is the **construct_block_header** function, which is vital as it requires the merkle root to create a valid block header. The success of mining relies on generating a block hash that meets or is lower than the difficulty target. This is continually checked in the mining loop within the **main**, where each iteration involves incrementing the nonce (by 1), hashing the block header, and comparing it. If the block hash meets the difficulty target, verified by the **hash_meets_difficulty_target** function, the block is successfully mined, adding the serialized block header, coinbase transaction, and valid txids to the block!

## Implementation details
Having outlined the general workings of my script, I'll now dive deeper into the key concepts, components, and critical functions that were instrumental in constructing a valid block. The script comprises several modules, each with distinct roles and responsibilities. In the following sections, I will analyze each module, explaining the specific components and their contributions to the project's success.
### transaction.rs
In my previous sections, talked about the **transaction.rs** module and explained the operation of the **Transaction** struct. However, I missed details about the **BlockHeader** struct. This struct is pivotal in creating a BlockHeader object, which is populated with data supplied by the **construct_block_header** function. The primary role of this struct is to organize and maintain all relevant data in a cohesive structure before it undergoes serialization and integration into the block.
### utils.rs
Next, I will go into the **utils.rs** module. This module houses a collection of utility functions that play a crucial role in supporting various operations throughout the script.

Starting from the top, the **get_merkle_root** function is foundational in constructing the block as it calculates both the merkle and witness roots. The process begins by converting the txids from little endian to big endian format. This is achieved by mapping over each txid in the vector, decoding it from a hex string to bytes, reversing these bytes, and collecting them into a 32-byte array.
These byte arrays are then collected in a vector, which is prepared for the next phase of the function. If the vector has an odd number of txids, the last txid is duplicated to ensure an even number for processing. The function proceeds by iterating over the vector in chunks of two, where both byte arrays are concatenated and then fed into a SHA256 hash function. This hashing process is repeated until only one 32-byte array remains.
Finally, this array is encoded back into a hex string and returned as the merkle root. This critical function is utilized twice within the script: once in **main.rs** to gather all txids, create the block's merkle root, and input it into the **construct_block_header** function and again in the **create_coinbase_tx** function, where a vector of wtxids is passed to construct the witness root.
##### Pseudo code:
-	Initialize a mutable variable be_txid (big endian txid) as an empty vector to store the txids.
-	Iterate over each txid in the input vector txid.
     -	For each txid, decode it from hex to bytes.
     -	Reverse the bytes to convert them from little-endian to big-endian.
     -	Copy the reversed bytes into a new array of size 32 and add it to be_txid.
-	While the length of the be_txid vector is greater than 1:
     -	If the length of be_txid is odd, duplicate the last element and add it to the end of the vector.
     -	Split be_txid into chunks of 2 elements each.
     -	For each pair of elements:
     -	Initialize a new SHA256 hasher.
     -	Update the hasher with the first and the second elements concatenating them.
     -	Double SHA256 the hasher
     -	Replace the pair in be_txid with the second hash.
-	The first element of be_txid is the Merkle root in big-endian format. Reverse the bytes.
-	Encode the Merkle root in hexadecimal and return it as the result.

The next few key functions are my transaction serialization functions. These are essential for block construction as they provide the serialized data that, when hashed, yields the txid or witness wtxid, depending on the function used. For legacy transactions, my **serialize_tx** function begins by converting the version number into little endian bytes, encoding it back into a hex string, and appending it to my serialized transaction string. The input (vin) count is added next as a single byte.
For each input, I loop through the following steps: reverse the txid and append it, convert the vout to little endian and append it, calculate the scriptsig's compact size and append it as a byte, followed by the actual scriptsig, and conclude with converting the sequence to little endian and appending it before exiting the loop.
Moving on to the outputs (vout), I follow a similar process. I append the little endian output count, and for each output, I append the little endian value (in sats), the scriptubkey's compact size followed by the actual scriptpubkey. Outside of this loop, I append the locktime in little endian and, if present, the sighash type at the end of the serialized transaction.
It's important to note that when I mention reversing to little endian and appending or converting to little endian and appending, I am referring to reversing its byte order to little endian, converting it to a hex, then appending it to the serialized_tx string.
##### Pseudo code:
-	Initialize an empty string serialized_tx to store the serialized transaction.
-	Convert the transaction version to little endian bytes and encode it to hex. Append this to serialized_tx.
-	Get the count of transaction inputs (vin) and append its hex.
-	For each transaction input (vin) in the transaction:
     -	Decode the txid from hex to bytes, reverse the bytes to get the txid in big endian, and append its hex.
     -	Convert the output index (vout) to little endian bytes and append its hex.
     -	Calculate the compact size of the unlocking script (scriptsig), convert it to hex, and append.
     -	Append the scriptsig.
     -	Convert the sequence number to little endian bytes and append its hex representation to serialized_tx.
-	Get the count of transaction outputs (vout) and append its hex.
-	For each transaction output (vout) in the transaction:
     -	Convert the output value to little endian bytes and append its hex.
     -	Calculate the compact size of the locking script (scriptpubkey), convert it to hex.
     -	Append the scriptpubkey itself to serialized_tx.
-	Convert the locktime to little endian bytes and append its hex.
-	If the transaction has a sighash, append it to serialized_tx.
-	Return serialized_tx.

The process for my **serialize_segwit_tx** function is similar to **serialize_tx**, but with a few distinctions to accommodate segwit transactions. After appending the version number, I push 00 and 01, which serve as the marker and flag. These values are crucial for identifying segwit transactions, which store their signature and public keys in the witness data. If the input belongs to a p2wpkh transaction, the scriptsig is 00. Otherwise, the scriptsig is appended to the serialized string as in legacy transactions.
Also, if the transaction is a coinbase transaction, the witness reserve value is incorporated into the serialization process. Specifically, a 01 stack value is pushed, followed by 20 as the compact size, and then the reserve value itself. These changes are necessary for serializing a segwit transaction to accurately generate a valid txid
##### Pseudo code:
-	Initialize an empty string serialized_tx to store the serialized transaction.
-	Convert the transaction version to little endian bytes and encode it to hex and append (Same as the previous function)
-	If the first transaction input (vin) is a coinbase transaction, append 0001 to serialized_tx.
-	Get the count of transaction inputs (vin) and append its hex. (Same as the previous function)
-	For each transaction input (vin) in the transaction, do the following:
     -	Decode the txid from hex to bytes, reverse the bytes to get the txid in big-endian, and append its hex. (Same as the previous function)
     -	Convert the output index (vout) to little endian bytes and append the hex. (Same as the previous function)
     -	If the unlocking script (scriptsig) is empty, append 00 to serialized_tx. Otherwise, calculate the compact size of the scriptsig, convert it to hex, and append it to serialized_tx, followed by the scriptsig itself. (Same as the previous function)
     -	Convert the sequence number to little endian bytes and append its hex. (Same as the previous function)
-	Get the count of transaction outputs (vout) and append its hex. (Same as the previous function)
-	For each transaction output (vout) in the transaction, do the same as previous function.
-	For each transaction input (vin) in the transaction, if it has a witness field that equals "0000000000000000000000000000000000000000000000000000000000000000", append 01, 20, and the witness field to serialized_tx.
-	Convert the locktime to little endian bytes and append its hex. (Same as the previous function)
-	Return serialized_tx.

Serializing a segwit transaction to derive a wtxid follows a slightly modified procedure in the **serialize_segwit_wtx** function. While the initial steps mirror those described above, the serialization of witness data occurs after the outputs. For each transaction, the number of stack items is determined using the **compact size* function and pushed as a hex. Afterward, for each item in the witness vector, its compact size is calculated and appended, followed by the actual value at the current witness index.
These transaction serialization functions share many similarities, yet the methods for obtaining the txid and wtxid in segwit transactions introduce important differences.
##### Pseudo code:
Everything is the same as the previous transaction except:
-	Append 00 and 01 (after version) to serialized_tx to represent the marker and flag of a segwit transaction.
-	For each transaction input (vin) in the transaction everything is again the same as the previous function but:
     -	Append 00 to serialized_tx to represent an empty scriptsig.
-	After the serialized outputs (vout), for each transaction input (vin) in the transaction, if it has a witness field:
     -	Calculate the compact size of the witness field, convert it to hex then append.
     -	For each item in the witness field, decode it from hex to bytes, calculate its compact size, convert it back to hex, and append it to serialized_tx, followed by the item itself.
-	Return serialized_tx.

The next important component I want to talk about involves preparing transactions for signing. I'll start with the legacy process and then describe the segwit approach. The **get_tx_ready_for_signing_legacy** function constructs the transaction in a specific manner before using the **serialize_tx** function to serialize it for the message. This differs slightly from the **get_segwit_message** function, which directly returns the serialized message.
For a legacy transaction, **get_tx_ready_for_signing_legacy** begins by extracting the signature and public key from the scriptsig of the first input. Next, for each input in the transaction, it clears the existing scriptsig and replaces it with the scriptsubsey from the output being spent (prevout). This replacement is essential because, during the signing process, the scriptsig of the input being signed is substituted with the scriptsubkey of the corresponding output. After removing the last two bytes of the signature (the sighash type), they are appended to the transaction.
The function then iterates over each input again, performing the same replacement of scriptsig with scriptpubkey. Ultimately, it returns a new **Transaction** object that includes the updated elements: version, locktime, inputs, outputs, and sighash type!
##### Pseudo code:
-	Get the scriptsig of the first transaction input (vin).
-	Extract the signature and public key from the scriptsig using the get_signature_and_publickey_from_scriptsig function.
-	For each transaction input (vin) in the transaction, do the following:
     -	Clear the scriptsig.
     -	Copy the scriptpubkey of the previous output (prevout) to the scriptsig.
-	Extract the last two bytes of the signature to use as the sighash type.
-	Format the sighash type by appending 000000 to it.
-	Set the sighash of the transaction to the formatted sighash type.
-	For each transaction input (vin) in the transaction:
     -	Clear the scriptsig.
     -	Copy the scriptpubkey of the previous output (prevout) to the scriptsig.
-	Return a new transaction.

The **get_segwit_tx_message** function plays a crucial role in constructing the message required to validate a signature in a segwit transaction, differing significantly from the legacy message construction. This function is designed to assemble the pre-image (or message) needed for signature validation.
The process starts by appending the 4-byte little endian version number to the message. For each input, the txid and output index (vout), both in little endian, are concatenated along with the sequence number, and then stored in variables named input_bytes and sequence_bytes, respectively.
After iterating through all inputs, the input_hash variable, which combines txid+vouts and sequence_bytes, is hashed and added to the pre-image string. Next, the function serializes and hashes the txid+vout of the input currently undergoing signature verification, adding this to the pre-image as well.
The script code is formatted by incorporating the public key hash (retrieved from **p2wpkh_script_validation**) into a predefined structure: * *1976a914{publickeyhash}88ac* *. This is then appended to the pre-image. Next, the transaction amount and sequence are converted to little endian and pushed into the pre-image.
For the outputs, an output_bytes variable is used to collect the data for each output, including the little endian amount, the compact size of the scriptpubkey, and the scriptpubkey itself. After all output data is compiled, it undergoes double hashing and is added to the pre-image in hex format.
Finally, the locktime and sighash type, both reversed to little endian and encoded in hex, are appended to complete the segwit pre-image. This complicated construction of the pre-image is then ready to be used in **p2wpkh_script_validation** for signature verification.
##### Pseudo code:
-	Clone the transaction to a new variable tx.
-	Convert the transaction version to littleendian bytes and encode it to hex. Store this in version.
-	Initialize two empty byte vectors input_bytes and sequences_bytes.
-	For each transaction input (vin) in the transaction:
     -	Decode the txid from hex to bytes, reverse the bytes to get the txid in big endian, and append these bytes to input_bytes.
     -	Convert the output index (vout) to little endian bytes and append to input_bytes.
     -	Convert the sequence number to little endian bytes and append to sequences_bytes.
-	Double SHA256 hash the input_bytes and sequences_bytes. Store these in input_hash and sequences_hash.
-	Get the transaction input (vin) at the specified index from vin_index.
-	Decode the txid of this input from hex to bytes, reverse the bytes to get the txid in big endian, and encode this to hex. Store in. txid.
-	Convert the output index (vout) of this input to little endian bytes and encode this to hex. Store in vout.
-	Format txid and vout into a string input.
-	Format the public key hash pubkey_hash into a script code scriptcode.
-	Get the value of the previous output (prevout) of this input, convert it to little endian bytes, and encode this to hex. Store in amount_le.
-	Convert the sequence number of this input to little endian bytes and encode this to hex. Store in sequence.
-	Initialize an empty byte vector output_bytes.
-	For each transaction output (vout) in the transaction:
     -	Convert the output value to little endian bytes and append to output_bytes.
     -	Calculate the compact size of the locking script (scriptpubkey), convert it to bytes, and append to output_bytes.
     -	Decode the locking script (scriptpubkey) from hex to bytes and append to output_bytes.
-	Double SHA256 hash the output_bytes and store this in output_hash.
-	Convert the locktime of the transaction to little endian bytes and encode this to hex. Store in locktime.
-	Convert the sighash type sighash_type to a 32-bit integer, convert this to little endian bytes, and encode to hex. Store in formatted_sighash.
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




