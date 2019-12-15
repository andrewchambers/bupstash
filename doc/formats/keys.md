# Keys

There are currently two types of key, master keys, and derived send keys. Master keys can be used to encrypt and decrypt
data, while send keys are derived from master keys, and can only encrypt data, and never decrypt data.

Send keys can be used to generate ephemeral session keys addressed tomaster keys public key
and send data encrypted with that ephemeral key. The master key can be used recompute this ephemeral key at decryption time.  
The sender discards the ephemeral keys once encryption has finished to preserve data secrecy if a send key is eventually compromised.

Each master/send key pair also has a unique hash key, created by combining two secret hash key parts,
which are used to create a unique secret hash function that allows content addressed based deduplication, while
preventing attackers from doing hash lookups, and prevents client keys from poisoning each others deduplication space
with deliberately corrupt data. The hash function is also be used at decryption time
as a cryptographically secure integrity check.

Encryption and decryption keys are saved on disk using a simple json encoding, the encoding is as follows:

## MasterKeyV1
```
	{"MasterKeyV1" : {
		
		// A randomly generated key id unique to this key. 
		"id" : [u8; 32],
		
		// A partial hash key.
		//
		// The master hash_key1 xor the sender hash_key2 is used as a per key-pair secret hash function, which
		// prevents content guessing and deduplication space poisoning by malicious clients.
		"hash_key1" : [u8; hydrogen::HASH_KEYBYTES],
		
		// This half of the keypair is used in place of a send key hash_key2 when a master key is used as a send key.
		"hash_key2" : [u8; hydrogen::HASH_KEYBYTES],
		
		// A preshared key known to both both a master key and a derived send key, it used as
		// proof both the master key and send key originated from the same party, and both had access to the same key.
		"data_psk" : [u8; hydrogen::KX_PSKBYTES],
		
		// A public key encrypted data is addressed to, similar to a gpg public key you can send encrypted data addressed to.
		"data_pk" : [u8; hydrogen::KX_PUBLICKEYBYTES],

		// The secret key used to compute backup ephemeral keys created by a send key.
		"data_sk" : [u8; hydrogen::KX_SECRETKEYBYTES],
	   }
	} 
```

## SendKeyV1
```
	{"SendKeyV1" : {
		
		// A randomly generated key id unique to this key. 
		"id" : [u8; 32],

		// The id of the master key this key was derived from. 
		"master_key_id" : [u8; 32],
		
		// The same as the master hash_key1.
		"hash_key1" : [u8; hydrogen::HASH_KEYBYTES],
		
		// A unique client portion of the derived hash key.
		"hash_key2" : [u8; hydrogen::HASH_KEYBYTES],
		
		// The same preshared key as the master key this send key was derived from.
		"data_psk" : [u8; hydrogen::KX_PSKBYTES],
		
		// The public key portion of the master key.
		"master_data_pk" : [u8; hydrogen::KX_PUBLICKEYBYTES],
	   }
	} 
``` 

