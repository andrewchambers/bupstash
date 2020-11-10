# Password Protected Keys

Bupstash allows users to fetch the key to via arbitrary commands via the environment variable
BUPSTASH_KEY_COMMAND, here we will configure bupstash to invoke gpg on a password protected a key file.

First create a key:

```
$ bupstash new-key -o demo.key
```

Next we password protect the key using gpg:

```
$ gpg --symmetric demo.key
```

gpg will ask you for a password using your configured pin entry program and then create demo.key.gpg.

Verify you can decrypt the key:

```
$ gpg --decrypt demo.key.gpg
...
-----BEGIN BUPSTASH KEY-----
...
-----END BUPSTASH KEY-----
```

Now we can remove the unencrypted key:

```
$ shred demo.key
```

Finally, we can tell bupstash to use this encrypted key, to do this we setup the environment variable BUPSTASH_KEY_COMMAND:

```
$ export BUPSTASH_KEY_COMMAND="gpg -q --decrypt $(pwd)/demo.key.gpg"
```

Now whenever bupstash requires a key, it will ask gpg for it, and gpg will ask for the password.


```
$ bupstash list
                                                                                                                                                         
┌──────────────────────────────────────────────────────┐                                                 
│ Enter passphrase                                     │                                                 
│                                                      │                                                 
│                                                      │                                                 
│ Passphrase: ________________________________________ │                                                 
│                                                      │                                                 
│       <OK>                              <Cancel>     │                                                 
└──────────────────────────────────────────────────────┘

```

If you have gpg agent configured, the password does not need to be re-entered until gpg-agent expires the password
entry.

Remember that BUPSTASH_KEY_COMMAND can be set to run any command of your choosing, giving great flexibility when it comes to protecting sensitive bupstash keys.

Finally, don't forget to check out our other guides and manuals to learn about 'put keys', that do not have the ability to decrypt data after it is sent. 'put keys' allow us to avoid putting our sensitive decryption keys
on devices making backups.