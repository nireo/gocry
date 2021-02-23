# gocry

gocry is a simple ransomware implementation using golang. It hasn't been tested on Windows, but it does work on Linux.

## Disclamer

This project is purely academic, use at your own risk. I do not encourage in any way the use of this software illegally or to attack targets without their previous authorization.

**gocry** is an academic ransomware made for learning about cryptograpchy and security.

## Running with server

Firstly you need to create an environment variable file `.env` in the `server` folder. The file should contain:

```
# .env
db_name=name of the database
db_port=port of the database
db_user=user that owns the postgres database
db_host=host where the user is in.
```

Then you can run the server by running:

```
go run server.go
```

Then running the actual ransomware that encrypts everything is ran by:

```
go run main.go
```

The values of the ransomware can be configured in the `main.go` file. The ransom message, root directory to encrypt and the address of the server.

## Running without server

**NOTE** This is still feature is still work in progress. In the `server` folder there are some simple programs to make the ransomware manageable. Currently though the client will not work if a server connection cannot be established.

## How it works.

1. The program checks if any files are already encrypted, by checking for the .gocry extension. If files are already encrypted, check the `<root_dir>/key.txt` file for a valid decryption key. If not, continue the encryption process.
2. The program creates a random 32-bit array using the `crypto` package's `rand.Reader`. Then the key from that is placed into a `memguard` key enclave.
3. The key is passed into the `crypt.EncryptRoot` function which finds all the files in a given root directory, and encrypts them, using AES-GCM 256-bit encryption.
4. Once encryption is done, the victim information is sent to the server, and establishing a unique id, with which the server can identify the client.

## Todo:

These are issues or ideas I think should be added.

- Fix filepaths such that they work for both windows and linux.
- Make it fully optional to use a server.

## Dependencies

- [memguard](https://github.com/awnumar/memguard)
- [gorm](https://gorm.io/)

## Contributing

The project is still in somewhat active development and anyone can open issues and create pull requests relating to the project. All contributions are appreciated!
