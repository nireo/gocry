# gocry

gocry is a simple ransomware implementation using golang. It hasn't been tested on Windows, but it does work on Linux.

## Disclamer

This project is purely for educational purposes. I'm not responsible for what you do with the code provided here.

gocry is an academic ransomware made for learning about cryptograpchy and security.

## Running

First of all you need to start the server which needs a `.env` file.

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

Note that the ransomware only decrypts all the files in a given path, for example: `./test`. This can be quite easily changed in the `ransomware.go` file's main function.

## Todo:

These are issues or ideas I think should be added.

- Fix filepaths such that they work for both windows and linux.
- Store the encryption key in a way, such that it can't found from memory.
- Make a better interface compared to a simple command-line loop
- Make the key decryption need some sort of verification

## Dependencies

- [memguard](https://github.com/awnumar/memguard)
- [gorm](https://gorm.io/)

## Contributing

The project is still in somewhat active development and anyone can open issues and create pull requests relating to the project. All contributions are appreciated!
