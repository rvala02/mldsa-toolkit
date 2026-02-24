package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
	"unsafe"
)

// We need to import unsafe to use go:linkname, effectively telling the compiler
// we know what we are doing.
import _ "unsafe"

// --- Linkname Definitions ---

// We treat the private key as an opaque pointer (unsafe.Pointer) because
// we cannot import the actual mldsa.PrivateKey struct definition.

//go:linkname newPrivateKey44 crypto/internal/fips140/mldsa.NewPrivateKey44
func newPrivateKey44(b []byte) (unsafe.Pointer, error)

//go:linkname sign crypto/internal/fips140/mldsa.Sign
func sign(priv unsafe.Pointer, msg []byte, context []byte) ([]byte, error)

// ----------------------------

func helpMsg() {
	fmt.Println(`
timing.go -i file -o file -k file -n size

-i file      File with the messages to sign (32 byte long)
-o file      File to write the timing data to
-k file      The private keys to use for signing
-n size      Size of individual keys (2560 for ML-DSA-44)
-h | --help  this message
`)
}

func main() {
	var (
		inFile   string
		outFile  string
		keyFile  string
		readSize int
		help     bool
	)

	flag.StringVar(&inFile, "i", "", "File with the messages to sign")
	flag.StringVar(&outFile, "o", "", "File to write the timing data to")
	flag.StringVar(&keyFile, "k", "", "The private keys to use for signing")
	flag.IntVar(&readSize, "n", 0, "Size of individual keys")
	flag.BoolVar(&help, "h", false, "Show help")
	flag.BoolVar(&help, "help", false, "Show help")

	flag.Parse()

	if help || (inFile == "" && outFile == "" && keyFile == "" && readSize == 0) {
		helpMsg()
		if help {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if inFile == "" {
		fmt.Fprintln(os.Stderr, "ERROR: no input file specified (-i)")
		os.Exit(1)
	}
	if outFile == "" {
		fmt.Fprintln(os.Stderr, "ERROR: no output file specified (-o)")
		os.Exit(1)
	}
	if keyFile == "" {
		fmt.Fprintln(os.Stderr, "ERROR: no key file specified (-k)")
		os.Exit(1)
	}
	if readSize == 0 {
		fmt.Fprintln(os.Stderr, "ERROR: size of ciphertexts unspecified (-n)")
		os.Exit(1)
	}

	kFile, err := os.Open(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening key file: %v\n", err)
		os.Exit(1)
	}
	defer kFile.Close()

	iFile, err := os.Open(inFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening input file: %v\n", err)
		os.Exit(1)
	}
	defer iFile.Close()

	oFile, err := os.Create(outFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer oFile.Close()

	writer := bufio.NewWriter(oFile)
	defer writer.Flush()

	writer.WriteString("raw times\n")

	keyBuf := make([]byte, readSize)
	msgBuf := make([]byte, 32)

	for {
		// Read private key bytes
		_, err := io.ReadFull(kFile, keyBuf)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading key: %v\n", err)
			break
		}

		// Read message bytes
		_, err = io.ReadFull(iFile, msgBuf)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			fmt.Fprintf(os.Stderr, "Error reading message: %v\n", err)
			break
		}

		// Linkname Call: Parse the private key
		// This calls crypto/internal/fips140/mldsa.NewPrivateKey44
		privKeyPtr, err := newPrivateKey44(keyBuf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing private key: %v\n", err)
			continue
		}

		start := time.Now()

		// Linkname Call: Sign the message
		// This calls crypto/internal/fips140/mldsa.Sign
		// We pass the unsafe.Pointer we got from newPrivateKey44 directly.
		_, err = sign(privKeyPtr, msgBuf, "")

		diff := time.Since(start).Nanoseconds()

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error signing: %v\n", err)
			continue
		}

		writer.WriteString(fmt.Sprintf("%d\n", diff))
	}

	fmt.Println("done")
}
