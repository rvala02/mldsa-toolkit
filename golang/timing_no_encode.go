package main

import (
	"bufio"
	"crypto/internal/fips140/mldsa"
	"flag"
	"fmt"
	"io"
	"os"
)

func helpMsg() {
	fmt.Println(`
timing.go -i file -o file -k file -m scheme [-s file]

-i file      File with the messages to sign (32 bytes each)
-o file      File to write the timing data to
-k file      Binary file containing a single 32-byte seed
-m scheme    ML-DSA parameter set: 44, 65, or 87
-s file      File to write concatenated signatures to (optional)
-h | --help  this message
`)
}

func main() {
	var (
		inFile  string
		outFile string
		keyFile string
		sigFile string
		scheme  string
		help    bool
	)

	flag.StringVar(&inFile, "i", "", "File with the messages to sign")
	flag.StringVar(&outFile, "o", "", "File to write the timing data to")
	flag.StringVar(&keyFile, "k", "", "Binary file with a single 32-byte seed")
	flag.StringVar(&sigFile, "s", "", "File to write concatenated signatures to (optional)")
	flag.StringVar(&scheme, "m", "44", "ML-DSA parameter set: 44, 65, or 87")
	flag.BoolVar(&help, "h", false, "Show help")
	flag.BoolVar(&help, "help", false, "Show help")

	flag.Parse()

	if help {
		helpMsg()
		os.Exit(0)
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
	if scheme != "44" && scheme != "65" && scheme != "87" {
		fmt.Fprintln(os.Stderr, "ERROR: -m must be 44, 65, or 87")
		os.Exit(1)
	}

	newPrivateKey := mldsa.NewPrivateKey44
	switch scheme {
	case "65":
		newPrivateKey = mldsa.NewPrivateKey65
	case "87":
		newPrivateKey = mldsa.NewPrivateKey87
	}

	seed, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading key file: %v\n", err)
		os.Exit(1)
	}
	if len(seed) != 32 {
		fmt.Fprintf(os.Stderr, "ERROR: key file must be exactly 32 bytes (got %d)\n", len(seed))
		os.Exit(1)
	}
	privKey, err := newPrivateKey(seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing private key: %v\n", err)
		os.Exit(1)
	}

	var sFile *os.File
	if sigFile != "" {
		sFile, err = os.Create(sigFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating signature file: %v\n", err)
			os.Exit(1)
		}
		defer sFile.Close()
	}

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

	msgBuf := make([]byte, 32)

	for {
		_, err := io.ReadFull(iFile, msgBuf)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			fmt.Fprintf(os.Stderr, "Error reading message: %v\n", err)
			break
		}

		sig, diff, err := mldsa.SignDeterministic(privKey, msgBuf, "")

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error signing: %v\n", err)
			continue
		}

		writer.WriteString(fmt.Sprintf("%d\n", diff))

		if sFile != nil {
			sFile.Write(sig)
		}
	}

	fmt.Println("done")
}
