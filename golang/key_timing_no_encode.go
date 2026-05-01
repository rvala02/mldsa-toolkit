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
key_timing_no_encode.go -i file -o file -t file -k file -n num [-m scheme]

-i file      File with concatenated messages to sign
-o file      File where to write raw signatures (concatenated)
-t file      File where to write timing data
-k file      File with concatenated 32-byte seeds.
-n num       Length of each message in bytes
-m scheme    ML-DSA parameter set: 44, 65, or 87 (default: 44)
-h | --help  This message
`)
}

func main() {
	var (
		inFile   string
		sigFile  string
		timeFile string
		keyFile  string
		msgLen   int
		scheme   string
		help     bool
	)

	flag.StringVar(&inFile, "i", "", "File with the messages to sign")
	flag.StringVar(&sigFile, "o", "", "Signatures output file")
	flag.StringVar(&timeFile, "t", "", "Timing output file")
	flag.StringVar(&keyFile, "k", "", "Concatenated 32-byte seeds")
	flag.IntVar(&msgLen, "n", 0, "Message length in bytes")
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
	if sigFile == "" {
		fmt.Fprintln(os.Stderr, "ERROR: no signatures file specified (-o)")
		os.Exit(1)
	}
	if timeFile == "" {
		fmt.Fprintln(os.Stderr, "ERROR: no timing output file specified (-t)")
		os.Exit(1)
	}
	if keyFile == "" {
		fmt.Fprintln(os.Stderr, "ERROR: no key file specified (-k)")
		os.Exit(1)
	}
	if msgLen <= 0 {
		fmt.Fprintln(os.Stderr, "ERROR: message length must be positive (-n)")
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

	sFile, err := os.Create(sigFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating signature file: %v\n", err)
		os.Exit(1)
	}
	defer sFile.Close()

	tFile, err := os.Create(timeFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer tFile.Close()

	writer := bufio.NewWriter(tFile)
	defer writer.Flush()

	writer.WriteString("raw times\n")

	seedBuf := make([]byte, 32)
	msgBuf := make([]byte, msgLen)

	for {
		_, err := io.ReadFull(kFile, seedBuf)
		if err == io.EOF {
			break
		}
		if err != nil {
			if err == io.ErrUnexpectedEOF {
				fmt.Fprintln(os.Stderr, "ERROR: truncated seed at end of key file")
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Error reading key file: %v\n", err)
			os.Exit(1)
		}

		_, err = io.ReadFull(iFile, msgBuf)
		if err == io.EOF {
			fmt.Fprintln(os.Stderr, "ERROR: more seeds than messages")
			os.Exit(1)
		}
		if err != nil {
			if err == io.ErrUnexpectedEOF {
				fmt.Fprintln(os.Stderr, "ERROR: truncated message")
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Error reading message: %v\n", err)
			break
		}

		privKey, err := newPrivateKey(seedBuf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing private key: %v\n", err)
			continue
		}

		sig, diff, err := mldsa.SignDeterministic(privKey, msgBuf, "")

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error signing: %v\n", err)
			continue
		}

		if _, err := sFile.Write(sig); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing signature: %v\n", err)
			continue
		}
		writer.WriteString(fmt.Sprintf("%d\n", diff))
	}

	fmt.Println("done")
}
