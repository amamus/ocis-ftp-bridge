// Command hash-password generates an Argon2id password hash in PHC format
// suitable for use in ocis-ftp-bridge configuration files.
//
// Usage:
//
//	hash-password <password>
//	hash-password -m 65536 -t 3 -p 4 <password>
//
// The generated hash can be placed in the password_hash field of an account
// in the configuration file. The plaintext password is read from the argument
// and never logged.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"math"
	"os"

	"golang.org/x/crypto/argon2"
)

func main() {
	memory := flag.Uint("m", 65536, "Argon2id memory parameter in KiB")
	time := flag.Uint("t", 3, "Argon2id time (iterations) parameter")
	threads := flag.Uint("p", 4, "Argon2id parallelism (threads) parameter")
	keyLen := flag.Uint("k", 32, "Derived key length in bytes")
	saltLen := flag.Uint("s", 16, "Salt length in bytes")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <password>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	password := flag.Arg(0)
	if password == "" {
		fmt.Fprintln(os.Stderr, "Error: password must not be empty")
		os.Exit(1)
	}

	// Validate parameters before conversion to uint32/uint8: out-of-range
	// values would panic inside argon2 or silently truncate.
	if *time == 0 || *time > math.MaxUint32 {
		fmt.Fprintf(os.Stderr, "Error: invalid -t value %d: must be between 1 and %d\n", *time, uint64(math.MaxUint32))
		os.Exit(1)
	}
	if *memory == 0 || *memory > math.MaxUint32 {
		fmt.Fprintf(os.Stderr, "Error: invalid -m value %d: must be between 1 and %d\n", *memory, uint64(math.MaxUint32))
		os.Exit(1)
	}
	if *threads == 0 || *threads > 255 {
		fmt.Fprintf(os.Stderr, "Error: invalid -p value %d: must be between 1 and 255\n", *threads)
		os.Exit(1)
	}
	if *keyLen == 0 || *keyLen > math.MaxUint32 {
		fmt.Fprintf(os.Stderr, "Error: invalid -k value %d: must be between 1 and %d\n", *keyLen, uint64(math.MaxUint32))
		os.Exit(1)
	}

	salt := make([]byte, *saltLen)
	if _, err := rand.Read(salt); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to generate salt: %v\n", err)
		os.Exit(1)
	}

	// #nosec G115 -- all parameters are validated to fit uint32/uint8 above
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		uint32(*time),
		uint32(*memory),
		uint8(*threads),
		uint32(*keyLen),
	)

	// PHC string format: $argon2id$v=19$m=<memory>,t=<time>,p=<threads>$<salt>$<hash>
	encoded := fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		*memory, *time, *threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	fmt.Println(encoded)
}
