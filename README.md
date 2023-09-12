# project1-scanner

Scanner for Project1

# Installation

1. Clone this repository
```bash
git clone {GH_REPO}
```

2. Run the precompiled binary (see [usage](#Usage) for more information)

## From source:
Make sure you have the latest version of Golang installed. To verify your installation, run:

```bash
$ go version
```

Output:

```bash
go version go1.21.1 linux/amd64
```

1. Compile your own binary from source
```bash
$ go build main.go -o main
```

2. Add or move the binary to a folder in your $PATH

# Usage

```bash
$ ./main -target intigriti -service 0
```

# Services
Get a list of supported services:

```bash
$ ./main -services
```
