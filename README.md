# project1-scanner

Scanner for [Project1](#)

# Installation

1. Clone this repository
```bash
$ git clone {GH_REPO}
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
```
Usage of main:
  -headers string
    	Specify request headers to send with requests (separate each header with a double semi-colon: "User-Agent: xyz;; Cookies: xyz...;;"
  -service int
    	Specify the service ID you'd like to check for: "0" for Atlassian Jira Service Desk
  -services
    	Print all services with their associated IDs
  -target string
    	Specify your target domain name or Company name: Intigriti
  -timeout float
    	Specify a timeout for each request sent in seconds (default: "7.0"). (default 7)
```

## Examples

```bash
$ ./main -target intigriti -service 0
```

# Services
Get a list of supported services:

```bash
$ ./main -services
1 Service(s) loaded!
| ID | Service                               
|----|---------------------------------------
| 0  | Atlassian Jira Service Desk
...
```

# Contributions
Learn more on how to contribute to the project

# License
Project's License

