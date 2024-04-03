# Misconfig Mapper

A list of with the most common misconfigurations among popular services used by bug bounty targets and online (software) companies!

Curated by @INTIGRITI for the community!

![image](./images/logo.png)

# CLI Tool

_**Misconfig Mapper**_ has a [dedicated open-source CLI tool](https://github.com/intigriti/service-scanner) written in Golang to help you automate the testing of most misconfigurations found on covered services.\
\
It can enumerate dedicated instances of services that your company may use and perform passive & active tests to check for certain misconfigurations at scale!\
\
The tool is based on templates and is versatile. New services can be easily added by adding them to the `services.json` file.

# Features

-   The CLI tool is based on templates defined in the `services.json` file. You can add as many as you want. See [_Templates section_](cli-tool.md#templates) for more information on how to add a template.
-   If you provide a company name, the tool will automatically generate permutations based on the keyword you provided and try to find any matching services.
-   You can optionally choose only to enumerate services and not perform any active tests (see more on [_Usage section_](cli-tool.md#usage)).

# Installation

1. Clone this repository:

```bash
$ git clone https://github.com/intigriti/misconfig-mapper.git
```

2. Run the pre-compiled binary (see [usage](cli-tool.md#usage) for more information).

```bash
$ ./misconfig-mapper -help
```



## From source

If you want to build your own instance from source, ensure you have the latest version of Golang installed. To verify your installation, run:

```bash
$ go version
  go version go1.21.5 linux/amd64
```

1. Next, compile your binary from source:

```bash
$ go build -o misconfig-mapper
```

2. Finally, add or move the binary to a folder in your `$PATH` (optional)

# Usage

**Example 1:** Perform active tests to enumerate all misconfigured third-party services

```basic
$ ./misconfig-mapper -target "yourcompanyname" -service "*"
```

<figure><img src=".gitbook/assets/image%20(2).png" alt=""><figcaption></figcaption></figure>

**Example 2:** Only perform passive tests to enumerate all third-party services

```bash
$ ./misconfig-mapper -target "yourcompanyname" -service "*" -passive-only
```

<figure><img src=".gitbook/assets/image%20(1).png" alt=""><figcaption></figcaption></figure>

**Example 3:** Only test for one specific service (by ID or name)

```bash
$ ./misconfig-mapper -target "yourcompanyname" -service "1"
```

```bash
$ ./misconfig-mapper -target "yourcompanyname" -service "drupal"
```

<figure><img src=".gitbook/assets/image%20(4).png" alt=""><figcaption></figcaption></figure>

**Example 4:** Print out all loaded services

```bash
$ ./misconfig-mapper -services
```

<figure><img src=".gitbook/assets/image%20(3).png" alt=""><figcaption></figcaption></figure>

Additionally, you can pass request headers using the `-headers` flag to comply with any request requirements (separate each header using a **double semi-colon**):

```
-headers "User-Agent: xyz;; Cookie: session=eyJ...;;"
```

```
Usage of ./misconfig-mapper:
  -headers string
    	Specify request headers to send with requests (separate each header with a double semi-colon: "User-Agent: xyz;; Cookie: xyz...;;"
  -passive-only
    	Only check for existing instances (don't check for misconfigurations). Default: "false"
  -permutations
    	Enable permutations and look for several other keywords of your target. Default: "true" (default true)
  -service string
    	Specify the service ID you want to check for: "0" for Atlassian Jira Open Signups. Wildcards are also accepted to check for all services. (default "0")
  -services
    	Print all services with their associated IDs
  -target string
    	Specify your target domain name or company/organization name: "intigriti.com" or "intigriti"
  -timeout float
    	Specify a timeout for each request sent in seconds (default: "7.0"). (default 7)
```

# Templates

You can easily define more templates to scan for. Templates are in a structured JSON object and read from `services.json`\
\
To define more services, edit the services.json file and separate each misconfiguration in your services.json file.

```json
{
	"id":			0,
	"baseURL":		"{BASE_URL}",
	"path":			"{PATH}",
	"service":		"{SERVICE_NAME}",
	"description":		"{DESCRIPTION}",
	"reproductionSteps":	[
		"{STEP_1}",
		"{STEP_2}",
		...
	],
	"passive":		[
		"{KEYWORD_1}",
		"{KEYWORD_2}",
		...
	],
	"active":		[
		"{KEYWORD_1}",
		"{KEYWORD_2}",
		...
	],
	"references":		[
		"{REFERENCE_1}",
		"{REFERENCE_2}",
		...
	]
}
```

### ID

**Type:** number\
\
The `id` field is used to identify the service when the `-service` flag is provided. It should be a numerical value that follows the sequence of previous IDs.

**BaseURL**

**Type:** string

The `baseURL` field is used to locate the third-party service, if it exists.

{% hint style="info" %}
The CLI tool can auto-detect and replace the **"{TARGET}"** template variable with the target provided using the target flag.\
\
Example: https://{TARGET}.example.com will allow the tool to look for:

-   https://yourcompanyname.example.com
-   https://yourcompanyname-app.example.com
-   https://yourcompanyname-eu.example.com
-   ...
    {% endhint %}

### **Path**

**Type:** string

The `path` field checks whether the service is vulnerable by observing the response.

{% hint style="info" %}
The CLI tool can auto-detect and replace the **"{TARGET}"** template variable with the target provided using the target flag.\
\
Example: /app/{TARGET} will allow the tool to look for:

-   https://example.com/app/yourcompanyname
-   https://example.com/app/yourcompanyname-app
-   https://example.com/app/yourcompanyname-eu
-   ...
    {% endhint %}

### **Service**

**Type:** string

The `service` field is used to display the service name in the CLI output results to visually confirm which service is currently being scanned.

### **Description**

**Type:** string

The `description` field displays the service description in the CLI output once a service has been enumerated or identified and confirmed vulnerable.

### **Reproduction Steps**

**Type:** string array

The `reproductionSteps` field reports back on how to reproduce the found misconfiguration. These steps are derived from this documentation.

{% hint style="info" %}
Each step should be in a separate array entry. You can specify as many steps as you'd like to.
{% endhint %}

### **Passive**

**Type:** string array

The `passive` field supports enumeration & validation of a third-party service for your target. We recommend defining strict keywords to minimize the chances of false positive results.

### **Active**

**Type:** string array

The `active` field is used to validate the existence of a misconfigured third-party service for your target. Make sure to define strict keywords to minimize the chances of false positive results.

### **References**

**Type:** string array

The' references' field documents enumerated and misconfigured services. These references are derived from this documentation.

{% hint style="info" %}
Each reference should be in a separate array entry. You can specify as many references as you'd like to.
{% endhint %}

# Contributions

Learn more on how to contribute to the project.

# License

This project is licensed and available under the {LICENSE} license.
