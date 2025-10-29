# iamgen

A CLI tool to generate AWS IAM user credentials and securely share them via PrivateBin.

## Features

- 🔐 Creates AWS IAM users with console and/or programmatic access
- 🔑 Generates strong passwords and access keys
- 🔒 Encrypts credentials using PrivateBin (AES-256-GCM)
- 🔗 Provides one-time shareable links
- ⚙️ Configurable expiration times and options
- 🔄 Automatic rollback on failures

## Installation

### Using Go Install

```bash
go install github.com/kristiand00/iamgen@latest
```

### Using Homebrew (after release)

```bash
brew install kristiand00/tap/iamgen
```

### Download Binary

Download the latest release from the [releases page](https://github.com/kristiand00/iamgen/releases).

## Prerequisites

- AWS credentials with IAM permissions
- PrivateBin server (1.6+ or 1.7.x)
- Go 1.24+ (for building from source)

## Configuration

Create a `config.yaml` file:

```yaml
privatebin_url: https://privatebin.net
expire: 1week
burn: 0
opendiscussion: 0
format: plaintext
custom_message: "Here are the new AWS credentials: "
username_prefix: ""
user_path: ""
password_length: 20
password_reset_required: false
create_console_login: true
create_access_key: true
region: "us-east-1"
compression: none
```

### Configuration Options

| Option | Description | Default | Valid Values |
|--------|-------------|---------|--------------|
| `privatebin_url` | Your PrivateBin server URL | `https://privatebin.net` | Any valid URL |
| `expire` | Link expiration time | `1day` | `5min`, `10min`, `1hour`, `1day`, `1week`, `1month`, `1year`, `never` |
| `burn` | Burn after reading (0=no, 1=yes) | `1` | `0`, `1` |
| `opendiscussion` | Enable comments (0=no, 1=yes) | `0` | `0`, `1` |
| `format` | Paste format | `plaintext` | `plaintext`, `markdown`, `syntaxhighlighting` |
| `custom_message` | Custom message in output | See default | Any string |
| `username_prefix` | Auto-generate username prefix | `""` | Any string |
| `user_path` | IAM user path | `""` | IAM path format |
| `password_length` | Generated password length | `20` | Minimum `12` |
| `password_reset_required` | Force password reset on first login | `false` | `true`, `false` |
| `create_console_login` | Create console password | `true` | `true`, `false` |
| `create_access_key` | Create access key | `true` | `true`, `false` |
| `region` | AWS region | `""` (uses default) | AWS region codes |
| `compression` | Compression algorithm | `none` | `none`, `zlib` |

You can also set the config path via environment variable:
```bash
export IAMGEN_CONFIG=/path/to/config.yaml
```

## Usage

### Basic Usage

Create a user with console access:
```bash
iamgen -u john.doe -c
```

Create a user with programmatic access (access key):
```bash
iamgen -u john.doe -p
```

Create a user with both console and programmatic access:
```bash
iamgen -u john.doe -c -p
```

### Using AWS Credentials from CSV

```bash
iamgen -u john.doe -c -csv /path/to/credentials.csv
```

### Auto-generate Username

Set `username_prefix` in config.yaml, then:
```bash
iamgen -c -p
```

This will generate a username like `myprefix1234567890`.

### Command-Line Flags

```
-u string
    Username to create (required unless username_prefix is set in config)
    
-c  Create console login (password)
    Overrides config.yaml if specified
    
-p  Create programmatic access (access key)
    Overrides config.yaml if specified
    
-csv string
    Path to AWS credentials CSV file
    Overrides environment/profile credentials
    
-path string
    IAM user path
    Overrides config.yaml user_path
```

## Examples

### Example 1: Create User with Console Access

```bash
iamgen -u alice -c
```

Output:
```
Creating user: alice
Sending to PrivateBin...
Creating login profile (console password)...
---
Subject: New AWS Credentials for alice

Hello,
Here are the new AWS credentials: 
This link will expire in 1 week and can only be viewed once.
https://privatebin.net/?abc123#secretkey

---
```

### Example 2: Using Different AWS Credentials

```bash
iamgen -u bob -c -p -csv ./admin-credentials.csv
```

### Example 3: Create User in Specific Path

```bash
iamgen -u charlie -c -p -path /contractors/
```

## How It Works

1. **Creates IAM User**: Creates a new AWS IAM user (or uses existing)
2. **Generates Credentials**: Creates console password and/or access keys
3. **Encrypts Data**: Encrypts credentials using AES-256-GCM
4. **Uploads to PrivateBin**: Sends encrypted data to PrivateBin server
5. **Returns Link**: Provides a secure one-time link with decryption key
6. **Creates Login Profile**: Sets up AWS console access (if requested)

The decryption key is included in the URL fragment (after `#`), which is never sent to the server.

## Security Features

- **End-to-end encryption**: Data is encrypted client-side before upload
- **One-time links**: Links are destroyed after first view (if burn=1)
- **Automatic rollback**: Failed operations clean up created resources
- **Strong passwords**: Generates passwords with minimum 12 characters including symbols
- **No server knowledge**: PrivateBin server never sees unencrypted data

## Building from Source

```bash
git clone https://github.com/kristiand00/iamgen.git
cd iamgen
go build -o iamgen main.go
```

## Development

### Running Tests

```bash
go test ./...
```

### Local Build

```bash
go build -o iamgen main.go
./iamgen -u testuser -c
```

## Troubleshooting

### "Failed to load AWS config"

Ensure you have AWS credentials configured:
```bash
aws configure
```

Or use the `-csv` flag to provide credentials directly.

### "Invalid PrivateBin URL"

Check that your `privatebin_url` in config.yaml is correct and accessible.

### "Failed to create user"

Ensure your AWS credentials have IAM user creation permissions:
- `iam:CreateUser`
- `iam:CreateLoginProfile`
- `iam:CreateAccessKey`

### PrivateBin Compatibility

This tool supports PrivateBin versions 1.6+ and 1.7.x. It uses:
- 600,000 PBKDF2 iterations
- AES-256-GCM encryption
- Standard Base64 encoding

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- [PrivateBin](https://privatebin.info/) - The secure pastebin
- [gearnode/privatebin](https://github.com/gearnode/privatebin) - Go PrivateBin client reference
- AWS SDK for Go v2

## Author

Kristian Dolecki ([@kristiand00](https://github.com/kristiand00))

## Support

For issues and questions, please use the [GitHub issue tracker](https://github.com/kristiand00/iamgen/issues).

