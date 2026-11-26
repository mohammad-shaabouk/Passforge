# 🔐 PassForge

**PassForge** is a Python command-line utility for generating secure passwords, memorable passphrases and numeric PINs, and evaluating password strength. It provides entropy estimates, pattern detection, estimated cracking times, and an optional breach check using the Have I Been Pwned API.

Designed with a simple terminal workflow in mind, including Kali Linux and other Linux distributions.

> [!WARNING]
> PassForge is a password utility—not a guarantee of security. Use unique passwords, store them in a trusted password manager, and enable multi-factor authentication whenever possible.

## ✨ Features

- **Password generation:** Cryptographically secure random passwords using Python's `secrets` module.
- **Passphrase generation:** Memorable multi-word phrases using an embedded word list or a custom list.
- **PIN generation:** Random numeric PINs while rejecting simple repeated-digit and sequential patterns.
- **Password strength analysis:** Strength score, entropy estimates, character-set analysis, common-password checks, pattern detection, and recommendations.
- **Estimated cracking times:** Illustrative estimates across online, slow-hash, and fast-hash scenarios.
- **Breach lookup (optional):** Check against Have I Been Pwned's Pwned Passwords service using the k-anonymity range method.
- **Batch analysis:** Analyze passwords from a text file.
- **Convenient output:** Plain output for pipelines, optional saving, and clipboard copying (where supported).
- **Terminal interface:** Rich tables and colored reports powered by Typer and Rich.

## 📋 Table of Contents

- [Requirements](#-requirements)
- [Installation](#-installation)
- [Getting Started](#-getting-started)
- [Commands](#-commands)
  - [generate](#generate---generate-passwords)
  - [passphrase](#passphrase---generate-passphrases)
  - [pin](#pin---generate-pins)
  - [check](#check---analyze-a-password)
  - [batch](#batch---analyze-a-file)
- [Breach Check and Privacy](#-breach-check-and-privacy)
- [Output and Exit Codes](#-output-and-exit-codes)
- [Security Notes](#-security-notes)
- [Troubleshooting](#-troubleshooting)
- [Disclaimer](#-disclaimer)

## 📦 Requirements

- Python 3
- `typer`
- `rich`

The remaining modules used by PassForge (including `secrets`, `string`, `re`, `hashlib`, `math`, and `urllib`) are part of Python's standard library.

## 🚀 Installation

### Kali Linux / Debian-based systems

Install the dependencies using the system package manager:

```bash
sudo apt update
sudo apt install -y python3-typer python3-rich
```

Download or clone this repository, then enter its directory. For example:

```bash
git clone https://github.com/USERNAME/REPOSITORY.git
cd REPOSITORY
```

Replace the placeholder repository URL above with your actual GitHub repository URL.

Run the script:

```bash
python3 passforge.py --help
```

### Virtual environment (recommended if you prefer isolated dependencies)

```bash
mkdir -p ~/passforge
cd ~/passforge

python3 -m venv .venv
source .venv/bin/activate

pip install typer rich
```

Place `passforge.py` in this directory and run it with:

```bash
python passforge.py --help
```

To use the environment in a new terminal, activate it again:

```bash
cd ~/passforge
source .venv/bin/activate
```

### Optional: clipboard support

The `--copy` option uses available clipboard utilities. On Linux, PassForge attempts to use `xclip`, `xsel`, or `wl-copy`.

Install one if needed:

```bash
sudo apt install -y xclip
```

For Wayland, you can install:

```bash
sudo apt install -y wl-clipboard
```

### Optional: install a command shortcut

You can make the script available as `passforge`:

```bash
sudo cp passforge.py /usr/local/bin/passforge
sudo chmod +x /usr/local/bin/passforge
```

Then use it without explicitly invoking Python:

```bash
passforge --help
passforge generate
```

## 🧭 Getting Started

Show the help menu:

```bash
python3 passforge.py --help
```

Show the installed script version:

```bash
python3 passforge.py --version
```

Generate a password:

```bash
python3 passforge.py generate
```

Generate a passphrase:

```bash
python3 passforge.py passphrase
```

Analyze a password securely (interactive hidden input):

```bash
python3 passforge.py check
```

## 🛠️ Commands

### `generate` — Generate passwords

Generates random passwords with at least one character from each enabled character pool. Remaining characters are selected from the combined enabled character set.

```bash
python3 passforge.py generate
```

Default settings: 20 characters, lowercase letters, uppercase letters, digits, and symbols enabled.

#### Options

| Option | Description | Default |
|---|---|---|
| `-l`, `--length` | Password length (4–4096) | `20` |
| `-n`, `--count` | Number of passwords (1–1000) | `1` |
| `--lower` / `--no-lower` | Enable/disable lowercase letters | Enabled |
| `--upper` / `--no-upper` | Enable/disable uppercase letters | Enabled |
| `--digits` / `--no-digits` | Enable/disable digits | Enabled |
| `--symbols` / `--no-symbols` | Enable/disable symbols | Enabled |
| `--custom-symbols TEXT` | Use a custom symbol set | Built-in symbols |
| `-a`, `--no-ambiguous` | Exclude look-alike characters (`I`, `l`, `1`, `O`, `0`, `o`, etc.) | Disabled |
| `-x`, `--exclude TEXT` | Exclude specified characters | None |
| `--analyze` / `--no-analyze` | Show/hide strength analysis in the table | Enabled |
| `-o`, `--save PATH` | Append generated passwords to a file | Not saved |
| `-c`, `--copy` | Copy the first generated password to clipboard | Disabled |
| `--plain` | Output passwords only (no table) | Disabled |

#### Examples

Generate a 32-character password:

```bash
python3 passforge.py generate --length 32
```

Generate 10 passwords:

```bash
python3 passforge.py generate --count 10
```

Generate without symbols:

```bash
python3 passforge.py generate --length 16 --no-symbols
```

Use only uppercase letters and digits:

```bash
python3 passforge.py generate --no-lower --no-symbols
```

Avoid ambiguous characters:

```bash
python3 passforge.py generate --no-ambiguous
```

Exclude certain characters:

```bash
python3 passforge.py generate --exclude '{}[]'
```

Specify custom symbols:

```bash
python3 passforge.py generate --custom-symbols '!@#'
```

Generate, save, and copy the first result:

```bash
python3 passforge.py generate --count 5 --save ~/passwords.txt --copy
```

Print only passwords (useful for shell pipelines):

```bash
python3 passforge.py generate --plain
```

> If the requested length is shorter than the number of enabled character pools, generation fails. Enable fewer character types or increase the length.

### `passphrase` — Generate passphrases

Generates memorable phrases by selecting words from a word list. By default, it uses the embedded list, capitalizes words, joins them with hyphens, and appends a two-digit number.

```bash
python3 passforge.py passphrase
```

#### Options

| Option | Description | Default |
|---|---|---|
| `-w`, `--words` | Number of words (3–20) | `5` |
| `-s`, `--sep` | Word separator | `-` |
| `--capitalize` / `--no-capitalize` | Capitalize each word | Enabled |
| `--number` / `--no-number` | Append a random two-digit number | Enabled |
| `--wordlist PATH` | Custom word list, one word per line | Embedded list |
| `-n`, `--count` | Number of phrases (1–100) | `1` |
| `-o`, `--save PATH` | Append phrases to a file | Not saved |
| `-c`, `--copy` | Copy first phrase to clipboard | Disabled |
| `--plain` | Output phrases only | Disabled |

#### Examples

Generate a phrase with six words:

```bash
python3 passforge.py passphrase --words 6
```

Use dots as separators and omit the number:

```bash
python3 passforge.py passphrase --sep . --no-number
```

Generate three phrases:

```bash
python3 passforge.py passphrase --count 3
```

Use your own word list:

```bash
python3 passforge.py passphrase --wordlist ~/mywords.txt
```

Custom word lists are filtered to English alphabetic words between 4 and 9 characters. The usable list must contain at least 100 words.

> **Entropy note:** PassForge reports an estimate based on the word-list size and phrase construction, assuming an attacker knows the generation method. The bundled word list is relatively small; using more words or a larger custom word list can increase the phrase's estimated entropy.

### `pin` — Generate numeric PINs

Creates numeric PINs and rejects all-identical digits and detected sequential patterns.

```bash
python3 passforge.py pin
```

#### Options

| Option | Description | Default |
|---|---|---|
| `-l`, `--length` | PIN length (4–32) | `6` |
| `-n`, `--count` | Number of PINs (1–100) | `1` |
| `--plain` | Output PINs without styling | Disabled |

#### Examples

Generate an 8-digit PIN:

```bash
python3 passforge.py pin --length 8
```

Generate five 4-digit PINs:

```bash
python3 passforge.py pin --length 4 --count 5
```

### `check` — Analyze a password

Evaluates a single password and reports its estimated strength, effective and theoretical entropy, character classes, detected weaknesses, recommendations, and estimated cracking times.

For privacy, prefer the interactive prompt, which hides the password while typing:

```bash
python3 passforge.py check
```

You can also provide the password as an argument (not recommended for real passwords):

```bash
python3 passforge.py check 'ExamplePassword123!'
```

#### Options

| Option | Description |
|---|---|
| `-b`, `--breach` | Check the Pwned Passwords database (requires internet) |
| `--show` | Show the password in clear text in the report |
| `--common-file PATH` | Add a file of common passwords to the built-in list |
| `--min-score N` | Exit with code `1` if score is below N (0–100) |

#### Examples

Check strength and optionally query known breaches:

```bash
python3 passforge.py check --breach
```

Show the password in the report:

```bash
python3 passforge.py check --show
```

Use an additional common-password list:

```bash
python3 passforge.py check --common-file ~/common-passwords.txt
```

Set a minimum acceptable score:

```bash
python3 passforge.py check --min-score 70
```

#### What the analysis considers

PassForge checks for patterns and risk factors including:

- Known common passwords.
- Simple leetspeak substitutions of common passwords.
- Repeated characters and repeated blocks.
- Alphabetic, numeric, and keyboard sequences.
- Years and date-like patterns.
- Common password composition patterns (such as a capitalized word followed by digits and a symbol).

The report includes recommendations based on the findings and password composition.

#### Strength labels

The tool uses the following entropy bands:

| Label | Effective entropy |
|---|---:|
| Very Weak | Less than 28 bits |
| Weak | 28–35 bits |
| Medium | 36–59 bits |
| Strong | 60–79 bits |
| Very Strong | 80 bits or more |

Entropy and cracking-time estimates are approximations and should not be interpreted as guarantees.

### `batch` — Analyze a file

Analyzes a text file containing one password per line and displays a summary table.

Create a file:

```bash
nano passwords.txt
```

Example file contents (illustrative only—do not use these example passwords):

```text
example-password
another-example
third-example
```

Run the analysis:

```bash
python3 passforge.py batch passwords.txt
```

#### Options

| Option | Description |
|---|---|
| `-b`, `--breach` | Check each password against Pwned Passwords (requires internet) |
| `--show` | Display passwords in clear text |
| `--min-score N` | Exit with code `1` if any password's score is below N (0–100) |

#### Examples

Run batch analysis with breach checking:

```bash
python3 passforge.py batch passwords.txt --breach
```

Require a minimum score of 60:

```bash
python3 passforge.py batch passwords.txt --min-score 60
```

> [!CAUTION]
> Batch files may contain sensitive credentials. Avoid using real passwords in files unless necessary. Protect the file, avoid displaying passwords, and securely remove it when appropriate. The `--show` option displays passwords in clear text.

## 🌐 Breach Check and Privacy

When `--breach` is enabled, PassForge checks passwords through the Have I Been Pwned Pwned Passwords API.

The check uses the **k-anonymity range method**:

1. PassForge calculates the password's SHA-1 hash locally.
2. It sends only the first five hexadecimal characters of that hash to the service.
3. The service returns matching hash suffixes for that prefix.
4. PassForge compares the remaining suffix locally and retrieves the occurrence count.

The plaintext password is not sent to the service. This feature requires internet connectivity and may fail if the service is unreachable.

## 📄 Output, Saving, Clipboard, and Exit Codes

### Saving results

The `--save` option appends results to a file. PassForge attempts to create the file with permissions `600` (owner read/write only) and applies those permissions afterward.

Example:

```bash
python3 passforge.py generate --count 3 --save ~/generated-passwords.txt
```

Treat saved password files as sensitive. File permissions do not replace secure storage in a password manager.

### Clipboard

The `--copy` option copies the first generated password or passphrase to the clipboard if a supported clipboard utility is available.

### Plain output

Use `--plain` to avoid decorative output when scripting or piping results:

```bash
python3 passforge.py generate --plain
python3 passforge.py passphrase --plain
python3 passforge.py pin --plain
```

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | Successful execution; no configured score threshold was violated |
| `1` | Password is below `--min-score`, or `check` reports a breached password |
| `2` | Input or usage error (for example, empty input, invalid length, or an empty batch file) |

The `check` command also exits with code `1` if a password is found in known breaches, even when no minimum score is specified.

Example in a shell script:

```bash
python3 passforge.py check --min-score 70
if [ $? -eq 0 ]; then
    echo "Password meets the configured threshold."
else
    echo "Password did not pass."
fi
```

## 🔒 Security Notes

- Use a different password for every account.
- Prefer passwords of 16 characters or more for important accounts, or use long randomly generated passphrases.
- Store credentials in a reputable password manager.
- Avoid passing real passwords as command-line arguments; they may be recorded in shell history or exposed through process information.
- Use the hidden interactive prompt for `check`.
- Avoid `--show` unless you specifically need to reveal the password.
- Protect files used with `batch` and files created with `--save`.
- Enable multi-factor authentication (MFA/2FA) whenever available.
- The strength score and cracking-time estimates are heuristics, not proof that a password is safe.
- A password not found in the breach database is not necessarily safe or uncompromised.

## 🧰 Troubleshooting

| Problem | Possible solution |
|---|---|
| `ModuleNotFoundError: No module named 'typer'` | Install `python3-typer` using APT or install Typer inside a virtual environment with `pip`. |
| `ModuleNotFoundError: No module named 'rich'` | Install `python3-rich` using APT or `pip` inside a virtual environment. |
| `externally-managed-environment` when using `pip` | Use a virtual environment or install the system packages with APT. |
| `Permission denied` when running the script directly | Run with `python3 passforge.py`, or make it executable using `chmod +x passforge.py`. |
| Clipboard copy fails | Install `xclip`, `xsel`, or `wl-clipboard`, depending on your desktop environment. |
| Breach check fails | Check internet connectivity or try again later. |
| Password length is too short for selected character sets | Increase the length or disable some character pools. |
| Virtual environment is not active in a new terminal | Re-activate it using `source .venv/bin/activate`. |
| Batch file is empty or invalid | Ensure the file exists, is readable, and contains at least one non-empty line. |

## ⚖️ Disclaimer

PassForge is provided for educational and personal security use. The author makes no guarantees about the accuracy of strength scores, entropy estimates, cracking-time calculations, or breach-check results. Use the tool responsibly and review its output critically.

---

## 💡 Quick Reference

```bash
# Install dependencies on Kali/Debian
sudo apt update && sudo apt install -y python3-typer python3-rich

# Generate a 24-character password
python3 passforge.py generate --length 24

# Generate a memorable passphrase
python3 passforge.py passphrase --words 6

# Generate a PIN
python3 passforge.py pin --length 8

# Analyze a password securely
python3 passforge.py check

# Check against known breaches
python3 passforge.py check --breach

# Analyze a password file
python3 passforge.py batch passwords.txt

# View command help
python3 passforge.py --help
python3 passforge.py generate --help
python3 passforge.py passphrase --help
python3 passforge.py pin --help
python3 passforge.py check --help
python3 passforge.py batch --help
```