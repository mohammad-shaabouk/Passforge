#!/usr/bin/env python3
"""
PassForge - Password Generator & Strength Checker
-------------------------------------------------
Libraries: secrets, string, re (+ Typer / Rich for a beautiful CLI)

Commands:
    generate    Generate strong random passwords (cryptographically secure)
    passphrase  Generate memorable passphrases (diceware style)
    pin         Generate numeric PINs
    check       Analyse the strength of a password (entropy, patterns, crack time)
    batch       Analyse many passwords from a file
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import secrets
import shutil
import string
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Dict, List, Optional, Set

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

__version__ = "1.0.0"

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    name="passforge",
    help="[bold cyan]PassForge[/] - Strong password generator & strength checker.",
    rich_markup_mode="rich",
    no_args_is_help=True,
    add_completion=False,
)

# --------------------------------------------------------------------------- #
#  Constants
# --------------------------------------------------------------------------- #
DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/~"
AMBIGUOUS = "Il1O0o|`'\""

COMMON_PASSWORDS: Set[str] = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
    "monkey", "letmein", "696969", "shadow", "master", "666666", "qwertyuiop",
    "123321", "mustang", "1234567890", "michael", "654321", "superman",
    "1qaz2wsx", "7777777", "121212", "000000", "qazwsx", "123qwe", "killer",
    "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
    "soccer", "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou",
    "2000", "charlie", "robert", "thomas", "hockey", "ranger", "daniel",
    "starwars", "klaster", "112233", "george", "computer", "michelle",
    "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111", "131313",
    "freedom", "777777", "pass", "maggie", "159753", "aaaaaa", "ginger",
    "princess", "joshua", "cheese", "amanda", "summer", "love", "ashley",
    "nicole", "chelsea", "biteme", "matthew", "access", "yankees", "987654321",
    "dallas", "austin", "thunder", "taylor", "matrix", "admin", "admin123",
    "welcome", "login", "passw0rd", "password1", "password123", "p@ssw0rd",
    "root", "toor", "kali", "changeme", "default", "guest", "test", "test123",
    "qwerty123", "iloveu", "secret", "letmein123", "monkey123", "azerty",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
                 "abcdefghijklmnopqrstuvwxyz"]
_SEQ_VARIANTS = KEYBOARD_ROWS + [r[::-1] for r in KEYBOARD_ROWS]

LEET_MAP = str.maketrans({"@": "a", "4": "a", "$": "s", "5": "s", "3": "e",
                          "0": "o", "1": "i", "!": "i", "7": "t", "8": "b"})

EMBEDDED_WORDS = """
able acid acorn actor adapt agent alarm album alpha amber anchor angle apple
arena armor arrow atlas attic audio autumn badge baker balance bamboo banner
barrel basket beach beacon bench berry bicycle bishop blanket blossom border
bottle branch bridge bronze bubble bucket cabin cactus camel candle canyon
carpet castle cattle cedar cellar chair cherry circle clever cliff clock cloud
clover coast cobalt comet copper coral cotton crater crystal curtain dagger
daisy delta desert diamond dinner dolphin donkey dragon drift eagle earth
ember engine falcon feather fiddle forest fossil fountain galaxy garden garlic
ginger glacier goblet granite guitar hammer harbor harvest hazel helmet heron
hollow honey horizon island ivory jacket jaguar jungle kettle kitten ladder
lagoon lantern lemon lizard lotus magnet mango maple marble meadow mirror
monkey mountain nectar needle nickel noble oasis ocean olive orchid otter
paddle palace panda parrot pebble pepper pillow planet plume pocket puzzle
quartz rabbit raven river rocket saddle salmon sapphire shadow silver spider
spring summit tablet temple thunder timber tomato tunnel turtle valley velvet
violet walnut whisper window winter wizard yellow zebra
""".split()

# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #
def build_pools(use_lower: bool, use_upper: bool, use_digits: bool,
                symbols: Optional[str], exclude: str,
                no_ambiguous: bool) -> List[str]:
    """Return the list of enabled character pools after exclusions."""
    banned = set(exclude)
    if no_ambiguous:
        banned |= set(AMBIGUOUS)

    raw = []
    if use_lower:
        raw.append(string.ascii_lowercase)
    if use_upper:
        raw.append(string.ascii_uppercase)
    if use_digits:
        raw.append(string.digits)
    if symbols:
        raw.append(symbols)

    pools = ["".join(c for c in dict.fromkeys(p) if c not in banned) for p in raw]
    return [p for p in pools if p]


def generate_password(length: int, pools: List[str]) -> str:
    """Generate a password guaranteeing at least one char from every pool."""
    if not pools:
        raise ValueError("No characters available - enable at least one set.")
    if length < len(pools):
        raise ValueError(f"Length must be >= {len(pools)} for the selected sets.")

    chars = [secrets.choice(p) for p in pools]
    alphabet = "".join(dict.fromkeys("".join(pools)))
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def human_time(log10_seconds: float) -> str:
    """Convert log10(seconds) into a readable duration."""
    if log10_seconds < 0:
        return "instantly"
    log10_years = log10_seconds - 7.4983  # 3.156e7 seconds per year
    if log10_years > 10:
        return "> 10 billion years"
    seconds = 10 ** log10_seconds
    units = [("year", 31_557_600), ("day", 86_400), ("hour", 3_600),
             ("minute", 60), ("second", 1)]
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            if value >= 1_000_000:
                return f"{value / 1_000_000:.1f} million {name}s"
            if value >= 1_000:
                return f"{value / 1_000:.1f} thousand {name}s"
            value = round(value)
            return f"{value} {name}{'s' if value != 1 else ''}"
    return "instantly"


def copy_to_clipboard(text: str) -> bool:
    for cmd in (["xclip", "-selection", "clipboard"], ["xsel", "-ib"], ["wl-copy"]):
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode(), check=True, timeout=5)
                return True
            except (subprocess.SubprocessError, OSError):
                continue
    return False


def save_secure(path: Path, lines: List[str]) -> None:
    """Append lines to a file created with 0600 permissions."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_wordlist(path: Optional[Path]) -> List[str]:
    if path is None:
        return sorted(set(EMBEDDED_WORDS))
    words = {w.strip().lower() for w in path.read_text(errors="ignore").splitlines()}
    words = {w for w in words if re.fullmatch(r"[a-z]{4,9}", w)}
    return sorted(words)


def mask(pw: str) -> str:
    if len(pw) <= 2:
        return "*" * len(pw)
    return pw[0] + "*" * (len(pw) - 2) + pw[-1]


# --------------------------------------------------------------------------- #
#  Strength analysis
# --------------------------------------------------------------------------- #
@dataclass
class Report:
    length: int
    classes: Dict[str, bool]
    pool_size: int
    raw_entropy: float
    entropy: float
    score: int
    label: str
    color: str
    issues: List[str] = field(default_factory=list)
    tips: List[str] = field(default_factory=list)
    crack: Dict[str, str] = field(default_factory=dict)


def find_sequences(pw: str, min_len: int = 3) -> List[str]:
    """Find ascending/descending alphabetic, numeric & keyboard runs."""
    low = pw.lower()
    found: List[str] = []
    k = 0
    while k <= len(low) - min_len:
        best = ""
        chunk = low[k:k + min_len]
        for seq in _SEQ_VARIANTS:
            idx = seq.find(chunk)
            if idx == -1:
                continue
            ln = min_len
            while (k + ln < len(low) and idx + ln < len(seq)
                   and seq[idx + ln] == low[k + ln]):
                ln += 1
            if ln > len(best):
                best = low[k:k + ln]
        if best:
            found.append(best)
            k += len(best)
        else:
            k += 1
    return found


def analyze(pw: str, common: Set[str]) -> Report:
    classes = {
        "lowercase": bool(re.search(r"[a-z]", pw)),
        "uppercase": bool(re.search(r"[A-Z]", pw)),
        "digits": bool(re.search(r"\d", pw)),
        "symbols": bool(re.search(r"[!-/:-@\[-`{-~]", pw)),
        "unicode/other": bool(re.search(r"[^\x00-\x7F]", pw)),
    }
    pool = (26 * classes["lowercase"] + 26 * classes["uppercase"]
            + 10 * classes["digits"] + 33 * classes["symbols"]
            + 60 * classes["unicode/other"])
    pool = max(pool, 1)
    per_char = math.log2(pool)
    raw = len(pw) * per_char
    eff = raw
    issues: List[str] = []
    tips: List[str] = []

    low = pw.lower()
    normalized = low.translate(LEET_MAP)

    # 1) Known common passwords
    if low in common:
        eff = min(eff, 4.0)
        issues.append("This is one of the most common passwords in the world.")
    elif normalized in common:
        eff = min(eff, 10.0)
        issues.append("Common password with simple leetspeak substitutions "
                      "(e.g. a→@, o→0).")
    else:
        for word in common:
            if len(word) >= 5 and word in normalized:
                eff -= max(len(word) * per_char - 12.0, 0.0)
                issues.append(f"Contains a very common word/password: '{word}'.")
                break

    # 2) Repeated characters (aaa, 1111)
    for m in re.finditer(r"(.)\1{2,}", pw):
        eff -= (len(m.group()) - 1) * per_char
        issues.append(f"Repeated characters: '{m.group()}'.")

    # 3) Repeated blocks (abcabc, 123123)
    m = re.fullmatch(r"(.{2,}?)\1+", pw)
    if m:
        eff -= (len(pw) - len(m.group(1))) * per_char
        issues.append(f"Repeated block pattern: '{m.group(1)}' × "
                      f"{len(pw) // len(m.group(1))}.")

    # 4) Sequences / keyboard walks
    for seq in find_sequences(pw):
        eff -= (len(seq) - 1) * per_char * 0.8
        issues.append(f"Sequential / keyboard pattern: '{seq}'.")

    # 5) Years and dates
    if re.search(r"(?<!\d)(19|20)\d{2}(?!\d)", pw):
        eff -= 6.7
        issues.append("Contains a year (very easy to guess).")
    if re.search(r"(?<!\d)(0[1-9]|[12]\d|3[01])[/.\-]?(0[1-9]|1[0-2])[/.\-]?(\d{2}|\d{4})(?!\d)", pw):
        eff -= 8.0
        issues.append("Looks like a date (DD/MM/YY).")

    # 6) Composition
    if re.fullmatch(r"\d+", pw):
        issues.append("Digits only.")
    elif re.fullmatch(r"[A-Za-z]+", pw):
        issues.append("Letters only.")
    if re.search(r"^[A-Z][a-z]+\d{1,4}[!@#$%^&*]?$", pw):
        eff -= 6.0
        issues.append("Typical 'Word + digits + symbol' structure.")

    # Recommendations
    if len(pw) < 12:
        tips.append("Use at least 12 characters (16+ is recommended).")
    if not classes["uppercase"] or not classes["lowercase"]:
        tips.append("Mix uppercase and lowercase letters.")
    if not classes["digits"]:
        tips.append("Add digits.")
    if not classes["symbols"]:
        tips.append("Add symbols.")
    if issues:
        tips.append("Avoid predictable patterns - use a random generator "
                    "(passforge generate).")
    tips.append("Use a unique password per account and a password manager.")

    eff = max(eff, 0.0)
    if len(pw) < 8:
        eff = min(eff, 27.0)

    if eff < 28:
        label, color = "Very Weak", "red"
    elif eff < 36:
        label, color = "Weak", "dark_orange"
    elif eff < 60:
        label, color = "Medium", "yellow"
    elif eff < 80:
        label, color = "Strong", "green"
    else:
        label, color = "Very Strong", "bright_green"
    score = min(100, int(eff / 90 * 100))

    scenarios = {
        "Online attack (100 guesses/s, throttled)": 2,
        "Offline - slow hash (bcrypt, 10k/s)": 4,
        "Offline - fast hash (MD5/NTLM GPU rig, 100B/s)": 11,
    }
    crack = {}
    for name, log_rate in scenarios.items():
        log_seconds = (eff - 1) * math.log10(2) - log_rate  # average = half the space
        crack[name] = human_time(log_seconds)

    return Report(len(pw), classes, pool, raw, eff, score, label, color,
                  issues, tips, crack)


def hibp_count(pw: str) -> int:
    """Check Have I Been Pwned using k-anonymity (only 5 hash chars are sent)."""
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "PassForge-CLI", "Add-Padding": "true"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode("utf-8")
    for line in body.splitlines():
        h, _, count = line.partition(":")
        if h.strip() == suffix:
            return int(count)
    return 0


def load_common(extra: Optional[Path]) -> Set[str]:
    common = set(COMMON_PASSWORDS)
    if extra:
        with extra.open(errors="ignore") as fh:
            common |= {line.strip().lower() for line in fh if line.strip()}
    return common


def bar(score: int, color: str) -> str:
    filled = score // 5
    return f"[{color}]{'█' * filled}[/][dim]{'░' * (20 - filled)}[/] {score}/100"


def render_report(rep: Report, display: str, breached: Optional[int]) -> None:
    head = Table.grid(padding=(0, 2))
    head.add_row("Password", f"[bold]{display}[/]")
    head.add_row("Length", str(rep.length))
    head.add_row("Strength", f"[bold {rep.color}]{rep.label}[/]  {bar(rep.score, rep.color)}")
    head.add_row("Entropy", f"{rep.entropy:.1f} bits effective "
                            f"[dim](theoretical {rep.raw_entropy:.1f})[/]")
    cls = "  ".join(f"[green]✔[/] {k}" if v else f"[red]✘[/] {k}"
                    for k, v in rep.classes.items()
                    if v or k != "unicode/other")
    head.add_row("Character sets", cls)
    if breached is not None:
        if breached > 0:
            head.add_row("Breach check",
                         f"[bold red]FOUND in {breached:,} known data breaches![/]")
        elif breached == 0:
            head.add_row("Breach check", "[green]Not found in known breaches[/]")
    console.print(Panel(head, title="[bold]Password Analysis[/]", border_style=rep.color))

    t = Table(title="Estimated time to crack (average)", show_lines=False)
    t.add_column("Scenario")
    t.add_column("Time", justify="right")
    for k, v in rep.crack.items():
        t.add_row(k, v)
    console.print(t)

    if rep.issues:
        console.print("\n[bold red]Problems found:[/]")
        for i in rep.issues:
            console.print(f"  [red]•[/] {i}")
    if rep.tips:
        console.print("\n[bold cyan]Recommendations:[/]")
        for tip in rep.tips:
            console.print(f"  [cyan]→[/] {tip}")
    console.print()


def output_results(items: List[str], save: Optional[Path], copy: bool) -> None:
    if save:
        save_secure(save, items)
        console.print(f"[green]Saved to {save} (permissions 600).[/]")
    if copy:
        if copy_to_clipboard(items[0]):
            console.print("[green]First result copied to clipboard.[/]")
        else:
            console.print("[yellow]No clipboard tool found "
                          "(install xclip / xsel / wl-clipboard).[/]")


# --------------------------------------------------------------------------- #
#  Commands
# --------------------------------------------------------------------------- #
@app.command()
def generate(
    length: Annotated[int, typer.Option("--length", "-l", min=4, max=4096,
                                        help="Password length.")] = 20,
    count: Annotated[int, typer.Option("--count", "-n", min=1, max=1000,
                                       help="How many passwords.")] = 1,
    lower: Annotated[bool, typer.Option("--lower/--no-lower", help="a-z")] = True,
    upper: Annotated[bool, typer.Option("--upper/--no-upper", help="A-Z")] = True,
    digits: Annotated[bool, typer.Option("--digits/--no-digits", help="0-9")] = True,
    symbols: Annotated[bool, typer.Option("--symbols/--no-symbols", help="Symbols")] = True,
    custom_symbols: Annotated[Optional[str], typer.Option(
        "--custom-symbols", help="Use your own symbol set.")] = None,
    no_ambiguous: Annotated[bool, typer.Option(
        "--no-ambiguous", "-a", help="Exclude look-alike chars (I l 1 O 0 o).")] = False,
    exclude: Annotated[str, typer.Option(
        "--exclude", "-x", help="Characters to exclude.")] = "",
    analyze_it: Annotated[bool, typer.Option(
        "--analyze/--no-analyze", help="Show strength of each password.")] = True,
    save: Annotated[Optional[Path], typer.Option(
        "--save", "-o", help="Append results to a file (chmod 600).")] = None,
    copy: Annotated[bool, typer.Option("--copy", "-c", help="Copy first password.")] = False,
    plain: Annotated[bool, typer.Option(
        "--plain", help="Print only the passwords (for scripts/pipes).")] = False,
):
    """Generate strong random passwords using [bold]secrets[/]."""
    sym = (custom_symbols or DEFAULT_SYMBOLS) if symbols else None
    pools = build_pools(lower, upper, digits, sym, exclude, no_ambiguous)
    try:
        passwords = [generate_password(length, pools) for _ in range(count)]
    except ValueError as e:
        err_console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(2)

    if plain:
        for p in passwords:
            typer.echo(p)
    else:
        common = COMMON_PASSWORDS
        table = Table(title="Generated Passwords")
        table.add_column("#", justify="right", style="dim")
        table.add_column("Password", style="bold")
        if analyze_it:
            table.add_column("Entropy", justify="right")
            table.add_column("Strength")
        for i, p in enumerate(passwords, 1):
            row = [str(i), p]
            if analyze_it:
                r = analyze(p, common)
                row += [f"{r.entropy:.0f} bits", f"[{r.color}]{r.label}[/]"]
            table.add_row(*row)
        console.print(table)
    output_results(passwords, save, copy)


@app.command()
def passphrase(
    words: Annotated[int, typer.Option("--words", "-w", min=3, max=20,
                                       help="Number of words.")] = 5,
    separator: Annotated[str, typer.Option("--sep", "-s", help="Separator.")] = "-",
    capitalize: Annotated[bool, typer.Option("--capitalize/--no-capitalize")] = True,
    add_number: Annotated[bool, typer.Option("--number/--no-number",
                                             help="Append a random number.")] = True,
    wordlist: Annotated[Optional[Path], typer.Option(
        "--wordlist", exists=True, dir_okay=False, readable=True,
        help="Custom word list file (one word per line).")] = None,
    count: Annotated[int, typer.Option("--count", "-n", min=1, max=100)] = 1,
    save: Annotated[Optional[Path], typer.Option("--save", "-o")] = None,
    copy: Annotated[bool, typer.Option("--copy", "-c")] = False,
    plain: Annotated[bool, typer.Option("--plain")] = False,
):
    """Generate memorable passphrases (e.g. [italic]Falcon-Maple-River-Coral-Amber-47[/])."""
    wl = load_wordlist(wordlist)
    if len(wl) < 100:
        err_console.print("[red]Word list too small (need at least 100 usable words).[/]")
        raise typer.Exit(2)

    results = []
    for _ in range(count):
        chosen = [secrets.choice(wl) for _ in range(words)]
        if capitalize:
            chosen = [w.capitalize() for w in chosen]
        phrase = separator.join(chosen)
        if add_number:
            phrase += separator + str(secrets.randbelow(100)).zfill(2)
        results.append(phrase)

    bits = words * math.log2(len(wl)) + (math.log2(100) if add_number else 0)
    if plain:
        for p in results:
            typer.echo(p)
    else:
        for p in results:
            console.print(f"[bold green]{p}[/]")
        console.print(f"\n[dim]Word list: {len(wl)} words → ≈ {bits:.1f} bits of entropy "
                      f"(attacker is assumed to know the method).[/]")
    output_results(results, save, copy)


@app.command()
def pin(
    length: Annotated[int, typer.Option("--length", "-l", min=4, max=32)] = 6,
    count: Annotated[int, typer.Option("--count", "-n", min=1, max=100)] = 1,
    plain: Annotated[bool, typer.Option("--plain")] = False,
):
    """Generate random numeric PINs (avoids trivial ones like 1111 / 1234)."""
    results = []
    while len(results) < count:
        p = "".join(secrets.choice(string.digits) for _ in range(length))
        if re.fullmatch(r"(\d)\1+", p) or find_sequences(p):
            continue
        results.append(p)
    for p in results:
        typer.echo(p) if plain else console.print(f"[bold green]{p}[/]")


@app.command()
def check(
    password: Annotated[Optional[str], typer.Argument(
        help="Password to test. Omit it to be prompted securely "
             "(recommended: arguments are saved in shell history!).")] = None,
    breach: Annotated[bool, typer.Option(
        "--breach", "-b", help="Check Have I Been Pwned (online, k-anonymity).")] = False,
    show: Annotated[bool, typer.Option("--show", help="Display the password in clear text.")] = False,
    common_file: Annotated[Optional[Path], typer.Option(
        "--common-file", exists=True, dir_okay=False, readable=True,
        help="Extra wordlist of common passwords (e.g. rockyou subset).")] = None,
    min_score: Annotated[int, typer.Option(
        "--min-score", min=0, max=100,
        help="Exit with code 1 if score is lower (useful in scripts).")] = 0,
):
    """Analyse password strength: entropy, patterns, crack-time, breaches."""
    if password is None:
        password = typer.prompt("Password", hide_input=True)
    if not password:
        err_console.print("[red]Empty password.[/]")
        raise typer.Exit(2)

    rep = analyze(password, load_common(common_file))

    breached: Optional[int] = None
    if breach:
        try:
            breached = hibp_count(password)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            err_console.print(f"[yellow]Breach check failed: {e}[/]")

    render_report(rep, password if show else mask(password), breached)
    if rep.score < min_score or (breached or 0) > 0:
        raise typer.Exit(1)


@app.command()
def batch(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True,
                                         help="Text file, one password per line.")],
    breach: Annotated[bool, typer.Option("--breach", "-b")] = False,
    show: Annotated[bool, typer.Option("--show")] = False,
    min_score: Annotated[int, typer.Option("--min-score", min=0, max=100)] = 0,
):
    """Analyse many passwords from a file and print a summary table."""
    common = COMMON_PASSWORDS
    lines = [ln.rstrip("\n") for ln in file.read_text(errors="ignore").splitlines() if ln.strip()]
    if not lines:
        err_console.print("[red]File is empty.[/]")
        raise typer.Exit(2)

    table = Table(title=f"Batch analysis - {len(lines)} passwords")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Password")
    table.add_column("Len", justify="right")
    table.add_column("Entropy", justify="right")
    table.add_column("Strength")
    table.add_column("Issues", justify="right")
    if breach:
        table.add_column("Breaches", justify="right")

    failed = 0
    for i, pw in enumerate(lines, 1):
        r = analyze(pw, common)
        row = [str(i), pw if show else mask(pw), str(r.length),
               f"{r.entropy:.0f}", f"[{r.color}]{r.label}[/]", str(len(r.issues))]
        if breach:
            try:
                n = hibp_count(pw)
                row.append(f"[red]{n:,}[/]" if n else "[green]0[/]")
            except (urllib.error.URLError, TimeoutError, OSError):
                row.append("[yellow]n/a[/]")
        if r.score < min_score:
            failed += 1
        table.add_row(*row)
    console.print(table)
    if min_score and failed:
        console.print(f"[red]{failed} password(s) below minimum score {min_score}.[/]")
        raise typer.Exit(1)


@app.callback()
def main(
    version: Annotated[bool, typer.Option("--version", "-V", is_eager=True,
                                          help="Show version and exit.")] = False,
):
    if version:
        console.print(f"PassForge {__version__}")
        raise typer.Exit()


if __name__ == "__main__":
    app()
