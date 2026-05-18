#!/usr/bin/env python3
"""
Sheep Feeds CLI Interactive Setup Wizard
Copyright (c) 2026 byFranke - Security Solutions
"""

import base64
import configparser
import os
import secrets
import subprocess
import sys
from getpass import getpass
from pathlib import Path


PBKDF2_ITERATIONS = 600_000
PBKDF2_SALT_BYTES = 16


def check_dependencies():
    required = ["rich", "cryptography", "keyring"]
    missing = []
    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)

    if missing:
        print("Installing missing dependencies...")
        print(f"Missing packages: {', '.join(missing)}")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install"] + missing + ["--user"],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                if "externally-managed-environment" in result.stderr:
                    print("\nYour system uses externally managed Python (PEP 668).")
                    answer = input(
                        "Try installing with --break-system-packages? [y/N]: "
                    ).strip().lower()
                    if answer in ("y", "yes"):
                        result2 = subprocess.run(
                            [sys.executable, "-m", "pip", "install"] + missing
                            + ["--break-system-packages"],
                            capture_output=True, text=True,
                        )
                        if result2.returncode == 0:
                            print("Dependencies installed successfully!")
                            print(f"Please restart the setup:\n  {sys.executable} setup.py")
                            sys.exit(0)
                        print(f"Installation failed: {result2.stderr}")
                    print("\nAlternative installation methods:")
                    print("\n1. Use a virtual environment (recommended):")
                    print("   python3 -m venv venv")
                    print("   source venv/bin/activate")
                    print("   pip install -r requirements.txt")
                    print("   python setup.py")
                    print("\n2. Use system packages:")
                    print("   sudo apt install python3-rich python3-cryptography python3-keyring")
                    sys.exit(1)
                raise subprocess.CalledProcessError(
                    result.returncode, result.args, result.stderr
                )
            print("Dependencies installed successfully!")
            print(f"Please restart the setup:\n  {sys.executable} setup.py")
            sys.exit(0)
        except subprocess.CalledProcessError:
            print("Error installing dependencies. Run: pip install -r requirements.txt")
            sys.exit(1)


check_dependencies()


from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False


console = Console()

GITHUB_REPO = "https://github.com/byfranke/sheep-feeds-cli"
CONFIG_DIR = Path.home() / ".sheep-feeds-cli"
CONFIG_FILE = CONFIG_DIR / "config.ini"
VERSION_FILE = Path(__file__).parent / "VERSION"
PRIVACY_POLICY = "https://sheep.byfranke.com/pages/privacy.html"
TERMS_OF_SERVICE = "https://sheep.byfranke.com/pages/terms.html"
SUPPORT_EMAIL = "support@byfranke.com"
STORE_URL = "https://sheep.byfranke.com/pages/store"


class SecureTokenManager:
    def __init__(self):
        self.config_dir = CONFIG_DIR
        self.config_dir.mkdir(exist_ok=True)
        try:
            os.chmod(self.config_dir, 0o700)
        except OSError:
            pass

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        if not ENCRYPTION_AVAILABLE:
            raise ImportError("Cryptography library not available")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_token(self, token: str, password: str, salt: bytes) -> str:
        f = Fernet(self._derive_key(password, salt))
        return base64.b64encode(f.encrypt(token.encode())).decode()

    def save_encrypted_token(self, token: str, password: str):
        salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
        encrypted = self.encrypt_token(token, password, salt)

        config = configparser.ConfigParser()
        if CONFIG_FILE.exists():
            config.read(CONFIG_FILE)
        if "api" not in config:
            config["api"] = {}
        config["api"]["encrypted_token"] = encrypted
        config["api"]["salt"] = base64.b64encode(salt).decode()
        config["api"]["kdf_iterations"] = str(PBKDF2_ITERATIONS)
        config["api"]["encryption_enabled"] = "true"

        with open(CONFIG_FILE, "w") as f:
            config.write(f)
        os.chmod(CONFIG_FILE, 0o600)

    def use_system_keyring(self, token: str) -> bool:
        if not KEYRING_AVAILABLE:
            console.print("[yellow]Warning: keyring module not available[/yellow]")
            return False
        try:
            keyring.set_password("sheep-feeds-cli", "api_token", token)
            return True
        except Exception as e:
            console.print(f"[yellow]Warning: keyring failed: {e}[/yellow]")
            return False


class SheepFeedsSetup:
    def __init__(self):
        self.token_manager = SecureTokenManager()
        self.current_version = VERSION_FILE.read_text().strip() if VERSION_FILE.exists() else "1.0.0"

    def display_welcome(self):
        console.clear()
        header = (
            f"SHEEP FEEDS CLI SETUP WIZARD v{self.current_version}\n"
            "Threat-intelligence feeds for CTI workflows"
        )
        console.print(Panel(header, style="bold red"))

        legal = (
            "[bold]Legal[/bold]\n"
            f"- Privacy Policy: {PRIVACY_POLICY}\n"
            f"- Terms of Service: {TERMS_OF_SERVICE}\n"
            f"- Support: {SUPPORT_EMAIL}\n"
            "- License: byFranke License (see LICENSE file)\n\n"
            "By continuing, you agree to the terms and privacy policy."
        )
        console.print(Panel(legal, title="Legal Notice", style="yellow"))

        if not Confirm.ask("\n[bold]Accept and continue?[/bold]"):
            console.print("[red]Setup cancelled.[/red]")
            sys.exit(0)

    def check_python_version(self):
        v = sys.version_info
        if v.major < 3 or (v.major == 3 and v.minor < 7):
            console.print("[red]Python 3.7 or higher is required[/red]")
            sys.exit(1)
        console.print(f"[green][OK][/green] Python {v.major}.{v.minor}.{v.micro} detected")

    def configure_token(self):
        console.print("\n[bold]API Token Configuration[/bold]")
        console.print("Your API token will be encrypted with a master password.\n")

        if not ENCRYPTION_AVAILABLE:
            console.print("[red]Encryption libraries not available.[/red]")
            console.print("Install: pip install cryptography keyring")
            return False

        cta = (
            "[bold]Don't have an API token yet?[/bold]\n\n"
            f"Get one at [cyan]{STORE_URL}[/cyan]\n"
            "  - Sheep Pro / Pro Max / Enterprise — paid plans, token by email.\n"
            "  - Black Sheep gift card — redeem on Discord with /token.\n\n"
            "[dim]Tokens start with 'shp_'. Paste yours below.[/dim]"
        )
        console.print(Panel(cta, title="Need a token?", style="yellow"))

        console.print("\n[yellow]Enter your API token (hidden):[/yellow]")
        token = getpass("Token: ").strip()
        if not token:
            console.print("[red]Token cannot be empty.[/red]")
            console.print(f"Get yours at [cyan]{STORE_URL}[/cyan]")
            return False

        console.print("\n[bold]Set a master password for token encryption[/bold]")
        console.print("[dim]Required to decrypt the token in each terminal session.[/dim]")
        while True:
            pw1 = getpass("Master Password (min 8 chars): ")
            pw2 = getpass("Confirm Password: ")
            if pw1 != pw2:
                console.print("[red]Passwords don't match. Try again.[/red]")
                continue
            if len(pw1) < 8:
                console.print("[red]Password must be at least 8 characters[/red]")
                continue
            break

        self.token_manager.save_encrypted_token(token, pw1)
        console.print("[green][OK][/green] Token encrypted and saved")
        console.print(
            "[yellow]You'll re-enter the master password once per terminal session.[/yellow]"
        )
        return True

    def check_system_installation(self):
        console.print("\n[bold]Checking installation[/bold]")
        try:
            result = subprocess.run(
                ["which", "sheep-feeds"], capture_output=True, text=True
            )
            if result.returncode == 0:
                console.print(
                    f"[green][OK][/green] sheep-feeds is at: {result.stdout.strip()}"
                )
                return True
            console.print("[yellow]sheep-feeds not found in PATH.[/yellow]")
            console.print(f"Reinstall with the bundled install.sh, or check {GITHUB_REPO}")
            return False
        except Exception:
            return False

    def system_installation(self):
        console.print("\n[bold]System installation[/bold]")
        if Confirm.ask("Install sheep-feeds-cli system-wide? (requires sudo)"):
            try:
                script_path = Path(__file__).parent / "feeds-cli.py"
                subprocess.run(
                    ["sudo", "cp", str(script_path), "/usr/local/bin/sheep-feeds"],
                    check=True,
                )
                subprocess.run(
                    ["sudo", "chmod", "+x", "/usr/local/bin/sheep-feeds"], check=True
                )
                console.print(
                    "[green][OK][/green] Installed to /usr/local/bin/sheep-feeds"
                )
                console.print("Run 'sheep-feeds list' to test.")
            except subprocess.CalledProcessError as e:
                console.print(f"[red]Installation failed: {e}[/red]")

    def display_summary(self):
        console.print("\n" + "=" * 50)
        console.print(
            Panel(
                "[bold green]Setup Completed[/bold green]",
                style="green",
            )
        )
        guide = (
            "[bold]Quick start[/bold]\n\n"
            "1. List feeds:\n"
            "   [cyan]sheep-feeds list[/cyan]\n\n"
            "2. Latest 20 CVEs:\n"
            "   [cyan]sheep-feeds latest cve --count 20[/cyan]\n\n"
            "3. Items since a date, filtered by severity, as JSON:\n"
            "   [cyan]sheep-feeds get cve --since 2026-05-01 --severity high --json[/cyan]\n\n"
            "4. Per-feed stats:\n"
            "   [cyan]sheep-feeds stats ransomware[/cyan]\n\n"
            "5. Dashboard-style summary across all feeds:\n"
            "   [cyan]sheep-feeds summary[/cyan]\n\n"
            f"[dim]Documentation: {GITHUB_REPO}[/dim]"
        )
        console.print(Panel(guide, title="What's next?", style="cyan"))

    def run(self):
        self.display_welcome()
        self.check_python_version()
        ok = self.configure_token()
        if not ok:
            console.print(
                "[red]Token configuration failed. Re-run setup.py when ready.[/red]"
            )
            sys.exit(1)
        self.system_installation()
        self.check_system_installation()
        self.display_summary()


if __name__ == "__main__":
    try:
        SheepFeedsSetup().run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled.[/yellow]")
        sys.exit(130)
