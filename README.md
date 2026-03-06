# 🛠 Windows Pro Admin Tool

> **[English below](#english-version)**

---

## 🇵🇱 Wersja polska

Zaawansowane narzędzie administracyjne dla systemu Windows z graficznym interfejsem użytkownika (GUI), umożliwiające zarządzanie uprawnieniami NTFS, zasadami grup, kontami użytkowników oraz odzyskiwaniem systemu — bez konieczności korzystania z wielu wbudowanych narzędzi Windows.

### 📋 Wymagania

- Windows 10 / 11 (64-bit)
- Python 3.9+ (64-bit)
- Uruchomienie jako **Administrator**

### 📦 Instalacja

```bash
pip install -r requirements.txt
python admin_tool_PL.py
```

### ✨ Funkcje

#### 🔒 Uprawnienia NTFS
- Przeglądanie i edycja uprawnień NTFS dla plików i folderów
- Dodawanie i usuwanie wpisów ACL (Access Control List)
- Zmiana właściciela pliku/folderu (`Change Owner`) przez `SetNamedSecurityInfoW`
- Obsługa dziedziczenia uprawnień
- Wsparcie dla użytkowników, grup i kont systemowych

#### 💿 Zasady CD/DVD (Group Policy)
- Zarządzanie zasadami dostępu do napędu CD/DVD identycznie jak w `gpedit.msc`
- **Konfiguracja komputera** (HKLM) — blokada dla wszystkich użytkowników:
  - Odmowa wykonywania
  - Odmowa odczytu
  - Odmowa zapisu
- **Konfiguracja użytkownika** (HKCU) — blokada per użytkownik:
  - Odmowa odczytu
  - Odmowa zapisu
- Zapis do rejestru Windows **i** pliku `Registry.pol` — w pełni kompatybilny z `gpedit.msc`

#### ➕ Tworzenie kont użytkowników
- Masowe tworzenie kont użytkowników z pliku listy
- Wspólne hasło dla wszystkich tworzonych kont
- Automatyczne tworzenie folderów domowych na wybranym dysku
- Przypisywanie kont do lokalnych grup (Administratorzy / Użytkownicy)

#### 👥 Zarządzanie kontami
- Przeglądanie wszystkich lokalnych kont użytkowników
- Włączanie i wyłączanie kont
- Zmiana haseł
- Usuwanie kont
- Podgląd przynależności do grup

#### 🛡 Odzyskiwanie systemu
- Tworzenie punktów przywracania systemu z opisem i wyborem typu
- Uruchamianie kreatora dysku odzyskiwania USB
- Szybki dostęp do narzędzi diagnostycznych:
  - `sfc /scannow` — skanowanie plików systemowych
  - `DISM /RestoreHealth` — naprawa obrazu systemu
  - Zarządzanie dyskami, Windows Defender, Podgląd zdarzeń
  - Konfiguracja systemu (msconfig), Czyszczenie dysku, Menedżer urządzeń

### 🏗 Architektura techniczna

| Komponent | Technologia |
|-----------|-------------|
| GUI | PySide6 (Qt6) |
| Uprawnienia NTFS | `win32security`, `ctypes`, `advapi32` |
| Rejestr Windows | `winreg`, `reg.exe` |
| Group Policy | `Registry.pol` (format binarny PReg) |
| Konta użytkowników | `win32net`, `win32netcon` |

### 📁 Struktura projektu

```
admin_tool_FINAL.py   — główny plik aplikacji
requirements.txt      — zależności Python
README.md             — dokumentacja
```

### ⚠️ Uwagi

- Aplikacja wymaga uruchomienia z uprawnieniami **Administratora** — automatycznie prosi o elevację UAC przy starcie
- Zmiany zasad Group Policy są widoczne w `gpedit.msc` po jego ponownym uruchomieniu
- Testowano na Windows 10 22H2 i Windows 11 23H2

---

## English Version

Advanced Windows administration tool with a graphical user interface (GUI) for managing NTFS permissions, Group Policy, user accounts, and system recovery — all in one place, without switching between multiple built-in Windows tools.

### 📋 Requirements

- Windows 10 / 11 (64-bit)
- Python 3.9+ (64-bit)
- Must be run as **Administrator**

### 📦 Installation

```bash
pip install -r requirements.txt
python admin_tool_EN.py
```

### ✨ Features

#### 🔒 NTFS Permissions
- View and edit NTFS permissions for files and folders
- Add and remove ACL (Access Control List) entries
- Change file/folder ownership (`Change Owner`) via `SetNamedSecurityInfoW`
- Inheritance control
- Support for users, groups, and system accounts

#### 💿 CD/DVD Group Policy
- Manage CD/DVD drive access policies identical to `gpedit.msc`
- **Computer Configuration** (HKLM) — applies to all users:
  - Deny Execute access
  - Deny Read access
  - Deny Write access
- **User Configuration** (HKCU) — per-user policy:
  - Deny Read access
  - Deny Write access
- Writes to both Windows Registry **and** `Registry.pol` — fully compatible with `gpedit.msc`

#### ➕ User Account Creation
- Bulk creation of user accounts from a list
- Shared password for all created accounts
- Automatic home folder creation on a selected drive
- Assign accounts to local groups (Administrators / Users)

#### 👥 Account Management
- Browse all local user accounts
- Enable and disable accounts
- Change passwords
- Delete accounts
- View group membership

#### 🛡 System Recovery
- Create system restore points with custom description and type
- Launch the USB recovery drive wizard
- Quick access to diagnostic tools:
  - `sfc /scannow` — system file integrity scan
  - `DISM /RestoreHealth` — Windows image repair
  - Disk Management, Windows Defender, Event Viewer
  - System Configuration (msconfig), Disk Cleanup, Device Manager

### 🏗 Technical Architecture

| Component | Technology |
|-----------|-------------|
| GUI | PySide6 (Qt6) |
| NTFS Permissions | `win32security`, `ctypes`, `advapi32` |
| Windows Registry | `winreg`, `reg.exe` |
| Group Policy | `Registry.pol` (PReg binary format) |
| User Accounts | `win32net`, `win32netcon` |

### 📁 Project Structure

```
admin_tool_FINAL.py   — main application file
requirements.txt      — Python dependencies
README.md             — documentation
```

### ⚠️ Notes

- The application requires **Administrator** privileges — it automatically requests UAC elevation on startup
- Group Policy changes are visible in `gpedit.msc` after reopening it
- Tested on Windows 10 22H2 and Windows 11 23H2

---

### 📄 License

MIT License — free to use, modify and distribute.
