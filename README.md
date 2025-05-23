# Windows Maintenance Script

A streamlined PowerShell-based tool to automate routine system maintenance and apply optional power configuration tweaks.

## Features

- One-click full maintenance (cleanup, resets, etc.)
- Optional power tweaks
- Clean UI and console feedback
- Works on Windows 10 & 11

## Quick Start (Recommended)

**For most users, the easiest option is to:**

1. Head to the [Releases](../../releases) tab.
2. Download the prebuilt `Maintenance.exe`.
3. Right-click the EXE → **Run as administrator**

> This is the same code as the script below — just packaged for convenience. You can still inspect the source if you prefer.


## Manual Option (PowerShell Script)

If you prefer running the raw script manually:

### 1. Download the Script

- Click `Code` → `Download ZIP`, or clone the repo with:
  ```bash
  git clone https://github.com/Lokistic/Windows-Maintenance.git
  ```

### 2. Unblock the Script (Important)

- Right-click the `Maintenance.ps1` file.
- Select **Properties**.
- Check **Unblock** at the bottom.
- Click **Apply**.

### 3. Run the Script

- Right-click the file → **Run with PowerShell**
- It will auto-elevate if not already running as administrator.

> The script does not apply power tweaks unless you explicitly choose to.

## Troubleshooting

- If any power tweaks fail, the script provides instructions.
- You can also use tools like **PowerSettingsExplorer** to inspect GUIDs manually.

> Feel free to inspect the source to verify there is no malicious behavior.
