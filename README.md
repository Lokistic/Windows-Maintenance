# Windows Maintenance Script

Streamlined PowerShell script designed to automate routine system maintenance and apply optional power configuration tweaks.

## Features

- One-click maintenance run (cleanup, resets, etc.)
- Optional power tweaks
- Safe execution with input validation
- (Should) Supports Windows 10/11

## How to Use

1. **Download the script:**
   - Click `Download ZIP` or clone the repo, then extract it.

2. **Unblock the script (important):**
   - Right-click the `Maintenance.ps1` file.
   - Go to **Properties**.
   - Check the **Unblock** box at the bottom.
   - Click **Apply**.

3. **Run the script:**
   - Right-click the file and select **Run with PowerShell**.
   - It will auto-elevate if not already run as Administrator.

> The script will not apply tweaks unless you choose to.

## Troubleshooting

If any power tweaks fail, the script provides guidance to manually retrieve GUIDs.

---
