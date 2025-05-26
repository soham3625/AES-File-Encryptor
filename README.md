# 🔐 AES File Encryptor/Decryptor (GUI)

A simple, lightweight, and secure GUI tool built with Python and Tkinter to encrypt and decrypt files using AES-256 in CBC mode.

## 📦 Features

- AES-256 encryption/decryption (CBC mode)
- Easy-to-use graphical interface
- Cross-platform support (Windows, macOS, Linux)
- Lightweight with minimal dependencies

## 🖥️ Screenshot

*(You can add a screenshot of your app here once uploaded)*

## 🚀 Getting Started

### Prerequisites

- Python 3.x installed
- `pycryptodome` library

### Installation

Install the required dependency using pip:

```bash
pip install pycryptodome
Running the Tool
Clone the repository or download the script.

Run the script:

bash
Copy
Edit
python gui_tool.py
Use the interface to:

Browse and select a file.

Enter a secret key (password).

Click Encrypt or Decrypt.

Click Run to process the file.

📁 File Descriptions
File	Description
gui_tool.py	Main application script with GUI and encryption logic
requirements.txt	Python dependencies
README.md	Project documentation

🛡️ Security Note
This tool uses AES-256 encryption with a password-derived key via SHA-256 hashing.

Ensure you remember your password — encrypted files cannot be recovered without it.

Use strong and unique passwords for better security.

🧪 Example
Encrypted files will be saved as: yourfile.txt.enc

Decrypted files will be restored to their original name or as yourfile.dec if original exists.
