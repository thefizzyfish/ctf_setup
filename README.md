# CTF Setup Script

This script sets up a CTF working environment, including a markdown file to document notes with Obsidian and runs an nmap scan adding the output to the notes file.

## Requirements

- Python 3.x
- `nmap` installed and accessible from the command line

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/ctf_setup.git
    cd ctf_setup
    ```

2. Make the script executable:
    ```bash
    chmod +x ctf_setup.py
    ```

## Usage

Run the script with the following options:

```bash
./ctf_setup.py -p <path_to_ctf_directory> -np <path_to_notes_directory> -n <ctf_name> -ip <ctf_ip> -d <ctf_difficulty>
