#!/usr/bin/env python3

'''
Script that sets up a ctf working environment including a markdown file
to document notes with obsidian.
'''

import os
import sys
import subprocess
import argparse
import re

def get_args():
    parser = argparse.ArgumentParser(description="CTF setup script")
    parser.add_argument('-p', '--path', help='Path to the CTF directory', required=True)
    parser.add_argument('-np', '--notes_path', help='Path to the notes directory', required=True)
    parser.add_argument('-n', '--name', help='Name of the CTF', required=True)
    parser.add_argument('-ip', '--ip', help='IP address of the CTF', required=True)
    parser.add_argument('-d', '--difficulty', help='Difficulty of the CTF', required=True)
    return parser.parse_args()

def create_ctf_directory(path, ctf_name):
    try:
        print(f"[*] Creating directory {ctf_name} in {path}")
        ctf_path = os.path.join(path, ctf_name)
        os.makedirs(ctf_path, exist_ok=True)
    except FileExistsError:
        print(f"[-] Directory {ctf_path} already exists, skipping step")
        # move to next step if directory already exists
        return 

def create_notes_file(notes_path, name):
    try:
        print(f"[*] Creating notes file {name}.md in {notes_path}")
        with open(f"{notes_path}/{name}.md", "x") as f:
            f.write(f"`{name}`\n")
    except FileExistsError:
        print(f"[-] File {notes_path}/{name}.md already exists")
        sys.exit(1)

def format_notes_file(notes_path, name, ctf_ip, ctf_difficulty, nmap_output, example_commands, service_versions):
    try:
        with open(f"{notes_path}/{name}.md", "a") as f:
            f.write(f"`{ctf_ip}`\n`{ctf_difficulty}`\n")
            f.write(f"## Enumeration\n\n")
            f.write(f'### Nmap\n')
            f.write(f'```bash\n\n')
            f.write(f'{nmap_output}\n')
            f.write(f'```\n')
            f.write(f'### Example Commands\n')
            f.write(f'```bash\n')
            if example_commands:
                for command in example_commands:
                    f.write(f'{command}\n')
            else:
                f.write('No example commands available.\n')
            f.write(f'```\n')
            if service_versions:
                f.write(f'### Service Versions\n')
                f.write(f'```bash\n')
                for service in service_versions:
                    f.write(f'{service}\n')
            f.write(f'```\n\n')
            f.write(f"---\n")
            f.write(f"## Initial Access\n\n")
            f.write(f"---\n")
            f.write(f"## Privilege Escalation\n\n")
            f.write(f"---\n")
            f.write(f"## Flags\n\n")
            f.write(f'---\n')
    except FileExistsError:
        print(f"File {notes_path}/{name}.md already exists")
        sys.exit(1)

def all_ports(ctf_ip, ctf_path):
    # Change the current working directory to the CTF directory
    os.chdir(ctf_path)
    # construct the nmap_output file path
    nmap_output_file = os.path.join(ctf_path, "all-ports.nmap")
    # Print notification
    print(f"[*] Running nmap scan on {ctf_ip} to find all open ports.")
    # run nmap scan
    subprocess.run(["nmap", "-p-", "-T4", "-oN", nmap_output_file, ctf_ip], stdout=subprocess.PIPE)
    # read nmap scan nmap_output
    with open(nmap_output_file, "r") as file:
        nmap_output = file.read()
        # return open ports
        return re.findall(r"(\d+)/tcp\s+open", nmap_output)

def full_scan(ctf_ip, ctf_path):
    open_ports = all_ports(ctf_ip, ctf_path)
    if not open_ports:
        print("[-] No open ports found.")
        return ""
    ports_str = ",".join(open_ports)
    nmap_output_file = os.path.join(ctf_path, "full-scan.nmap")
    print(f"[*] Running full nmap scan on {ctf_ip} with open ports: {ports_str}.")
    try:
        subprocess.run(["nmap", "-p", ports_str, "-A", "-T4", "-oN", nmap_output_file, ctf_ip], stdout=subprocess.PIPE)
    except Exception as e:
        print(f"[-] An error occurred: {e}")
        return ""
    with open(nmap_output_file, "r") as file:
        nmap_output = file.read()
        return nmap_output

def generate_example_commands(nmap_output, ctf_ip):

    example_commands = []
    # Parse nmap and print out example commands for further enumeration, add example commands to
    # list and notes file
    # If a hostname is found, suggest adding it to /etc/hosts
    if "http-title: Did not follow redirect to" in nmap_output:
        hostnames = []
        example_commands.append(f"\n[+] Found hostnames, add them to /etc/hosts with the following:")
        for line in nmap_output.split("\n"):
            if "http-title: Did not follow redirect to" in line:
                hostnames.append(line.split("http-title: Did not follow redirect to http://")[1])
        for hostname in hostnames:
            example_commands.append(f"echo '{ctf_ip} {hostname}' | sudo tee -a /etc/hosts")
            print(f"[*] Found hostname: {ctf_ip} {hostname}")
    # If a web port is open, suggest gobuster and nikto
    if "http" in nmap_output or "https" in nmap_output:
        example_commands.append(f"\n[+] Found web ports, suggest running gobuster and nikto:")
        example_commands.append(f"gobuster dir -u http://{ctf_ip}:<PORT> -w /usr/share/wordlists/dirb/common.txt -t 50 -o gobuster.out")
        example_commands.append(f"nikto -h http://{ctf_ip}")

    # If an ssh port is open, suggest hydra
    if "ssh" in nmap_output:
        example_commands.append(f"\n[+] Found ssh port, suggest running hydra:")
        example_commands.append(f"hydra -l <USER> -P /usr/share/wordlists/rockyou.txt ssh://{ctf_ip}:<PORT>")
    # If an smb port is open, suggest enum4linux, smbclient, smbmap
    if "smb" or "445" in nmap_output:
        example_commands.append(f"\n[+] Found smb port, suggest running enum4linux, smbclient, smbmap:")
        example_commands.append(f"enum4linux -a {ctf_ip}")
        example_commands.append(f"smbclient -L {ctf_ip}")
        example_commands.append(f"smbmap -H {ctf_ip}")
    # If a mysql port is open, suggest mysql
    if "mysql" in nmap_output:
        example_commands.append(f"\n[+] Found mysql port, suggest running mysql:")
        example_commands.append(f"mysql -h {ctf_ip} -u root -p")
    # If a ftp port is open, suggest ftp
    if "ftp" in nmap_output:
        example_commands.append(f"\n[+] Found ftp port, suggest running ftp:")
        example_commands.append(f"ftp {ctf_ip}")
    # If wordpress is detected, suggest wpscan
    if "wordpress" in nmap_output:
        example_commands.append(f"\n[+] Found wordpress, suggest running wpscan:")
        example_commands.append(f"wpscan --url http://{ctf_ip} -e ap,at,u")
    return example_commands

# Function to parse nmap output and retrieve all service versions that are found
def get_service_versions(nmap_output):
    service_versions = set()
    for line in nmap_output.split("\n"):
        if "open" in line and "1 closed port" not in line:
            match = re.search(r"open\s+\S+\s+(.+)", line)
            if match:
                service_versions.add(match.group(1))
    return list(service_versions)

def main():
    args = get_args()
    ctf_name = args.name
    ctf_path = args.path
    notes_path = args.notes_path
    ctf_ip = args.ip
    ctf_difficulty = args.difficulty
    create_ctf_directory(ctf_path, ctf_name)
    create_notes_file(notes_path, ctf_name)
    nmap_output = full_scan(ctf_ip, os.path.join(ctf_path, ctf_name))
    if nmap_output:
        example_commands = generate_example_commands(nmap_output, ctf_ip)
        service_versions = get_service_versions(nmap_output)
    else:
        example_commands = []
    
    
    format_notes_file(notes_path, ctf_name, ctf_ip, ctf_difficulty, nmap_output, example_commands, service_versions)
    
    print(f"CTF: {ctf_name}")
    print(f"IP: {ctf_ip}")
    print(f"Difficulty: {ctf_difficulty}")

if __name__ == "__main__":
    main()
