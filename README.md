# Token Duplication to NT AUTHORITY\SYSTEM
![look at that bro](/img/image.png)

A simple C++ project demonstrating how easy it is to duplicate a token from the `lsass.exe` process to become `NT AUTHORITY\SYSTEM`.

## Prerequisites

- Administrative privileges on the machine where you will run this code.

## Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/lazy-importer/TokenDupper.git

Usage

Run the Executable  after building it :

Execute the compiled binary with administrative privileges.
The program will attempt to duplicate the token from the lsass.exe process.

The program will display ASCII art and execute a command prompt with elevated privileges.
The output of the whoami command will be displayed in red to indicate the current user context.

Explanation : 

-> The code loads ntdll.dll to access low-level Windows API functions.
-> It duplicates the token from the lsass.exe process, which typically runs under the NT AUTHORITY\SYSTEM account.
-> The duplicated token is used to create a new process with elevated privileges. 

This code is intended for educational purposes to understand how token manipulation can be used for privilege escalation.
Always use such knowledge responsibly and ethically.
Unauthorized privilege escalation on systems is illegal and unethical.

License

This project is licensed under the MIT License - see the LICENSE.md file for details.
