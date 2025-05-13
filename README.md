# CITS3007-Group 7-Access Control System 
## How to run test scripts
To run the test scripts, run the following commands:
1) Convert the check_account.ts into a check_account.c file.
```bash
checkmk test_scripts/check_account.ts > test_scripts/check_account.c
```
2) Compile check_account.c file and link with other associated files.
```bash 
gcc -Wall -Wextra -Werror -pedantic -std=c11 -g -pthread -o test_scripts/check_account test_scripts/check_account.c src/account.c src/login.c src/logging.h -lcheck -lsodium -lsubunit -lm -lrt -pthread
```
3) Run the test script.
```bash
./test_scripts/check_account
```


