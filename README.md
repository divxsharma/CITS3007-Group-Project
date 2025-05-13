# CITS3007-Group-Project
To run the test scripts, run the following commands:
1) checkmk test_scripts/check_account.ts > test_scripts/check_account.c
2) gcc -Wall -Wextra -Werror -pedantic -std=c11 -g -pthread -o test_scripts/check_account test_scripts/check_account.c src/account.c src/login.c src/logging.h -lcheck -lsodium -lsubunit -lm -lrt -pthread
3) ./test_scripts/check_account 