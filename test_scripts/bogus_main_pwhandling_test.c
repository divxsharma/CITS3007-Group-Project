#define TEST_USER "User1"
#define TEST_EMAIL "user1@gmail.com"
#define TEST_BIRTHDATE "1969-02-02"
#define SET_PASSWORD "Bruhbruhbruh12!"
#define TEST_PASSWORD "Thisisamalicioussqlinjection!12"
#define WRONG_PASSWORD "thispwwrongafbro"

#include "account.h"
#include "logging.h"
#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include "banned.h"

int main(void) {
    if (sodium_init() < 0) {
        log_message(LOG_ERROR, "Libsodium init failed");
        return 1;
    }

    //Fill in structure
    account_t acc = {0};
    strncpy(acc.userid, TEST_USER, USER_ID_LENGTH);
    acc.userid[USER_ID_LENGTH - 1] = '\0';
    strncpy(acc.email, TEST_EMAIL, EMAIL_LENGTH);
    acc.email[EMAIL_LENGTH - 1] = '\0';
    strncpy(acc.birthdate, TEST_BIRTHDATE , BIRTHDATE_LENGTH);
    acc.birthdate[BIRTHDATE_LENGTH - 1] = '\0';

    if (!account_update_password(&acc, SET_PASSWORD)) {
        log_message(LOG_ERROR, "Password hashing failed");
        return 1;
    }

    log_message(LOG_INFO, "Stored password hash for '%s':%s\n", acc.userid, acc.password_hash);

    if (account_validate_password(&acc, TEST_PASSWORD)) {
        log_message(LOG_INFO, "Password validation has succeeded for user '%s'", acc.userid);
    } else {
        log_message(LOG_ERROR, "Password validation failed for user '%s'", acc.userid);
        return 1;
    }

    if (!account_validate_password(&acc, WRONG_PASSWORD)) {
        log_message(LOG_INFO, "Password validation correctly rejected an invalid password for user '%s'", acc.userid);
    } else {
        log_message(LOG_ERROR, "Password validation incorrectly accepted an invalid password for user '%s'", acc.userid);
        return 1;
    }

    return 0;
}
