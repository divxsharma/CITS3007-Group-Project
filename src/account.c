#define _POSIX_C_SOURCE 200809L
#define MAX_PW_LEN 128 
#define MAX_TIME_STR_LEN 64
#define MAX_DURATION 31536000
#define MAX_LINE_LEN 256
#define OPSLIMIT crypto_pwhash_OPSLIMIT_INTERACTIVE
#define MEMLIMIT crypto_pwhash_MEMLIMIT_INTERACTIVE
#define MIN_PASSWORD_LENGTH 8

#include <unistd.h>
#include "account.h"
#include "logging.h" 
#include <arpa/inet.h>
#include <time.h>
#include <sodium.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include "banned.h"

/**
 * Create a new account with the specified parameters.
 *
 * This function initializes a new dynamically allocated account structure
 * with the given user ID, hash information derived from the specified plaintext password, email address,
 * and birthdate. Other fields are set to their default values.
 * On success, returns a pointer to the newly created account structure.
 * On error, returns NULL and logs an error message.
 */

 //helper functions for validation 

/** 
@brief Check if the email address is valid.
 *
 * This function checks if the provided email address is in a valid format.
 * It ensures that the email contains exactly one '@' symbol, has a valid domain,
 * and does not contain any invalid characters.
 *
 * @param email The email address to check.
 * @return true if the email address is valid, false otherwise.
 */

static bool check_email(const char *email){
  if(!email) return false;
  size_t len = strlen(email);

  if (len ==0 || len >= EMAIL_LENGTH) return false;
  const char *at = strchr(email, '@');

  if(!at || at == email || at == email + len - 1) return false;
  if (strchr(at+1,'@')) return false;

  size_t loc_len = (size_t)(at - email);
  if(loc_len == 0) return false;
  const char *dom = at + 1;
  const char *dot = strchr(dom, '.');
  if(!dot || dot == dom || dot == email + len - 1) return false;
  
  for (size_t i = 0; i < len; ++i) {
    unsigned char c = (unsigned char)email[i];
    if (c <= ' ' || c >= 127) return false;
    if (i < loc_len) {
        if (!(isalnum(c) || c == '.' || c == '_' || c == '-' || c == '+')) return false;
    } else if (email[i] == '@') {
        continue;
    } else {
        if (!(isalnum(c) || c == '.' || c == '-')) return false;
    }
}
return true;
}

/**
@brief 
Check if the birthdate is valid.
 *
 * This function checks if the provided birthdate is in a valid format (YYYY-MM-DD).
 * It ensures that the date is in the correct format and does not contain any invalid characters.
 *
 * @param birthdate The birthdate to check.
 * @return true if the birthdate is valid, false otherwise.
 */

static bool check_birthdate(const char *birthdate) {
  if (!birthdate) return false;
  for (size_t i = 0; i < BIRTHDATE_LENGTH; ++i) {
      if ((i == 4 || i == 7)) {
          if (birthdate[i] != '-') return false;
      } else if (!isdigit((unsigned char)birthdate[i])) {
          return false;
      }
  }
  return birthdate[BIRTHDATE_LENGTH] == '\0';
}

/**
 * @brief Create a new account with the specified parameters.
 *
 * This function initializes a new dynamically allocated account structure
 * with the given user ID, hash information derived from the specified plaintext password, email address,
 * and birthdate. Other fields are set to their default values.
 * On success, returns a pointer to the newly created account structure.
 * On error, returns NULL and logs an error message.
 *
 * @param userid The user ID for the new account.
 * @param plaintext_password The plaintext password for the new account.
 * @param email The email address for the new account.
 * @param birthdate The birthdate for the new account (format: YYYY-MM-DD).
 *
 * @return A pointer to the newly created account structure, or NULL on error.
 */

account_t *account_create(const char *userid, const char *plaintext_password,
                          const char *email, const char *birthdate
                      )
              
{
  if (!userid || !plaintext_password || !email || !birthdate) {
    log_message( LOG_ERROR,"account_create: null argument");
    return NULL;
}
size_t pw_len = strlen(plaintext_password);
if (pw_len < MIN_PASSWORD_LENGTH) {
    log_message( LOG_ERROR,"account_create: password too short");
    return NULL;
}
if (!check_email(email)) {
    log_message(LOG_ERROR,"account_create: invalid email format");
    return NULL;
}
if (!check_birthdate(birthdate)) {
    log_message(LOG_ERROR, "account_create: invalid birthdate format");
    return NULL;
}
if (!sodium_init()) {
    log_message(LOG_ERROR, "account_create: libsodium init failed");
    return NULL;
}
account_t *acc = calloc(1, sizeof(account_t));
if (!acc) {
    log_message(LOG_ERROR, "account_create: allocation failed");
    return NULL;
}

acc->unban_time = 0;
acc->expiration_time = 0;

strncpy(acc->userid, userid, USER_ID_LENGTH - 1);
acc->userid[USER_ID_LENGTH - 1] = '\0';
if (crypto_pwhash_str(acc->password_hash,
                      plaintext_password,
                      pw_len,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
    log_message(LOG_ERROR, "account_create: password hashing failed");
    free(acc);
    return NULL;
}

memset(acc->email, 0, EMAIL_LENGTH);
strncpy(acc->email, email, EMAIL_LENGTH - 1);

memcpy(acc->birthdate, birthdate, BIRTHDATE_LENGTH);
acc->birthdate[BIRTHDATE_LENGTH] = '\0';
return acc;
}

/**
  * @brief Free memory and resources used by the account.
  *
  * This function frees the memory allocated for the account structure and
  * wipes sensitive data before freeing.
  *
  * @param acc A pointer to the account structure to be freed.
  */ 

void account_free(account_t *acc) {
  if (!acc) return;
  sodium_memzero(acc, sizeof *acc);
  free(acc);
}
/**
@brief 
* @brief Set the email address for the account.
 *
 * This function updates the email address of the account with the provided new email.
 * It performs input validation to ensure that the new email is in a valid format and does not exceed the maximum length.
 *
 * @param acc A pointer to the account structure.
 * @param new_email The new email address to set for the account.
 *
 * @pre 'acc' must be non-NULL.
 * @pre 'new_email' must be non-NULL and a valid null-terminated string.
 *
 * @return void
 */
void account_set_email(account_t *acc, const char *new_email) {
if (!acc || !new_email) {
    log_message(LOG_ERROR,"account_set_email: null argument");
    return;
}
if (!check_email(new_email)) {
    log_message( LOG_ERROR,"account_set_email: invalid email format");
    return;
}
size_t len = strlen(new_email);
if (len >= EMAIL_LENGTH) {
    log_message(LOG_ERROR,"account_set_email: email too long");
    return;
}
char new_buf[EMAIL_LENGTH];
memset(new_buf, 0, EMAIL_LENGTH);
memcpy(new_buf, new_email, len + 1);
memcpy(acc->email, new_buf, EMAIL_LENGTH);
}




/**
 * @brief Verfies a users password against the stored hash.
 *
 * The function will validate the provided plaintext password agaisnt the stored password hash.
 * Using the account_t structure, with Libsodium package - Argon2 (crypto_pwhash_str_verify) for password verification.
 * It performs input validation and uses memory locking as an additional layer of security to minimise chance of memory dump exposure/attack. 
 * 
 * @param account_t A Pointer to an account_t structure which contains the  userid, email, plaintext password in hash format and birthdate
 * @param plaintext_password A pointer to the user's input of new password that needs to be securely hashed.
 * 
 * @pre 'acc' must be non-NULL.
 * @pre 'plaintext_password' must be non-NULL and a valid null-terminated string.
 *
 * @return Returns true or false.
 * 
 * @ref crypto_pwhash_str_verify(), sodium_mlock(), sodium_munlock() - Refer to https://doc.libsodium.org/password_hashing/default_phf
 * 
 * @note If failure occurs like Libsodium initilisation or memory lock fails, the function will create a debug/log error and return false.
 */

bool account_validate_password(const account_t *acc, const char *plaintext_password) {
  //Reference Doc: https://doc.libsodium.org/quickstart   
  if (sodium_init() < 0) {
      log_message(LOG_ERROR,"[account_validate_password]: Libsodium library initialisation has failed");
      return false;
  }
  
  
  //Side Question: This validation now is just refering to the pointer/memory location of acc, that it cannot be null
  //Should I also add on validation for the variables inside the structure, e.g. if acc -> email == NULL, etc... 
  if (acc == NULL || plaintext_password == NULL)
  {
    log_message(LOG_ERROR,"[account_validate_password]: NULL input detected for acc and plaintext_password");
    return false;
  } 

  size_t pwlen = strnlen(plaintext_password, MAX_PW_LEN);

  if (pwlen == 0 || pwlen > MAX_PW_LEN){
    log_message(LOG_ERROR,"[account_validate_password]: Invalid Password Length detected");
    return false;
  }

  //Additonal layer of security - Memory locking capability: Allocate and lock the plaintext_password after usage. 
  char secure_pw[MAX_PW_LEN];
  //Lock the password into memory and prevent it from being swapped to disk, if it fails then throw an error for debugging
  if (sodium_mlock(secure_pw, sizeof(secure_pw)) != 0) {
      log_message(LOG_ERROR, "[account_validate_password]: Failed to lock memory for password");
      return false;
  }

  
  strncpy(secure_pw, plaintext_password, sizeof(secure_pw) - 1);
  secure_pw[sizeof(secure_pw)- 1] = '\0';
  
  
  int result = crypto_pwhash_str_verify(acc->password_hash, secure_pw, pwlen);

  //Wipe and unlock the password buffer from memory to be used for password validation
  sodium_munlock(secure_pw,sizeof(secure_pw));

  
  if (result == 0 ){
    log_message(LOG_INFO,"[account_validate_password]: Password validated successfully for user '%s'", acc->userid);
    return true;
  }

  else {
    log_message(LOG_ERROR,"[account_validate_password]: Password validation failed for user '%s'", acc->userid);
    return false;
  }
}

/**
 * @brief Updates the user's stored password hash with the new password provided
 *
 * The function will generate a new hash from the new password provided by user and update the stored password hash in account_t structure acc.
 * Using the account_t structure, with Libsodium package - Argon2 (crypto_pwhash_str) for password hash generation.
 * It performs input validation and uses memory locking as an additional layer of security to minimise chance of memory dump exposure/attack. 
 * 
 * @param account_t A Pointer to an account_t structure which contains the  userid, email, plaintext password in hash format and birthdate
 * @param plaintext_password A pointer to the user's input of new password that needs to be securely hashed.
 * 
 * @pre 'acc' must be non-NULL.
 * @pre 'plaintext_password' must be non-NULL and a valid null-terminated string.
 *
 * @return Returns true or false.
 * 
 * @ref crypto_pwhash_str_verify(), sodium_mlock(), sodium_munlock() - Refer to https://doc.libsodium.org/password_hashing/default_phf
 *
 * @note If failure occurs like Libsodium initilisation or memory lock fails, the function will create a debug/log error and return false.
 */

bool account_update_password(account_t *acc, const char *new_plaintext_password) {
  if (sodium_init() < 0) {
    log_message(LOG_ERROR,"[account_update_password]: Libsodium library initialisation has failed");
    return false;
  }
  
  if (acc == NULL || new_plaintext_password == NULL)
  {
    log_message(LOG_ERROR,"[account_update_password]: NULL input detected for acc and new_plaintext_password");
    return false;
  } 
 
  size_t pwlen = strnlen(new_plaintext_password, MAX_PW_LEN);

  if (pwlen == 0 || pwlen > MAX_PW_LEN){
    log_message(LOG_ERROR,"[account_update_password]: Invalid Password Length detected");
    return false;
  }

  //Additonal layer of security - Memory locking capability: Allocate and lock the plaintext_password after usage. 
  char new_secure_pw[MAX_PW_LEN];

  if (sodium_mlock(new_secure_pw, sizeof(new_secure_pw)) != 0 ){
    log_message(LOG_ERROR, "[account_update_password]: Failed to lock memory for new_plaintext_password");
    return false;
  }

  strncpy(new_secure_pw, new_plaintext_password, sizeof(new_secure_pw) - 1);
  new_secure_pw[sizeof(new_secure_pw) - 1] = '\0';

  int result = crypto_pwhash_str(acc->password_hash, new_secure_pw, pwlen, OPSLIMIT, MEMLIMIT);

  //Wipe and unlock the password buffer from memory to be used for new password update
  sodium_munlock(new_secure_pw, sizeof(new_secure_pw));

  if (result == 0){
    log_message(LOG_INFO,"[account_update_password]: Password updated successfully for user '%s'", acc->userid);
    return true; 
  }

  else {
    log_message(LOG_ERROR,"[account_update_password]: Password updated failed for user '%s'", acc->userid);
    return false;
  }  
}


/**
 * @brief Convert a timestamp to a formatted string.
 *
 * Formats the given `time_t` value into a human-readable timestamp string.
 *
 * @param t The time value to format.
 * @param buffer Output buffer where the formatted time string is stored.
 * @param len The length of the output buffer.
 *
 * @note If formatting fails, the buffer will contain "unavailable".
 */
static void format_time(time_t t, char *buffer, size_t len) {
    if (!buffer || len == 0) return;
    struct tm *tm_info = localtime(&t);
    if (!tm_info || strftime(buffer, len, "%Y-%m-%d %H:%M:%S", tm_info) == 0) {
        strncpy(buffer, "unavailable", len - 1);
        buffer[len - 1] = '\0';
    }
}

/**
 * @brief Convert an IPv4 address to a human-readable string.
 *
 * Safely converts a binary IP address to string format using inet_ntop.
 *
 * @param ip The IPv4 address to convert.
 * @param buffer The output buffer to store the string.
 * @param len The length of the output buffer.
 *
 * @note If conversion fails, "unavailable" is stored in the buffer.
 */
static void format_ip(ip4_addr_t ip, char *buffer, size_t len) {
    if (!buffer || len == 0) return;
    if (!inet_ntop(AF_INET, &ip, buffer, len)) {
        strncpy(buffer, "unavailable", len - 1);
        buffer[len - 1] = '\0';
    }
}


/**
 * @brief Records a successful login attempt for a user account.
 *
 * Resets failure count, updates login time and IP, logs the login event securely.
 *
 * @param acc Pointer to a valid account_t structure.
 * @param ip The IPv4 address of the client attempting login.
 *
 * @note Uses defensive programming (Lab 3), secure logging (Lab 7).
 */
void account_record_login_success(account_t *acc, ip4_addr_t ip) {
    if (!acc) {
        log_message(LOG_ERROR, "[account_record_login_success]: NULL account pointer");
        return;
    }

    char ip_str[INET_ADDRSTRLEN] = {0};
    if (!inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN)) {
        log_message(LOG_WARN, "[account_record_login_success]: Failed to convert IP for user '%s'", acc->userid);
        strncpy(ip_str, "unknown", sizeof(ip_str) - 1);
    }

    char time_str[MAX_TIME_STR_LEN] = {0};
    format_time(time(NULL), time_str, sizeof(time_str));

    acc->last_ip = ip;
    acc->last_login_time = time(NULL);
    acc->login_fail_count = 0;

    log_message(LOG_INFO,
        "[account_record_login_success]: User '%s' successfully logged in from IP %s at %s",
        acc->userid, ip_str, time_str);
}



/**
 * @brief Records a failed login attempt for a user account.
 *
 * Increments login_fail_count and logs securely.
 * Prevents integer overflow if the count reaches UINT_MAX.
 *
 * @param acc Pointer to a valid account_t structure.
 *
 * @note Uses safe integers (Lab 4), logging best practices (Lab 7).
 */
void account_record_login_failure(account_t *acc) {
    if (!acc) {
        log_message(LOG_ERROR, "[account_record_login_failure]: NULL account pointer received.");
        return;
    }

    if (acc->login_fail_count == UINT_MAX) {
        log_message(LOG_WARN, "[account_record_login_failure]: Max failure count reached for user '%s'.", acc->userid);
        return;
    }

    acc->login_fail_count++;
    log_message(LOG_INFO, "[account_record_login_failure]: Failure #%u for user '%s",
                acc->login_fail_count, acc->userid);
}


/**
 * Checks if the account is currently banned.
 *
 * Compares the current system time to the account's unban time.
 * If unban_time is in the future, the account is considered banned.
 *
 * \param acc A pointer to the account_t structure, which contains the unban_time field indicating the ban expiration time.
 * 
 * \pre acc must be non-NULL.
 *
 * \return true if the account is banned, false otherwise.
 */

 bool account_is_banned(const account_t *acc) {
  if (acc == NULL) {
    log_message(LOG_ERROR, "[account_is_banned]: NULL account pointer received");
    return false;
  }

  if (acc->unban_time == 0) {
    return false;
  }

  time_t current_time = time(NULL);
  if (current_time == (time_t)-1) {
      log_message(LOG_ERROR, "[account_is_banned]: Current time not available");
      return false;
  }

  return acc->unban_time > current_time;
}

/**
 * Checks if the account is currently expired.
 *
 * Compares the current system time to the account's expiration time.
 * If expiration_time is in the past, the account is considered expired.
 *
 * \param acc A pointer to the account_t structure, which contains the expiration_time field indicating the account's expiration time.
 * 
 * \pre acc must be non-NULL.
 *
 * \return true if the account is expired, false otherwise.
 */

bool account_is_expired(const account_t *acc) {
  if (acc == NULL) {
    log_message(LOG_ERROR, "[account_is_expired]: NULL account pointer received");
    return false;
  }

  if (acc->expiration_time == 0) {
    return false;
  }

  time_t current_time = time(NULL);
  if (current_time == (time_t)-1) {
      log_message(LOG_ERROR, "[account_is_expired]: Current time not available");
      return false;
  }

  return acc->expiration_time < current_time; 
}

/**
 * Sets the account's unban time to the given duration.
 *
 * \param acc A pointer to the account_t structure.
 * \param t The number of seconds from now until the ban should expire.
 *
 * \pre acc must be non-NULL.
 */

void account_set_unban_time(account_t *acc, time_t t) {
  if (acc == NULL) {
    log_message(LOG_ERROR, "[account_set_unban_time]: NULL account pointer received");
    return;
  }

  if (t < 0) {
    log_message(LOG_WARN, "[account_set_unban_time]: Negative duration provided; unban_time not updated");
    return;
  }

  if (t == 0) {
    acc->unban_time = 0;
  } else {

    time_t current_time = time(NULL);
    if (current_time == (time_t)-1) {
        log_message(LOG_ERROR, "[account_set_unban_time]: Current time not available");
        return;
    }

    if (t > MAX_DURATION) {
      log_message(LOG_WARN, "[account_set_unban_time]: Duration exceeds maximum limit, setting to max duration");
      t = MAX_DURATION;
    }

    acc->unban_time = current_time + t;
  }
}

/**
 * Sets the account's expiration time to the given duration.
 *
 * \param acc A pointer to the account_t structure.
 * \param t The number of seconds from now until the account should expire.
 *
 * \pre acc must be non-NULL.
 */

void account_set_expiration_time(account_t *acc, time_t t) {
  if (acc == NULL) {
    log_message(LOG_ERROR, "[account_set_expiration_time]: NULL account pointer received");
    return;
  }

  if (t < 0) {
    log_message(LOG_WARN, "[account_set_expiration_time]: Negative duration provided; expiration_time not updated");
    return;
  }

  if (t == 0) {
    acc->expiration_time = 0;
  } else {

    time_t current_time = time(NULL);
    if (current_time == (time_t)-1) {
        log_message(LOG_ERROR, "[account_set_expiration_time]: Current time not available");
        return;
    }

    if (t > MAX_DURATION) {
      log_message(LOG_WARN, "[account_set_expiration_time]: Duration exceeds maximum limit, setting to max duration");
      t = MAX_DURATION;
    }

    acc->expiration_time = current_time + t;
  }
}

/**
 * @brief Print a detailed summary of a user's account.
 *
 * Outputs to a file descriptor including sensitive but non-secret fields.
 * Includes user ID, email, login count, and last login metadata.
 *
 * @param acct Pointer to the account_t structure.
 * @param fd Output file descriptor (e.g., STDOUT or socket).
 * @return true on success, false on failure.
 *
 * @note Applies safe I/O (Lab 5), structured logging (Lab 7).
 */
bool account_print_summary(const account_t *acct, int fd) {
    if (!acct) {
        log_message(LOG_ERROR, "[account_print_summary]: NULL account pointer.");
        return false;
    }

    if (fd < 0) {
        log_message(LOG_ERROR, "[account_print_summary]: Invalid file descriptor.");
        return false;
    }

    char line[MAX_LINE_LEN];
    ssize_t written;

    snprintf(line, sizeof(line), "User ID         : %s\n", acct->userid);
    if ((written = write(fd, line, strlen(line))) < 0) return false;

    snprintf(line, sizeof(line), "Email           : %s\n", acct->email);
    if ((written = write(fd, line, strlen(line))) < 0) return false;

    snprintf(line, sizeof(line), "Birthdate       : %s\n", acct->birthdate);
    if ((written = write(fd, line, strlen(line))) < 0) return false;

    snprintf(line, sizeof(line), "Login Failures  : %u\n", acct->login_fail_count);
    if ((written = write(fd, line, strlen(line))) < 0) return false;

    char ip_str[INET_ADDRSTRLEN] = "unavailable";
    format_ip(acct->last_ip, ip_str, sizeof(ip_str));
    snprintf(line, sizeof(line), "Last Login IP   : %s\n", ip_str);
    if ((written = write(fd, line, strlen(line))) < 0) return false;

    char time_str[MAX_TIME_STR_LEN] = "unavailable";
    format_time(acct->last_login_time, time_str, sizeof(time_str));
    snprintf(line, sizeof(line), "Last Login Time : %s\n", time_str);
    if ((written = write(fd, line, strlen(line))) < 0) return false;

    log_message(LOG_INFO, "[account_print_summary]: Printed summary for user '%s'.", acct->userid);
    return true;
}



