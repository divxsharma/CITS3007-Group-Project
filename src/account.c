#define _POSIX_C_SOURCE 200809L
#define MAX_PW_LEN 128 
#define MIN_PW_LEN 8
#define MAX_TIME_STR_LEN 64
#define MAX_DURATION 31536000
#define MAX_LINE_LEN 256
#define MAX_EMAIL_LEN 100

#define OPSLIMIT crypto_pwhash_OPSLIMIT_INTERACTIVE
#define MEMLIMIT crypto_pwhash_MEMLIMIT_INTERACTIVE

#include "account.h"
#include "logging.h" 

#include <arpa/inet.h>
#include <time.h>
#include <sodium.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
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
  size_t len = strnlen(email, MAX_EMAIL_LEN); 

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

static bool check_birthdate(const char *birthdate){
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
 * @brief Checks if the password contains any dangerous characters that may lead to code injection.
 * 
 * TODO: UPDATE DOCUMENTATION BLOCK, Passwords must be minimum 12 length, uppercase, no illegal characters. 
 * Disallows control characters and common shell metacharacters such as: ; & | < > ` ' " \ $
 *
 * @param password_provided A null-terminated string containing the user's password.
 
 * @return true if the password is safe, false if unsafe characters are found.
 */

 static bool validate_password(const char *password_provided) {

  if (password_provided == NULL){
    log_message(LOG_ERROR, "[validate_password]: Failed to validate password, Password contains NULL value or is empty.\n");
    return false;
  } 
    
  size_t len = strnlen(password_provided, MAX_PW_LEN + 1);
  
  if (len < MIN_PW_LEN || len > MAX_PW_LEN) {
    log_message(LOG_ERROR, "[validate_password]: Password must be between %d and %d characters.\n", MIN_PW_LEN, MAX_PW_LEN);
    return false;
  }
  
  // Blacklist chars used for OS, SQL, XSS injection and Path Traversal
  static const char *blacklisted_chars = "'\";|&<>$`(){}[]*?=/%-#./\\";

  bool has_upper   = false;
  bool has_lower   = false;
  bool has_digit   = false;
  bool has_special = false;

  for (size_t i = 0; i < len; ++i) {
    
      unsigned char c = (unsigned char)password_provided[i];

      if (strchr(blacklisted_chars, c)){
        log_message(LOG_ERROR, "[validate_password]: Failed to validate password, Blacklisted chars were provided.\n");
        return false;
      }

      if (isupper(c)){
        has_upper = true;
      }               
      
      else if (islower(c)){
        has_lower = true;
      }            

      else if (isdigit(c)){
        has_digit = true;
      }                

      else if (ispunct(c) || isspace(c)){
        has_special = true;
      }   
      
  }

  return has_upper && has_lower && has_digit && has_special;
}

/**
 * @brief Checks if the password contains any dangerous characters that may lead to code injection.
 * 
 * TODO: UPDATE DOCUMENTATION BLOCK, Passwords must be minimum 12 length, uppercase, no illegal characters. 
 * Disallows control characters and common shell metacharacters such as: ; & | < > ` ' " \ $
 *
 * @param password_provided A null-terminated string containing the user's password.
 
 * @return true if the password is safe, false if unsafe characters are found.
 */

static bool safe_str_copy(char *dst, size_t dst_size, const char *src) {

  int result = snprintf(dst, dst_size, "%s", src);

  if (result < 0) {
    log_message(LOG_ERROR, "[account_create]: snprintf error in copying value.\n");
    return false;
  }

  if ((size_t)result >= dst_size) {
    log_message(LOG_ERROR, "[account_create]: Failed to copy over value as truncation has occured.\n");
    return false;
  }
  return true;
}

/*
account_t *account_create(const char *userid, const char *plaintext_password, const char *email, const char *birthdate) {
    if (!userid || !plaintext_password || !email || !birthdate) {
        log_message(LOG_ERROR, "account_create: null argument");
        return NULL;
    }
    size_t pw_len = strlen(plaintext_password);
    if (pw_len < MIN_PW_LEN) {
        log_message(LOG_ERROR, "account_create: password too short");
        return NULL;
    }
    if (!check_email(email)) {
        log_message(LOG_ERROR, "account_create: invalid email format");
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

    strncpy(acc->userid, userid,
    USER_ID_LENGTH - 1);  // TODO: Use strcpy_s, strncpy (unsafe)
    acc->userid[USER_ID_LENGTH - 1] = '\0';

    if (crypto_pwhash_str(acc->password_hash, plaintext_password, pw_len,
    crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        log_message(LOG_ERROR, "account_create: password hashing failed");
        free(acc);
        return NULL;
    }

    memset(acc->email, 0, EMAIL_LENGTH);
    strncpy(acc->email, email,
    EMAIL_LENGTH - 1);  // TODO: Use strcpy_s, strncpy (unsafe)

    memcpy(acc->birthdate, birthdate,BIRTHDATE_LENGTH);  // TODO: Use memcpy_s, memcpy (unsafe)
    acc->birthdate[BIRTHDATE_LENGTH] = '\0';
    return acc;
}
*/

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

account_t *account_create(const char *userid, const char *plaintext_password, const char *email, const char *birthdate) {
  if (!userid || !plaintext_password || !email || !birthdate) {
    log_message(LOG_ERROR, "[account_create]: Userid, plaintext, email or birthday cannot be empty/NULL.\n");
    return NULL;
  }

  if (!validate_password(plaintext_password)) {
    log_message(LOG_ERROR, "[account_create]: Password contains unsafe characters that may allow injection.");
    return NULL;
  }

  if (!check_email(email)) {
    log_message(LOG_ERROR,"[account_create]: Invalid email format.\n");
    return NULL;
  }

  if (!check_birthdate(birthdate)) {
    log_message(LOG_ERROR,"[account_create]: Invalid birthdate format.\n");
    return NULL;
  }

  if (sodium_init() < 0) {
    log_message(LOG_ERROR,"[account_create]: Failed to initalise Libsodium library.\n");
    return NULL;
  }

  account_t *acc = calloc(1, sizeof(account_t));
  if (!acc) {
    log_message(LOG_ERROR, "[account_create]: Failed to allocate memory for acc struct (calloc returned NULL).\n");
    return NULL;
  }

  acc->unban_time = 0;
  acc->expiration_time = 0;

  if (!safe_str_copy(acc->userid, USER_ID_LENGTH, userid)) {
    log_message(LOG_ERROR, "[account_create]: Failed to securely copy user provided userid string into acc struct.\n");
    account_free(acc);
    return NULL;
  }

  if (crypto_pwhash_str(acc->password_hash, plaintext_password, strnlen(plaintext_password, MAX_PW_LEN), OPSLIMIT, MEMLIMIT) != 0) {
    log_message(LOG_ERROR, "[account_create]: Failed to securely hash password with crypto_pwhash_str().\n");
    account_free(acc);
    return NULL;
  }

  if (!safe_str_copy(acc->email, EMAIL_LENGTH, email)) {
    log_message(LOG_ERROR, "[account_create]: Failed to securely copy user provided email string into acc struct.\n");
    account_free(acc);
    return NULL;
  }

  if (!safe_str_copy(acc->birthdate,BIRTHDATE_LENGTH, birthdate)) {
    log_message(LOG_ERROR, "[account_create]: Failed to securely copy user provided birthdate string into acc struct.\n");
    account_free(acc);
    return NULL;
  }

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
  if (!acc){
    return;
  }

  sodium_memzero(acc, sizeof *acc);

  free(acc);
}

/**
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
      log_message(LOG_ERROR,"[account_set_email]: Null argument");
      return;
  }
  if (!check_email(new_email)) {
      log_message( LOG_ERROR,"[account_set_email]: Invalid email format");
      return;
  }
  size_t len = strnlen(new_email, MAX_EMAIL_LEN);
  if (len >= EMAIL_LENGTH) {
      log_message(LOG_ERROR,"[account_set_email]: Email too long");
      return;
  }
  char new_buf[EMAIL_LENGTH];
  memset(new_buf, 0, EMAIL_LENGTH); 
  memcpy(new_buf, new_email, len + 1); //TODO: Use memmove(), memcpy (unsafe)
  memcpy(acc->email, new_buf, EMAIL_LENGTH);  //TODO: Use memmove(), memcpy (unsafe)
}

/**
 * @brief Verfies a users password against the stored hash.
 *
 * The function will validate the provided plaintext password agaisnt the stored password hash.
 * Using the account_t structure, with Libsodium package - Argon2 (crypto_pwhash_str_verify) for password verification.
 * It performs input validation (for injections) and uses memory locking as an additional layer of security to minimise chance of memory dump exposure/attack. 
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
  if (sodium_init() < 0) {
    log_message(LOG_ERROR, "[account_validate_password]: Failed to intialise Libsodium library.\n");
    return false;
  }

  if (!validate_password(plaintext_password)) {
    log_message(LOG_ERROR, "[account_validate_password]: User's plaintext password does not meet secure desired password properties.\n");
    return false;
  }

  char secure_pw[MAX_PW_LEN];

  if (sodium_mlock(secure_pw, sizeof(secure_pw)) != 0) {
    log_message(LOG_ERROR, "[account_validate_password]: Failed to lock memory for password.\n");
    return false;
  }

  if (!safe_str_copy(secure_pw, sizeof(secure_pw), plaintext_password)) {
    log_message(LOG_ERROR, "[account_validate_password]: Failed to securely copy password into memory.\n");
    sodium_munlock(secure_pw, sizeof(secure_pw));
    return false;
  }

  int result = crypto_pwhash_str_verify(acc->password_hash, secure_pw, strnlen(secure_pw, MAX_PW_LEN));

  sodium_munlock(secure_pw, sizeof(secure_pw));
  sodium_memzero(secure_pw, sizeof(secure_pw));

  if (result == 0) {
    log_message(LOG_INFO, "[account_validate_password]: Password validated successfully for user '%s'.\n", acc->userid);
    return true;
  } 

  else {
    log_message(LOG_ERROR, "[account_validate_password]: Password validation failed for user '%s'.\n", acc->userid);
    return false;
  }
}

/**
 * @brief Updates the user's stored password hash with the new password provided
 *
 * The function will generate a new hash from the new password provided by user and update the stored password hash in account_t structure acc.
 * Using the account_t structure, with Libsodium package - Argon2 (crypto_pwhash_str) for password hash generation.
 * It performs input validation (for injections) and uses memory locking as an additional layer of security to minimise chance of memory dump exposure/attack. 
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
      log_message(LOG_ERROR, "[account_update_password]: Failed to intialise Libsodium library.\n");
      return false;
  }

  if (!validate_password(new_plaintext_password)) {
      log_message(LOG_ERROR, "[account_update_password]: New plaintext password does not meet secure desired password properties.\n");
      return false;
  }

  char new_secure_pw[MAX_PW_LEN];

  if (sodium_mlock(new_secure_pw, sizeof(new_secure_pw)) != 0) {
      log_message(LOG_ERROR, "[account_update_password]: Failed to lock memory for new password.\n");
      return false;
  }

  if (!safe_str_copy(new_secure_pw, sizeof(new_secure_pw), new_plaintext_password)) {
      log_message(LOG_ERROR, "[account_update_password]: Failed to securely copy new password into memory.\n");
      sodium_munlock(new_secure_pw, sizeof(new_secure_pw));
      sodium_memzero(new_secure_pw, sizeof(new_secure_pw));
      return false;
  }

  int result = crypto_pwhash_str(acc->password_hash, new_secure_pw, strnlen(new_secure_pw, MAX_PW_LEN), OPSLIMIT, MEMLIMIT);

  sodium_munlock(new_secure_pw, sizeof(new_secure_pw));
  sodium_memzero(new_secure_pw, sizeof(new_secure_pw));

  if (result == 0) {
      log_message(LOG_INFO, "[account_update_password]: Password updated successfully for user '%s'.\n", acc->userid);
      return true;
  } else {
      log_message(LOG_ERROR, "[account_update_password]: Password update failed for user '%s'.\n", acc->userid);
      return false;
  }
}

/**
* @brief Records a successful login attempt for a user account. //TODO: Add on the documentation block comments, remove the Covers:.... , provide more details on what this function does
*
* - Validates all input.
* - Logs IP and time with user context.
* - Resets failure counter securely.
*
* Covers: auditing (Lab 3), logging format (Lab 7), defensive programming.
*/
static void format_time(time_t t, char *buffer, size_t len) {
  if (!buffer || len == 0) return;
  struct tm *tm_info = localtime(&t);
  if (!tm_info || strftime(buffer, len, "%Y-%m-%d %H:%M:%S", tm_info) == 0) {
      strncpy(buffer, "unavailable", len - 1); //TODO: Use strcpy_s, strncpy (unsafe)
      buffer[len - 1] = '\0';
  }
}

void account_record_login_success(account_t *acc, ip4_addr_t ip) {
  if (!acc) {
      log_message(LOG_ERROR, "[account_record_login_success]: NULL account pointer.\n");
      return;
  }

  char ip_str[INET_ADDRSTRLEN] = {0};
  if (!inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN)) {
      log_message(LOG_WARN, "[account_record_login_success]: Failed to convert IP for user '%s'.\n", acc->userid);
      strncpy(ip_str, "unknown", sizeof(ip_str) - 1); //TODO: Use strcpy_s, strncpy (unsafe)
  }

  char time_str[MAX_TIME_STR_LEN] = {0};
  format_time(time(NULL), time_str, sizeof(time_str));

  acc->last_ip = ip;
  acc->last_login_time = time(NULL);
  acc->login_fail_count = 0;

  log_message(LOG_INFO,
      "[account_record_login_success]: User '%s' successfully logged in from IP '%s' at '%s'.\n",
      acc->userid, ip_str, time_str);
}


/**
 * @brief Records a failed login attempt for a user account.
 *
 * Increments the login failure counter in the account struct, logs the failure,
 * and ensures the count does not exceed UINT_MAX to avoid overflow.
 *
 * @param acc Pointer to a valid account_t structure.
 * 
 * @note If acc is NULL, the function logs an error and exits early.
 * 
 * @covers Lab 3 (defensive programming), Lab 4 (safe integers), Lab 7 (secure logging).
 */

 void account_record_login_failure(account_t *acc) {
  if (!acc) {
      log_message(LOG_ERROR, "[account_record_login_failure]: NULL account pointer received.\n");
      return;
  }

  if (acc->login_fail_count == UINT_MAX) {
      log_message(LOG_WARN, "[account_record_login_failure]: Max failure count reached for user '%s'.\n", acc->userid);
      return;
  }

  acc->login_fail_count++;
  log_message(LOG_INFO, "[account_record_login_failure]: Failure #%u for user '%s'.\n",
              acc->login_fail_count, acc->userid);
}

/**
 * Checks if the account is currently banned.
 *
 * Compares the current system time to the account's unban time.
 * If unban_time is in the future, the account is considered banned.
 *
 * @param acc A pointer to the account_t structure, which contains the unban_time field indicating the ban expiration time.
 * 
 * @pre acc must be non-NULL.
 *
 * @return true if the account is banned, false otherwise.
 */

 bool account_is_banned(const account_t *acc) {
  if (acc == NULL) {
    log_message(LOG_ERROR, "[account_is_banned]: NULL account pointer received, either account does not exist.\n");
    return true;
  }

  if (acc->unban_time == 0) {
    log_message(LOG_INFO, "[account_is_banned]: Account is not banned.\n");
    return false;
  }

  time_t current_time = time(NULL);
  if (current_time == (time_t)-1) {
    log_message(LOG_ERROR, "[account_is_banned]: Current time not available.\n");
    return true;
  }

  return acc->unban_time > current_time;
}

/**
 * Checks if the account is currently expired.
 *
 * Compares the current system time to the account's expiration time.
 * If expiration_time is in the past, the account is considered expired.
 *
 * @param acc A pointer to the account_t structure, which contains the expiration_time field indicating the account's expiration time.
 * 
 * @pre acc must be non-NULL.
 *
 * @return true if the account is expired, false otherwise.
 */

bool account_is_expired(const account_t *acc) {
  // Reason: 
  if (acc == NULL) {
    log_message(LOG_ERROR, "[account_is_expired]: NULL account pointer received.\n");
    return true;
  }

  if (acc->expiration_time == 0) {
    return false;
  }

  // Reason: 
  time_t current_time = time(NULL);
  if (current_time == (time_t)-1) {
      log_message(LOG_ERROR, "[account_is_expired]: Current time not available.\n");
      return true;
  }

  return acc->expiration_time < current_time; 
}

/**
 * Sets the account's unban time to the given duration.
 *
 * @param acc A pointer to the account_t structure.
 * @param t The number of seconds from now until the ban should expire.
 *
 * @pre acc must be non-NULL.
 */
void account_set_unban_time(account_t *acc, time_t t) {
  if (acc == NULL) {
    log_message(LOG_ERROR, "[account_set_unban_time]: NULL account pointer received.\n");
    return;
  }

  if (t < 0) {
    log_message(LOG_WARN, "[account_set_unban_time]: Negative duration provided; unban_time not updated.\n");
    return;
  }

  if (t == 0) {
    acc->unban_time = 0;
  } else {

    time_t current_time = time(NULL);
    if (current_time == (time_t)-1) {
        log_message(LOG_ERROR, "[account_set_unban_time]: Current time not available.\n");
        return;
    }

    if (t > MAX_DURATION) {
      log_message(LOG_WARN, "[account_set_unban_time]: Duration exceeds maximum limit, setting to max duration.\n");
      t = MAX_DURATION;
    }

    acc->unban_time = current_time + t;
  }
}

/**
 * Sets the account's expiration time to the given duration.
 *
 * @param acc A pointer to the account_t structure.
 * @param t The number of seconds from now until the account should expire.
 *
 * @pre acc must be non-NULL.
 */

void account_set_expiration_time(account_t *acc, time_t t) {
  if (acc == NULL) {
    log_message(LOG_ERROR, "[account_set_expiration_time]: NULL account pointer received.\n");
    return;
  }

  if (t < 0) {
    log_message(LOG_WARN, "[account_set_expiration_time]: Negative duration provided; expiration_time not updated.\n");
    return;
  }

  if (t == 0) {
    acc->expiration_time = 0;
  } else {

    time_t current_time = time(NULL);
    if (current_time == (time_t)-1) {
        log_message(LOG_ERROR, "[account_set_expiration_time]: Current time not available.\n");
        return;
    }

    if (t > MAX_DURATION) {
      log_message(LOG_WARN, "[account_set_expiration_time]: Duration exceeds maximum limit, setting to max duration.\n");
      t = MAX_DURATION;
    }

    acc->expiration_time = current_time + t;
  }
}

/**
 * @brief Print a detailed summary of a user's account to the specified file descriptor. //TODO: Modify the documentation block. 
 *
 * - Includes user ID, email, birthdate, failures, last login IP/time.
 * - All write operations are protected.
 * - Logs result.
 *
 * Covers: structured output (Lab 3), robust I/O (Lab 5), test logging (Lab 7).
 */
 static void format_ip(ip4_addr_t ip, char *buffer, size_t len) {
  if (!buffer || len == 0) return;
  if (!inet_ntop(AF_INET, &ip, buffer, len)) {
      strncpy(buffer, "unavailable", len - 1); //TODO: Use strcpy_s, strncpy (unsafe)
      buffer[len - 1] = '\0';
  }
}


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

  //TODO: IF YOU WANT TO USE SNPRINTF, YOU HAVE TO CHECK THE RETURN VALUE IF IT"S INTENDED (SNPRINTF CAN CAUSE TRUNCATION OF CODE)

  snprintf(line, sizeof(line), "User ID         : %s\n", acct->userid); 
  if ((written = write(fd, line, strlen(line))) < 0) return false;      //TODO: Use strnlen , strlen (unsafe)

  snprintf(line, sizeof(line), "Email           : %s\n", acct->email);
  if ((written = write(fd, line, strlen(line))) < 0) return false;     //TODO: Use strnlen , strlen (unsafe)

  snprintf(line, sizeof(line), "Birthdate       : %s\n", acct->birthdate); 
  if ((written = write(fd, line, strlen(line))) < 0) return false;         //TODO: Use strnlen , strlen (unsafe)

  snprintf(line, sizeof(line), "Login Failures  : %u\n", acct->login_fail_count);
  if ((written = write(fd, line, strlen(line))) < 0) return false;                //TODO: Use strnlen , strlen (unsafe)

  char ip_str[INET_ADDRSTRLEN] = "unavailable";
  format_ip(acct->last_ip, ip_str, sizeof(ip_str));
  snprintf(line, sizeof(line), "Last Login IP   : %s\n", ip_str); 
  if ((written = write(fd, line, strlen(line))) < 0) return false; //TODO: Use strnlen , strlen (unsafe)

  char time_str[MAX_TIME_STR_LEN] = "unavailable";
  format_time(acct->last_login_time, time_str, sizeof(time_str));
  snprintf(line, sizeof(line), "Last Login Time : %s\n", time_str); 
  if ((written = write(fd, line, strlen(line))) < 0) return false;  //TODO: Use strnlen , strlen (unsafe)

  log_message(LOG_INFO, "[account_print_summary]: Printed summary for user '%s'.", acct->userid);
  return true;
}


