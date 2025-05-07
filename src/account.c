/**
 * @file account.c
 * @brief Implements account-related functionality including creation, validation, and secure password handling using libsodium.
 *
 * This file contains functions for managing user accounts, including validating
 * email and birthdate formats, enforcing strong password rules, and securely
 * hashing and verifying passwords. It relies on the libsodium library for cryptographic
 * operations and includes logging for error diagnosis.
 *
 * @author Div Sharma [23810783]
 * @author Pranav Rajput [23736075]
 * @author William Lo [23722943]
 * @author Zachary Wang [24648002]
 * @author Jun Hao Dennis Lou [23067779]
 *
 * @bug No known bugs.
 */

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
 * @brief Validates an email address string.
 *
 * This function checks whether a given email string meets the formatting criteria:
 * - Email mustcontain exactly one '@' symbol.
 * - Before the "@" symbol, the values must not be empty and contain only valid characters.
 * - After the "@" symbol, it must contain at least one '.' and contain only valid characters.
 * - Entire Email string must be ASCII-printable and within defined length limits.
 *
 * @param email A null-terminated string representing the email address to validate.
 *
 * @pre `email` must not be NULL or empty.
 * @pre `MAX_EMAIL_LEN` and `EMAIL_LENGTH` must be properly defined.
 *
 * @post Returns true if the email passes all structural and character validity checks, otherwise, false.
 *
 * @return `true` if the input string is a valid email address; `false` if any format rule is violated.
 */

static bool check_email(const char *email){
  if(!email){
    return false;
  }

  size_t len = strnlen(email, MAX_EMAIL_LEN); 

  if (len ==0 || len >= EMAIL_LENGTH){
    return false;
  }

  const char *at = strchr(email, '@');

  if(!at || at == email || at == email + len - 1){
    return false;
  }

  if (strchr(at+1,'@')){
    return false;
  } 

  size_t loc_len = (size_t)(at - email);

  if(loc_len == 0){
    return false;
  }

  const char *dom = at + 1;
  const char *dot = strchr(dom, '.');

  if(!dot || dot == dom || dot == email + len - 1){
    return false;
  } 
  
  for (size_t i = 0; i < len; ++i) {

    unsigned char c = (unsigned char)email[i];

    if (c <= ' ' || c >= 127){
      return false;
    } 

    if (i < loc_len) {
        if (!(isalnum(c) || c == '.' || c == '_' || c == '-' || c == '+')){
          return false;
        }
    } 
    else if (email[i] == '@') {
        continue;
    } 
    else {
        if (!(isalnum(c) || c == '.' || c == '-')) return false;
    }
  }
  return true;
}

/**
 * @brief Validates that a birthdate string conforms to the format "YYYY-MM-DD".
 *
 * This function does the following:
 * - Check digit characters in the expected positions for year, month, and day.
 * - Check it contains hyphens (`-`) in the 5th and 8th character positions (index 4 and 7).
 * - Check that `BIRTHDATE_LENGTH` is exactly specified characters long and ends with null terminator.
 *
 * @note No range or logical validation (e.g., leap year, valid days/months) is performed.
 *
 * @param birthdate A null-terminated string representing the birthdate in the form "YYYY-MM-DD".
 *
 * @pre `birthdate` must not be NULL.
 * @pre `BIRTHDATE_LENGTH` must equal 10 + 1 (for null byte) (i.e., the length of "YYYY-MM-DD\0").
 *
 * @post Returns true if the string matches the required birthdate pattern, otherwise, false.
 *
 * @return `true` if the birthdate string is in valid format; `false` if structure of email/other conditions are violated.
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
 * @brief Validates a user-provided password against defined set of desirable password properties.
 *
 * This function does the following:
 * - Enforce length of the password must be between `MIN_PW_LEN` and `MAX_PW_LEN` characters.
 * - Enforce password to contain at least one uppercase letter, one lowercase letter, one digit, and one special character.
 * - Enforce password to not contain blacklisted characters typically associated with injection attacks 
 * (e.g., OS commands, SQL, XSS, path traversal).
 * - Check and log for any errors (failures/success) for auditing and debugging purposes.
 *
 * @param password_provided A null-terminated string representing the user's input password.
 *
 * @pre `password_provided` must not be NULL or empty.
 * @pre `MIN_PW_LEN` and `MAX_PW_LEN` must be properly defined.
 *
 * @post Returns `true` if the password passes all checks; otherwise, log an error and return false.
 *
 * @return `true` if the password is valid and secure according to the defined policy; `false` if any condition is violated.
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
 * @brief Safely copies a string into a destination buffer with truncation protection.
 *
 * This function does the following:
 * - Use `snprintf()` to copy a source string (`src`) into a destination buffer (`dst`) to capture that the buffer did not overflow. 
 * - Provide log errors if any has occured during the copying or if truncation occurs. 
 *
 * @param dst Pointer to the destination character buffer.
 * @param dst_size The size of the destination buffer in bytes.
 * @param src Null-terminated source string to copy from.
 *
 * @pre `dst` and `src` must not be NULL.
 * @pre `dst_size` must be greater than 0.
 * @pre acc struct defined length constraints must be properly declared and enforced.
 *
 * @post Return 'true' if `dst` will contain a completed null-terminated copy of `src`.
 *
 * @return `true` if the string was successfully copied without truncation; `false` if error occurs or truncation has happened.
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

/**
 * @brief Converts a `time_t` value into a human-readable date-time string.
 *
 * This function does the following:
 * - Format a given `time_t` value into the format "YYYY-MM-DD HH:MM:SS"
 * - Stores the result in the provided output buffer using `safe_str_copy()`. 
 * - Provide log errors if format of input failed or is invalid.  
 *
 * @param t The time value to be formatted.
 * @param buffer A pointer to the output character buffer where the formatted string will be stored.
 * @param len The length of the output buffer in bytes.
 *
 * @pre `buffer` must not be NULL and `len` must be greater than 0.
 * @post On success, the `buffer` contains a null-terminated timestamp string. On failure, the `buffer` contains the string `"unavailable"`.
 * 
 * @return None.
 */

static void format_time(time_t t, char *buffer, size_t len) {
  if (!buffer || len == 0) {
    return;
  }

  struct tm *tm_info = localtime(&t);
  if (!tm_info || strftime(buffer, len, "%Y-%m-%d %H:%M:%S", tm_info) == 0) {
      if (!safe_str_copy(buffer, len, "unavailable")) {
          log_message(LOG_ERROR, "[format_time]: Failed to copy fallback string into buffer.\n");
      }
  }
}

/**
 * @brief Converts an IPv4 address into a human-readable dotted-decimal string.
 *
 * This function does the following:
 *  attempts to convert a given `ip4_addr_t` address into a string representation
 * (e.g., "192.168.1.1") using `inet_ntop()`. 
 * - If conversion fails, it safely writes the fallback string `"unavailable"` into the buffer using `safe_str_copy()`. 
 *
 * @param ip The IPv4 address to convert.
 * @param buffer Pointer to the character buffer where the resulting string will be written.
 * @param len The size of the destination buffer in bytes.
 *
 * @pre `buffer` must not be NULL.
 * @pre `len` must be greater than 0.
 *
 * @post On success, `buffer` contains the null-terminated string form of the IP address. On failure, it contains the string `"unavailable"` if copying succeeds.
 *
 * @return None.
 */

static void format_ip(ip4_addr_t ip, char *buffer, size_t len) {
  if (!buffer || len == 0) {
      return;
  }

  if (!inet_ntop(AF_INET, &ip, buffer, len)) {
    if (!safe_str_copy(buffer, len, "unavailable")) {
        log_message(LOG_ERROR, "[format_ip]: Failed to copy fallback IP string.\n");
    }
  }
}

/**
 * @brief Creates and initializes a new user account with validated and securely stored data.
 *
 * This function performs the following:
 * - Validates all input parameters (user ID, password, email, and birthdate).
 * - Enforces password security requirements.
 * - Validates email and birthdate format.
 * - Initializes Libsodium for cryptographic operations.
 * - Allocates and populates a new `account_t` structure.
 * - Hashes and converts plaintext_password to a hashed version using `crypto_pwhash_str()`.
 * - Securely copies strings into fixed-size buffers with truncation protection.
 *
 * If any validation or operation fails, an error is logged and `NULL` is returned. 
 *
 * @param userid A null-terminated string representing the user ID.
 * @param plaintext_password A null-terminated string representing the user's password in plaintext.
 * @param email A null-terminated string representing the user's email address.
 * @param birthdate A null-terminated string in "YYYY-MM-DD" format representing the user's birthdate.
 *
 * @pre All input pointers must be non-NULL.
 * @pre `sodium_init()` must succeed before using Libsodium cryptographic functions.
 * @pre Constants `USER_ID_LENGTH`, `MAX_PW_LEN`, `EMAIL_LENGTH`, and `BIRTHDATE_LENGTH` must be properly defined.
 *
 * @post On success, a heap-allocated `account_t` structure is returned, containing securely copied and hashed data. On failure, appropriate error is logged and null is returned.
 *
 * @return 'true' if pointer to a newly allocated and initialized `account_t` struct on success; 'false if `NULL` or any validation/operation fails.
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
 * @brief Securely deallocates and wipes an `account_t` structure from memory.
 *
 * This function performs the following: 
 * - Log successful access to the structure.
 * - Securely erase its contents using `sodium_memzero()`.
 * - Free the allocated memory.
 *
 *
 * @param acc Pointer to the `account_t` structure to be securely freed.
 *
 * @pre `acc` must either be NULL or points to a valid `account_t` struct.
 *
 * @post If `acc` is non-NULL then its contents will be wiped securely and memory freed.
 *
 * @return None.
 */

void account_free(account_t *acc) {
  if (!acc){
    log_message(LOG_ERROR, "[account_free]: Failed to open account_t struct, it must not be NULL.\n");
  }
  else{
    log_message(LOG_ERROR, "[account_free]: Account struct found. Proceeding to securely erase data and free memory.\n");
    sodium_memzero(acc, sizeof *acc);
    free(acc);
  }
}

/**
 * @brief Provide user function to updates the email field of an existing `account_t` structure.
 *
 * This function performs the following:
 * - checks for null inputs
 * - validates the format of the new email string using `check_email()`.
 * - Once validated, securely copy it into acc->email to update new value.
 *
 * @param acc Pointer to the `account_t` structure whose email should be updated.
 * @param new_email A null-terminated string representing the new email address.
 *
 * @pre `acc` and `new_email` must not be NULL.
 * @pre `new_email` must pass format validation via `check_email()`.
 * @pre `MAX_EMAIL_LEN` and `EMAIL_LENGTH` must be defined and consistent.
 *
 * @post If validation succeeds, `acc->email` is updated with the new value; otherwise, the original email remains unchanged.
 *
 * @return None.
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

  if(!safe_str_copy(acc->email, EMAIL_LENGTH, new_email)) {
    log_message(LOG_ERROR,"[account_set_email]: Failed to update email to due copy failure.\n");
  }

  log_message(LOG_INFO, "[account_set_email]: Email has been successfully updated.\n");
}

/**
 * @brief Validates a user's plaintext password against the stored password hash.
 *
 * This function performs the following:
 * - Check that Libsodium library (if not already initialized).
 * - Check provided plaintext password meets password policy in `validate_password()`.
 * - Locks memory for the password buffer using `sodium_mlock()` to prevent it from being swapped.
 * - Securely copies the password into the locked buffer.
 * - Verifies the password against the stored hash in the `account_t` structure using libsodium's - `crypto_pwhash_str_verify()`.
 * - Cleans and unlocks the memory after verification.
 * - Log all major events (failures/success) for auditing and debugging.
 *
 * @param acc Pointer to a valid `account_t` structure containing the stored password hash.
 * @param plaintext_password A null-terminated string representing the user-provided password to validate.
 *
 * @pre `acc` and `plaintext_password` must not be NULL.
 * @pre `sodium_init()` must succeed prior to cryptographic operations.
 * @pre `plaintext_password` must pass internal policy checks via `validate_password()`.
 *
 * @post On success, securely unlocks and clears the password buffer and return `true`. On failure, record log error and reutrn `false`.
 *
 * @return `true` if the plaintext password matches the stored hash; otherwise, `false`.
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
 * @brief Updates the stored password hash in an `account_t` structure with a new plaintext password provided from user.
 *
 * This function performs the following:
 * - Check new password meets defined security policies.
 * - Locking memory using `sodium_mlock()` to protect the password buffer.
 * - Copying the password into the secure buffer using `safe_str_copy()`.
 * - Hashing the new plaintext password provided using `crypto_pwhash_str()`.
 * - Clean and unlock memory to remove residual sensitive data.
 * - Log all major events (failures/success) for auditing and debugging.
 *
 * @param acc Pointer to the `account_t` structure whose password will be updated.
 * @param new_plaintext_password Null-terminated string representing the new user-provided password.
 *
 * @pre `acc` and `new_plaintext_password` must not be NULL.
 * @pre `sodium_init()` must succeed before any cryptographic operations.
 * @pre `new_plaintext_password` must pass internal validation via `validate_password()`.
 *
 * @post If successful, `acc->password_hash` is updated with the new securely hashed password.
 *       The password buffer is securely wiped and unlocked regardless of outcome.
 *
 * @return `true` if the password was successfully updated and hashed; 
 *         `false` if validation, memory protection, or hashing fails.
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
 * @brief Records a successful login for a user account, updating metadata and logging the event.
 *
 * This function updates the given `account_t` structure to reflect a successful login event by:
 * - Storing the current time in `last_login_time`.
 * - Saving the provided IPv4 address to `last_ip`.
 * - Resetting the `login_fail_count` to zero.
 *
 * It converts the IP address to a readable string using `inet_ntop()` and formats the timestamp using `format_time()`.
 * If IP conversion fails, it falls back to the string `"unknown"` using `safe_str_copy()`. Errors and successes are
 * logged to aid in debugging and auditing.
 *
 * @param acc Pointer to the `account_t` structure representing the authenticated user.
 * @param ip  The IPv4 address (`ip4_addr_t`) from which the login occurred.
 *
 * @pre `acc` must not be NULL.
 *
 * @post The account's `last_login_time`, `last_ip`, and `login_fail_count` fields are updated. Log entries are provided to indicate the time and IP of the login event.
 *
 * @return None.
 */

void account_record_login_success(account_t *acc, ip4_addr_t ip) {
  if (!acc) {
      log_message(LOG_ERROR, "[account_record_login_success]: NULL account pointer.\n");
      return;
  }

  char ip_str[INET_ADDRSTRLEN] = {0};
  if (!inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN)) {
      log_message(LOG_WARN, "[account_record_login_success]: Failed to convert IP for user '%s'.\n", acc->userid);
      if (!safe_str_copy(ip_str, sizeof(ip_str), "unknown")) {
          log_message(LOG_ERROR, "[account_record_login_success]: Failed to copy fallback IP string.\n");
      }
  }

  char time_str[MAX_TIME_STR_LEN] = {0};
  format_time(time(NULL), time_str, sizeof(time_str));

  acc->last_ip = ip;
  acc->last_login_time = time(NULL);
  acc->login_fail_count = 0;

  log_message(LOG_INFO,
    "[account_record_login_success]: User '%s' successfully logged in from IP '%s' at '%s'.\n",acc->userid, ip_str, time_str);
}


/**
 * @brief Records a failed login attempt for the specified user account.
 *
 * This function increments the `login_fail_count` field in the given `account_t` structure.
 * It also logs the failed attempt, including the user ID and current failure count.
 * If the failure count has reached `UINT_MAX`, no further increment is performed and a warning is logged instead.
 *
 * @param acc Pointer to the `account_t` structure associated with the login attempt.
 *
 * @pre `acc` must not be NULL.
 *
 * @post If `login_fail_count` is less than `UINT_MAX`, it is incremented by one. Log entry is created.
 *
 * @return None.
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

  log_message(LOG_INFO, "[account_record_login_failure]: Failure #%u for user '%s'.\n", acc->login_fail_count, acc->userid);
}

 /**
 * @brief Checks whether a user account is currently banned based on the unban timestamp.
 *
 * This function determines if an account is banned by comparing the current time with
 * the `unban_time` field in the `account_t` structure:
 * - If `unban_time` is 0, the account is considered not banned.
 * - If the current time is not retrievable, the function conservatively returns `true`.
 * - Otherwise, the function returns `true` if the unban time is still in the future.
 *
 *
 * @param acc Pointer to the `account_t` structure to check.
 *
 * @pre `acc` must not be NULL.
 *
 * @post Logs the result of the ban check and returns the appropriate boolean value.
 *
 * @return `true` if the account is banned (i.e., `unban_time` is in the future), `false` if the account is NULL or the current time cannot be determined;
 *         
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
 * @brief Determines whether a user account has expired based on the expiration timestamp.
 *
 * This function checks if the `expiration_time` field in the given `account_t` structure
 * indicates that the account is no longer valid:
 * - If `expiration_time` is 0, the account is considered non-expiring and active.
 * - If the current system time cannot be retrieved, the function conservatively returns `true`.
 * - Otherwise, it returns `true` if the expiration time is earlier than the current time.
 *
 * Logging is performed to handle and report null account pointers and system time retrieval failures.
 *
 * @param acc Pointer to the `account_t` structure to check for expiration.
 *
 * @pre `acc` must not be NULL.
 *
 * @post Logs an error if the account pointer is NULL or if the current time cannot be retrieved.
 *
 * @return `true` if the account is expired, if the account is NULL, or if the current time is unavailable; `false` otherwise.
 */

bool account_is_expired(const account_t *acc) {
  if (acc == NULL) {
    log_message(LOG_ERROR, "[account_is_expired]: NULL account pointer received.\n");
    return true;
  }

  if (acc->expiration_time == 0) {
    return false;
  }

  time_t current_time = time(NULL);
  if (current_time == (time_t)-1) {
      log_message(LOG_ERROR, "[account_is_expired]: Current time not available.\n");
      return true;
  }

  return acc->expiration_time < current_time; 
}

/**
 * @brief Sets the unban time for a user account based on a duration from the current time.
 *
 * This function updates the `unban_time` field in the `account_t` structure as follows:
 * - If `t == 0`, the ban is cleared (`unban_time` is set to 0).
 * - If `t > 0`, it adds the duration `t` (in seconds) to the current system time.
 * - If `t` exceeds `MAX_DURATION`, it is clamped to `MAX_DURATION` and a warning is logged.
 *
 * @param acc Pointer to the `account_t` structure to update.
 * @param t Duration in seconds to set as the remaining ban time. Use 0 to remove the ban.
 *
 * @pre `acc` must not be NULL.
 * @pre `MAX_DURATION` must be defined.
 *
 * @post Updates `acc->unban_time` based on the specified duration and current time. 
 *
 * @return None.
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
 * @brief Sets the expiration time for a user account based on a duration from the current time.
 *
 * This function sets the `expiration_time` field in the given `account_t` structure:
 * - If `t == 0`, the account is set to never expire (`expiration_time` is set to 0).
 * - If `t > 0`, it adds the duration `t` (in seconds) to the current time and sets it as the expiration time.
 * - If `t > MAX_DURATION`, it is clamped to `MAX_DURATION` and a warning is logged.
 *
 * @param acc Pointer to the `account_t` structure whose expiration time should be updated.
 * @param t Duration in seconds from the current time after which the account should expire. Use 0 to disable expiration.
 *
 * @pre `acc` must not be NULL.
 * @pre `MAX_DURATION` must be defined.
 *
 * @post If valid, updates `acc->expiration_time` based on the current time and duration. Otherwise, no change occurs.
 *
 * @return None.
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


