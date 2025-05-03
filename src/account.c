#define _POSIX_C_SOURCE 200809L
#define MAX_PW_LEN 128 
#define OPSLIMIT crypto_pwhash_OPSLIMIT_INTERACTIVE
#define MEMLIMIT crypto_pwhash_MEMLIMIT_INTERACTIVE

#include "account.h"
#include "logging.h" 

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

static bool check_email(const char *email){
  if(!email) return false;
  size_t len = strlen(email);
  //must fit and not be empty
  if (len ==0 || len >= EMAIL_LENGTH) return false;
  const char *at = strchr(email, '@');
  //must contain exactly one @
  if(!at || at == email || at == email + len - 1) return false;
  if (strchr(at+1,'@')) return false;

  size_t loc_len = (size_t)(at - email);
  if(loc_len == 0) return false;
  const char *dom = at + 1;
  const char *dot = strchr(dom, '.');
  if(!dot || dot == dom || dot == email + len - 1) return false;

  //goes through whether its an allowed char
  
  for (size_t i = 0; i < len; ++i) {
    unsigned char c = (unsigned char)email[i];
    if (c <= ' ' || c >= 127) return false;
    if (i < local_len) {
        if (!(isalnum(c) || c == '.' || c == '_' || c == '-' || c == '+')) return false;
    } else if (email[i] == '@') {
        continue;
    } else {
        if (!(isalnum(c) || c == '.' || c == '-')) return false;
    }
}
return true;
}
// checks for yyyy-mm-dd format
static bool check_birthdate(const char *birthdate) {
  if (!birthdate) return false;
  for (size_t i = 0; i < BIRTHDATE_LENGTH; ++i) {
      if ((i == 4 || i == 7)) {
          if (birthdate[i] != '-') return false;
      } else if (!isdigit((unsigned char)birthdate[i])) {
          return false;
      }
  }
  // ensure no extra characters
  return birthdate[BIRTHDATE_LENGTH] == '\0';
}

//initi lib sodium
static bool init_libsodium(void) {
  static bool initialized = false;
  if (!initialized) {
      if (libsodium_init() < 0) {
          log_message("init_sodium: sodium_init failed");
          return false;
      }
      initialized = true;
  }
  return true;
}


account_t *account_create(const char *userid, const char *plaintext_password,
                          const char *email, const char *birthdate
                      )
              
{
  if (!userid || !plaintext_password || !email || !birthdate) {
    log_message("account_create: null argument");
    return NULL;
}
size_t pw_len = strlen(plaintext_password);
if (pw_len < MIN_PASSWORD_LENGTH) {
    log_message("account_create: password too short");
    return NULL;
}
if (!check_email(email)) {
    log_message("account_create: invalid email format");
    return NULL;
}
if (!check_birthdate(birthdate)) {
    log_message("account_create: invalid birthdate format");
    return NULL;
}
if (!init_sodium()) {
    log_message("account_create: libsodium init failed");
    return NULL;
}
account_t *acc = calloc(1, sizeof(account_t));
if (!acc) {
    log_message("account_create: allocation failed");
    return NULL;
}
// Copy user ID
strncpy(acc->userid, userid, USER_ID_LENGTH - 1);
acc->userid[USER_ID_LENGTH - 1] = '\0';
// Hash password (Argon2id, moderate limits)
if (crypto_pwhash_str(acc->password_hash,
                      plaintext_password,
                      pw_len,
                      crypto_pwhash_OPSLIMIT_MODERATE,
                      crypto_pwhash_MEMLIMIT_MODERATE) != 0) {
    log_message("account_create: password hashing failed");
    free(acc);
    return NULL;
}
// Store email safely
memset(acc->email, 0, EMAIL_LENGTH);
strncpy(acc->email, email, EMAIL_LENGTH - 1);
// Store birthdate exactly
memcpy(acc->birthdate, birthdate, BIRTHDATE_LENGTH);
acc->birthdate[BIRTHDATE_LENGTH] = '\0';
return acc;
}


void account_free(account_t *acc) {
  if (!acc) return;
  // Wipe sensitive data in the struct before freeing
  sodium_memzero(acc, sizeof *acc);
  free(acc);
}


void account_set_email(account_t *acc, const char *new_email) {
if (!acc || !new_email) {
    log_message("account_set_email: null argument");
    return;
}
if (!check_email(new_email)) {
    log_message("account_set_email: invalid email format");
    return;
}
size_t len = strlen(new_email);
if (len >= EMAIL_LENGTH) {
    log_message("account_set_email: email too long");
    return;
}
// Atomic update
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
  //Ensure that libsodium library must be initialised first otherwise return false/quit function 
  if (sodium_init() < 0) {
      log_message(LOG_ERROR,"[account_validate_password]: Libsodium library initialisation has failed");
      return false;
  }
  
  //Precondition 1: Acc and plaintext_password cannot be NULL
  //Side Question: This validation now is just refering to the pointer/memory location of acc, that it cannot be null
  //Should I also add on validation for the variables inside the structure, e.g. if acc -> email == NULL, etc... 
  if (acc == NULL || plaintext_password == NULL)
  {
    log_message(LOG_ERROR,"[account_validate_password]: NULL input detected for acc and plaintext_password");
    return false;
  } 

  //Precondition 2: Plaintext_password must be valid and have null-terminated string.
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

  //Copy over the secure_pw, which has been memory locked and add in a null byte
  strncpy(secure_pw, plaintext_password, sizeof(secure_pw) - 1);
  secure_pw[sizeof(secure_pw)- 1] = '\0';
  
  //Save into results which provides whether crypto_verify functon works (0 = verificiation successful, -1 is an error)
  int result = crypto_pwhash_str_verify(acc->password_hash, secure_pw, pwlen);

  //Wipe and unlock the password buffer from memory to be used for password validation
  sodium_munlock(secure_pw,sizeof(secure_pw));

  //Store a "result" variable from the crypto_pwhash_str_verify()function, which validates if password validated succesfully or not
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
  //Check that libsodium initialised properly
  if (sodium_init() < 0) {
    log_message(LOG_ERROR,"[account_update_password]: Libsodium library initialisation has failed");
    return false;
  }

  //Check for precondition 1: where acc and plaintext_password cannot be NULL
  if (acc == NULL || new_plaintext_password == NULL)
  {
    log_message(LOG_ERROR,"[account_update_password]: NULL input detected for acc and new_plaintext_password");
    return false;
  } 

  //Check for precondition 2: where plaintext_password must be valid and have null-terminated string.
  size_t pwlen = strnlen(new_plaintext_password, MAX_PW_LEN);

  if (pwlen == 0 || pwlen > MAX_PW_LEN){
    log_message(LOG_ERROR,"[account_update_password]: Invalid Password Length detected");
    return false;
  }

  //Additonal layer of security - Memory locking capability: Allocate and lock the plaintext_password after usage. 
  char new_secure_pw[MAX_PW_LEN];

  //Checking that memory is locked succesfully otherwise, throw an error.
  if (sodium_mlock(new_secure_pw, sizeof(new_secure_pw)) != 0 ){
    log_message(LOG_ERROR, "[account_update_password]: Failed to lock memory for new_plaintext_password");
    return false;
  }

  //Copy over the new secure_pw, which has been memory locked and add in a null byte
  strncpy(new_secure_pw, new_plaintext_password, sizeof(new_secure_pw) - 1);
  new_secure_pw[sizeof(new_secure_pw) - 1] = '\0';

  //Generate a new secure hash for the new_plaintext_password and store into structure acc->password_hash 
  int result = crypto_pwhash_str(acc->password_hash, new_secure_pw, pwlen, OPSLIMIT, MEMLIMIT);

  //Wipe and unlock the password buffer from memory to be used for new password update
  sodium_munlock(new_secure_pw, sizeof(new_secure_pw));

  //Verify the results from crypto_pwhash_str(), 0 = password updated successful
  if (result == 0){
    log_message(LOG_INFO,"[account_update_password]: Password updated successfully for user '%s'", acc->userid);
    return true; 
  }

  else {
    log_message(LOG_ERROR,"[account_update_password]: Password updated failed for user '%s'", acc->userid);
    return false;
  }  

}

void account_record_login_success(account_t *acc, ip4_addr_t ip) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) ip;
}

void account_record_login_failure(account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
}

bool account_is_banned(const account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  return false;
}

bool account_is_expired(const account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  return false;
}

void account_set_unban_time(account_t *acc, time_t t) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) t;
}

void account_set_expiration_time(account_t *acc, time_t t) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) t;
}

void account_set_email(account_t *acc, const char *new_email) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) new_email;
}

bool account_print_summary(const account_t *acct, int fd) {
  // remove the contents of this function and replace it with your own code.
  (void) acct;
  (void) fd;
  return false;
}

