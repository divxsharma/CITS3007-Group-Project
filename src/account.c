#include "account.h"
#include "logging.h"

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/**
 * Create a new account with the specified parameters.
 *
 * This function initializes a new dynamically allocated account structure
 * with the given user ID, hash information derived from the specified plaintext password, email address,
 * and birthdate. Other fields are set to their default values.
 *
 * On success, returns a pointer to the newly created account structure.
 * On error, returns NULL and logs an error message.
 */
account_t *account_create(const char *userid, const char *plaintext_password,
                          const char *email, const char *birthdate
                      )
{
  // remove the contents of this function and replace it with your own code.
  (void) userid;
  (void) plaintext_password;
  (void) email;
  (void) birthdate;


  // replace:
  account_t *acc = malloc(sizeof(account_t));

  // When creating an account, we need to initialize the fields
  acc->unban_time = 0;           // Not banned
  acc->expiration_time = 0;      // No expiration
  
  return acc;
}


void account_free(account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
}


bool account_validate_password(const account_t *acc, const char *plaintext_password) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) plaintext_password;
  return false;
}

bool account_update_password(account_t *acc, const char *new_plaintext_password) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) new_plaintext_password;
  return false;
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
  // Precondition: acc must be non-NULL
  if (acc == NULL) {
    log_message(LOG_ERROR, "[account_is_banned]: NULL account pointer received");
    return false;
  }

  // Check if the account is banned
  // If unban_time is 0, there is no ban set
  if (acc->unban_time == 0)
    return false;
  
  // If current time is earlier than unban_time, the account is still banned
  return acc->unban_time > time(NULL);
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
  // Precondition: acc must be non-NULL
  if (acc == NULL) {
    log_message(LOG_ERROR, "[account_is_expired]: NULL account pointer received");
    return false;
  }

  // Check if the account is expired
  // If expiration_time is 0, there is no expiration set
  if (acc->expiration_time == 0)
    return false;
  
  // If current time is later than expiration_time, the account is expired
  return acc->expiration_time < time(NULL); 
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
  // Precondition: acc must be non-NULL
  if (acc == NULL) {
    log_message(LOG_ERROR, "[account_set_unban_time]: NULL account pointer received");
    return;
  }

  // Reject negative duration to avoid accidental or malicious unban
  if (t < 0) {
    log_message(LOG_WARN, "[account_set_unban_time]: Negative duration provided; unban_time not updated");
    return;
  }

  // Set the unban time to the specified duration
  acc->unban_time = t;
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
  // Precondition: acc must be non-NULL
  if (acc == NULL) {
    log_message(LOG_ERROR, "[account_set_expiration_time]: NULL account pointer received");
    return;
  }

  // Reject negative duration to avoid immediate expiration or misconfiguration
  if (t < 0) {
    log_message(LOG_WARN, "[account_set_expiration_time]: Negative duration provided; expiration_time not updated");
    return;
  }

  // Set the expiration time to the specified duration
  acc->expiration_time = t;
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

