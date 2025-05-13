/**
 * @file login.c
 * @brief Handles user authentication, session management, and account status checks.
 *
 * This file implements the login procedure for validating user credentials,
 * managing session and enforcing account restrictions like as bans,
 * expiration and login failure. It interacts with the account functions for
 * validation and logs for debug and info purposes.
 *
 * Functions in this file ensure that only valid, non-banned, non-expired users
 * with correct credentials are allowed to initiate a session. It securely
 * populates login session metadata and sends status messages to clients.
 *
 * @author Div Sharma [23810783]
 * @author Pranav Rajput [23736075]
 * @author William Lo [23722943]
 * @author Zachary Wang [24648002]
 * @author Jun Hao Dennis Lou [23067779]
 *
 * @bug No known bugs.
 */

#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include "login.h"
#include "logging.h"
#include "db.h"

/**
 * @brief Handles user login by verifying credentials, account status, and updating session data.
 *
 * This function does the following:
 * - Validating the `userid` and `password` inputs.
 * - Looking up the account by `userid`.
 * - Checking if the account is banned or expired.
 * - Checking for too many failed login attempts.
 * - Verifying the password using secure comparison.
 * - Updating the session data with account ID and session times.
 * - Logging the result of the login attempt.
 * - Sending a success or failure message to the client.
 *
 * @param userid A pointer to  user identifier string.
 * @param password A pointer to plaintext password string.
 * @param client_ip The IPv4 address of the connecting client.
 * @param login_time The server time at which login was attempted.
 * @param client_output_fd File descriptor used to send the login result to the client.
 * @param log_fd File descriptor reserved for future logging or audit output.
 * @param session A pointer to `login_session_data_t` structure to show on successful login.
 *
 * @pre `userid`, `password`, and `session` must not be NULL.
 * @pre `client_output_fd` must be a valid writable file descriptor.
 *
 * @post On success, session details are filled and a message is sent to the client.
 *       On failure, an appropriate `LOGIN_FAIL_*` result is returned.
 *
 * @return `LOGIN_SUCCESS` on successful authentication;
 *         otherwise, a `login_result_t` displays reason for failure:
 *         - `LOGIN_FAIL_USER_NOT_FOUND`
 *         - `LOGIN_FAIL_BAD_PASSWORD`
 *         - `LOGIN_FAIL_ACCOUNT_BANNED`
 *         - `LOGIN_FAIL_ACCOUNT_EXPIRED`
 */

login_result_t handle_login(const char *userid, const char *password, ip4_addr_t client_ip, time_t login_time, int client_output_fd, int log_fd, login_session_data_t *session) 
{
  const int SESSION_TIMEOUT = 24 * 60 * 60; 

  (void)client_output_fd;
  (void)log_fd;

  if (userid == NULL) {
    log_message(LOG_INFO, "[handle_login] userid is NULL");
    return LOGIN_FAIL_USER_NOT_FOUND;
  }
  if (password == NULL) {
    log_message(LOG_INFO, "[handle_login] password is NULL");
    return LOGIN_FAIL_BAD_PASSWORD;
  }
  if (session == NULL) {
    log_message(LOG_ERROR, "[handle_login] session is NULL");
    return LOGIN_FAIL_INTERNAL_ERROR;
  }

  account_t account = {0};
  bool account_exists  = account_lookup_by_userid(userid, &account);
  if (!account_exists) {
    log_message(LOG_INFO, "[handle_login] User %s not found", userid);
    return LOGIN_FAIL_USER_NOT_FOUND;
  }

  bool is_account_banned = account_is_banned(&account);
  if (is_account_banned) {
    log_message(LOG_INFO, "[handle_login] Account %s is banned", userid);
    account_record_login_failure(&account);
    return LOGIN_FAIL_ACCOUNT_BANNED;
  }
  bool is_account_expired = account_is_expired(&account);
  if (is_account_expired) {
    log_message(LOG_INFO, "[handle_login] Account %s is expired", userid);
    account_record_login_failure(&account);
    return LOGIN_FAIL_ACCOUNT_EXPIRED;
  }

  if (account.login_fail_count > 10) {
    log_message(LOG_INFO, "[handle_login] Account %s has too many failed logins", userid);
    account_record_login_failure(&account);
    return LOGIN_FAIL_BAD_PASSWORD;
  }

  bool password_correct = account_validate_password(&account, password);
  if (!password_correct) {
    account_record_login_failure(&account);
    log_message(LOG_INFO, "[handle_login] Incorrect password for user %s", userid);
    return LOGIN_FAIL_BAD_PASSWORD;
  }
  
  account_record_login_success(&account, client_ip);
  log_message(LOG_INFO, "[handle_login] User %s @ %i logged in successfully", userid, client_ip);
  
  session->account_id = (int)account.account_id; 
  session->session_start = login_time;
  session->expiration_time = login_time + SESSION_TIMEOUT;

  const char *success_message = "[handle_login]: Login successful.\n";
  
  ssize_t bytes_written = write(client_output_fd, success_message, strlen(success_message));
  if (bytes_written < 0) {
    log_message(LOG_WARN, "[handle_login] Failed to write to client_output_fd for user %s", userid);
  }

  return LOGIN_SUCCESS;
}
