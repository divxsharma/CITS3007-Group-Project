#include "login.h"
#include "logging.h"
#include "db.h"

login_result_t handle_login(const char *userid, const char *password,
                            ip4_addr_t client_ip, time_t login_time,
                            int client_output_fd, int log_fd,
                            login_session_data_t *session) 
{
  // The objective of this function are as follows:
  // 0. Check userid and password are not NULL
  // 1. Check if the user exists
  // 2. Check if the account is banned or expired, based on the current system time
  // 3. Check if the account has more than 10 consecutive failed logins
  // 4. Check if the password is correct
  // 5. Record the log status success or failure
  // 6. Populate the session data if successful
  // 7. Write appropriate messages to the client_output_fd file descriptor, which send output to the client (i.e., the person trying to log on) as well as to the the system logs (using log_message)

  //  Preperation: Setting the timeout for the session if the login is successful (Since it is a game, and people may play for the whole day as the most reasonable maximum single session time to expect)
  const int SESSION_TIMEOUT = 24 * 60 * 60; // 24 hours in seconds


  // Step 0: Check userid and password are not NULL
  if (userid == NULL) {
    log_message(LOG_INFO, "handle_login: userid is NULL");
    return LOGIN_FAIL_USER_NOT_FOUND;
  }
  if (password == NULL) {
    log_message(LOG_INFO, "handle_login: password is NULL");
    return LOGIN_FAIL_BAD_PASSWORD;
  }

  // Step 1: Allocate stack space for the account and check if the user exists. If not, return LOGIN_FAIL_USER_NOT_FOUND
  account_t *account = {0};
  bool account_exists  = account_lookup_by_userid(userid, account);
  if (!account_exists) {
    log_message(LOG_INFO, "handle_login: User %s not found", userid);
    return LOGIN_FAIL_USER_NOT_FOUND;
  }

  // Step 2: Check if the account is banned or expired
  bool is_account_banned = account_is_banned(account);
  if (is_account_banned) {
    log_message(LOG_INFO, "handle_login: Account %s is banned", userid);
    return LOGIN_FAIL_ACCOUNT_BANNED;
  }
  bool is_account_expired = account_is_expired(account);
  if (is_account_expired) {
    log_message(LOG_INFO, "handle_login: Account %s is expired", userid);
    return LOGIN_FAIL_ACCOUNT_EXPIRED;
  }

  // Step 3: Check if the account has more than 10 consecutive failed logins
  int failed_logins = account_get_failed_logins(account);
  if (failed_logins > 10) {
    log_message(LOG_INFO, "handle_login: Account %s has too many failed logins", userid);
    return LOGIN_FAIL_BAD_PASSWORD;
  }
  // Step 4: Check if the password is correct
  bool password_correct = account_check_password(account, password);
  if (!password_correct) {
    log_message(LOG_INFO, "handle_login: Incorrect password for user %s", userid);
    return LOGIN_FAIL_BAD_PASSWORD;
  }
  
  // Step 5: Record the log status success or failure
  log_message(LOG_INFO, "handle_login: User %s @ %i logged in successfully", userid, client_ip);
  
  // Step 6: Populate the session data if successful
  session->account_id = account->account_id;
  session->session_start = login_time;
  session->expiration_time = login_time + SESSION_TIMEOUT;

  // Step 7: Write appropriate messages to the client_output_fd file descriptor
  // Send success message to client
  const char *success_message = "Login successful";
  size_t bytes_written = write(client_output_fd, success_message, strlen(success_message));
  return LOGIN_SUCCESS;
}
