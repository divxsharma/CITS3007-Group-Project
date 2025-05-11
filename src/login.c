#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include "login.h"
#include "logging.h"
#include "db.h"
#include "banned.h"

login_result_t handle_login(const char *userid, const char *password,
                            ip4_addr_t client_ip, time_t login_time,
                            int client_output_fd, int log_fd,
                            login_session_data_t *session) 
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
