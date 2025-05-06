#define CITS3007_PERMISSIVE

#include "../src/logging.h"
#include "../src/login.h"
#include "../src/account.h"
#include "../src/logging.h"
#include <check.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>

/* Panic function replacement */
/**
 * Abort immediately for unrecoverable errors /
 * invalid program state.
 * 
 * Arguments:
 * - msg: message to log before aborting
 * 
 * This function should not return.
 */
static void panic(const char *msg) {
    fprintf(stderr, "PANIC: %s\n", msg);
    abort();
}
/* Logging function replacement */
// Global mutex for logging
// This mutex is used to ensure that log messages are printed in a thread-safe manner.
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_message(log_level_t level, const char *fmt, ...) {
  pthread_mutex_lock(&log_mutex);

  va_list args;
  va_start(args, fmt);
  switch (level) {
    case LOG_DEBUG:
      fprintf(stderr, "DEBUG: ");
      break;
    case LOG_INFO:
      fprintf(stdout, "INFO: ");
      break;
    case LOG_WARN:
      fprintf(stderr, "WARNING: ");
      break;
    case LOG_ERROR:
      fprintf(stderr, "ERROR: ");
      break;
    default:
      panic("Invalid log level");
      break;
  }
  if (level == LOG_INFO) {
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");
  } else {
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
  }
   
  va_end(args);

  pthread_mutex_unlock(&log_mutex);
}

/*
 * Test cases for the handle_login function.
 * This suite includes tests for various scenarios including:
 * - Successful login
 * - User not found
 * - Bad password
 * - Account expired
 * - Account banned
 * - IP banned
 * - Internal error
 */

/* Mock lookup function to simulate the database.
 * Each case will have its own unique mock account lookup return.
 * Run with: gcc test_scripts/handle_login_tests.c src/logging.h src/login.c src/account.c -I./src -lcheck -lsodium -lsubunit -lpthread -lrt -lm -o test_scripts/handle_login_tests
 */
bool account_lookup_by_userid(const char *userid, account_t *result) {
    if (strcmp(userid, "test1") == 0) {
        result->account_id = 1;
        strcpy(result->userid, "test1");
        result->unban_time = 0;
        result->expiration_time = time(NULL) + 24*60*60;
        // Use the real password hashing function
        account_update_password(result, "hashpass1");
        return true;
    }

    if (strcmp(userid, "test3") == 0) {
        result->account_id = 3;
        strcpy(result->userid, "test3");
        result->unban_time = time(NULL) + 1e7; // Set a future unban time
        result->expiration_time = time(NULL) + 24*60*60;
        // Use the real password hashing function
        account_update_password(result, "hashpass3");
        return true;
    }

    if (strcmp(userid, "test4") == 0) {
      result->account_id = 4;
      strcpy(result->userid, "test4");
      result->unban_time = 0;
      result->expiration_time = time(NULL) - 24*60*60; // Set an expired account
      // Use the real password hashing function
      account_update_password(result, "hashpass4");
      return true;
    }

    if (strcmp(userid, "test5") == 0) {
      result->account_id = 5;
      strcpy(result->userid, "test5");
      result->unban_time = 0;
      result->login_fail_count = 11; // Set too many failed logins
      result->expiration_time = time(NULL) + 24*60*60; // Set an expired account
      // Use the real password hashing function
      account_update_password(result, "hashpass5");
      return true;
    }

    if (strcmp(userid, "test6") == 0) {
      result->account_id = 6;
      strcpy(result->userid, "test6");
      result->unban_time = 0;
      result->expiration_time = time(NULL) + 24*60*60; // Set an expired account
      // Use the real password hashing function
      account_update_password(result, "hashpass6");
      return true;
    }

    if (strcmp(userid, "test7") == 0) {
      result->account_id = 7;
      strcpy(result->userid, "test7");
      result->unban_time = 0;
      result->expiration_time = time(NULL) + 24*60*60; // Set an expired account
      // Use the real password hashing function
      account_update_password(result, "hashpass7");
      return true;
    }

    if (strcmp(userid, "test9") == 0) {
      result->account_id = 9;
      strcpy(result->userid, "test9");
      result->unban_time = 0;
      result->login_fail_count = 10; // Set too many failed logins
      result->expiration_time = time(NULL) + 24*60*60; // Set an expired account
      // Use the real password hashing function
      account_update_password(result, "hashpass9");
      return true;
    }
    return false;
}

/* 
 * First test case: Expected Successful login
 */
START_TEST(test_handle_login_success) {
    login_session_data_t session;
    int client_output_fd = STDOUT_FILENO; // Use standard output for testing
    int log_fd = STDERR_FILENO; // Use standard error for logging
    time_t login_time = time(NULL);
    ip4_addr_t client_ip = {127001}; // Localhost IP
    log_message(LOG_INFO, "[TEST] Testing successful login for user: test1");
    login_result_t result = handle_login("test1", "hashpass1", client_ip, login_time, client_output_fd, log_fd, &session);
    log_message(LOG_INFO, "[TEST] Login result: %d", result);
    ck_assert_int_eq(result, LOGIN_SUCCESS);
    ck_assert_int_eq(session.session_start, login_time); 
} END_TEST

/* 
 * Second test case: Expected User Not Found
 * This test case simulates a login attempt with a non-existent user.
 */
START_TEST(test_handle_login_user_not_found) {
  login_session_data_t session;
  int client_output_fd = STDOUT_FILENO; // Use standard output for testing
  int log_fd = STDERR_FILENO; // Use standard error for logging
  time_t login_time = time(NULL);
  ip4_addr_t client_ip = {127001}; // Localhost IP
  log_message(LOG_INFO, "[TEST] Testing Unsuccessful user not found login for user: test2");
  login_result_t result = handle_login("test2", "hashpass1", client_ip, login_time, client_output_fd, log_fd, &session);
  log_message(LOG_INFO, "[TEST] Login result: %d", result);
  ck_assert_int_eq(result, LOGIN_FAIL_USER_NOT_FOUND);
  // ck_assert_int_eq(session.session_start, login_time); // Removed because early return is expected.
  // ck_assert_int_eq(session.expiration_time, login_time + 24 * 60 * 60);  // ^
} END_TEST

/* 
 * Third test case: Expected User is banned
 * This test case simulates a login attempt with a currently banned user.
 */
START_TEST(test_handle_login_user_banned) {
  login_session_data_t session;
  int client_output_fd = STDOUT_FILENO; // Use standard output for testing
  int log_fd = STDERR_FILENO; // Use standard error for logging
  time_t login_time = time(NULL);
  ip4_addr_t client_ip = {127001}; // Localhost IP
  log_message(LOG_INFO, "[TEST] Testing banned user login: test3");
  login_result_t result = handle_login("test3", "hashpass1", client_ip, login_time, client_output_fd, log_fd, &session);
  log_message(LOG_INFO, "[TEST] Login result: %d", result);
  ck_assert_int_eq(result, LOGIN_FAIL_ACCOUNT_BANNED);
} END_TEST

/* 
 * Fourth test case: Expected user's account exoired
 * This test case simulates a login attempt with a currently expired account.
 */
START_TEST(test_handle_login_user_expired) {
  login_session_data_t session;
  int client_output_fd = STDOUT_FILENO; // Use standard output for testing
  int log_fd = STDERR_FILENO; // Use standard error for logging
  time_t login_time = time(NULL);
  ip4_addr_t client_ip = {127001}; // Localhost IP
  log_message(LOG_INFO, "[TEST] Testing expired user login: test4");
  login_result_t result = handle_login("test4", "hashpass1", client_ip, login_time, client_output_fd, log_fd, &session);
  log_message(LOG_INFO, "[TEST] Login result: %d", result);
  ck_assert_int_eq(result, LOGIN_FAIL_ACCOUNT_EXPIRED);
} END_TEST

/* 
 * Fifth test case: Expected user's account has too many failed logins
 * This test case simulates a login attempt with too many failed logins.
 */
START_TEST(test_handle_login_user_too_many_failed_logins) {
  login_session_data_t session;
  int client_output_fd = STDOUT_FILENO; // Use standard output for testing
  int log_fd = STDERR_FILENO; // Use standard error for logging
  time_t login_time = time(NULL);
  ip4_addr_t client_ip = {127001}; // Localhost IP
  log_message(LOG_INFO, "[TEST] Testing too many fails user login: test5");
  login_result_t result = handle_login("test5", "hashpass5", client_ip, login_time, client_output_fd, log_fd, &session);
  log_message(LOG_INFO, "[TEST] Login result: %d", result);
  ck_assert_int_eq(result, LOGIN_FAIL_BAD_PASSWORD);
} END_TEST

/* 
 * Sixth test case: Expected user's provides incorrect password
 * This test case simulates a login attempt with a correct username but incorrect password.
 */
START_TEST(test_handle_login_correct_username_incorrect_password) {
  login_session_data_t session;
  int client_output_fd = STDOUT_FILENO; // Use standard output for testing
  int log_fd = STDERR_FILENO; // Use standard error for logging
  time_t login_time = time(NULL);
  ip4_addr_t client_ip = {127001}; // Localhost IP
  log_message(LOG_INFO, "[TEST] Testing correct username incorrect password user login: test6");
  login_result_t result = handle_login("test6", "abc123", client_ip, login_time, client_output_fd, log_fd, &session);
  log_message(LOG_INFO, "[TEST] Login result: %d", result);
  ck_assert_int_eq(result, LOGIN_FAIL_BAD_PASSWORD);
} END_TEST

/* 
 * Seventh test case: Expected user's provides correct username but NULL password
 * This test case simulates a login attempt with a correct username but null password.
 */
START_TEST(test_handle_login_correct_username_null_password) {
  login_session_data_t session;
  int client_output_fd = STDOUT_FILENO; // Use standard output for testing
  int log_fd = STDERR_FILENO; // Use standard error for logging
  time_t login_time = time(NULL);
  ip4_addr_t client_ip = {127001}; // Localhost IP
  log_message(LOG_INFO, "[TEST] Testing correct username incorrect password user login: test7");
  login_result_t result = handle_login("test7", NULL, client_ip, login_time, client_output_fd, log_fd, &session);
  log_message(LOG_INFO, "[TEST] Login result: %d", result);
  ck_assert_int_eq(result, LOGIN_FAIL_BAD_PASSWORD);
} END_TEST

/* 
 * Eight test case: Expected user's provides NULL username but correct password for another account.
 * This test case simulates a login attempt with a NULL username but correct password.
 */
START_TEST(test_handle_login_null_username_correct_password) {
  login_session_data_t session;
  int client_output_fd = STDOUT_FILENO; // Use standard output for testing
  int log_fd = STDERR_FILENO; // Use standard error for logging
  time_t login_time = time(NULL);
  ip4_addr_t client_ip = {127001}; // Localhost IP
  log_message(LOG_INFO, "[TEST] Testing correct username incorrect password user login: test7");
  login_result_t result = handle_login(NULL, "hashpass6", client_ip, login_time, client_output_fd, log_fd, &session);
  log_message(LOG_INFO, "[TEST] Login result: %d", result);
  ck_assert_int_eq(result, LOGIN_FAIL_USER_NOT_FOUND);
} END_TEST

/* 
 * Ninth test case: Expected user's provides a correct username and password but with exactly 10 failed logins
 * This test case simulates a login attempt with a correct username and password but with exactly 10 failed logins.
 */

START_TEST(test_handle_login_correct_username_correct_password_exactly_10_prior_failed_logins) {
  login_session_data_t session;
  int client_output_fd = STDOUT_FILENO; // Use standard output for testing
  int log_fd = STDERR_FILENO; // Use standard error for logging
  time_t login_time = time(NULL);
  ip4_addr_t client_ip = {127001}; // Localhost IP
  log_message(LOG_INFO, "[TEST] Testing correct username and password but with 10 prior failed attempts user login: test7");
  login_result_t result = handle_login("test9", "hashpass9", client_ip, login_time, client_output_fd, log_fd, &session);
  log_message(LOG_INFO, "[TEST] Login result: %d", result);
  ck_assert_int_eq(result, LOGIN_SUCCESS);
} END_TEST

int main(void) {
    Suite *suite = suite_create("HandleLogin");
    TCase *tcase = tcase_create("Core");

    // Add test cases to the test case
    tcase_add_test(tcase, test_handle_login_success);
    tcase_add_test(tcase, test_handle_login_user_not_found);
    tcase_add_test(tcase, test_handle_login_user_banned);
    tcase_add_test(tcase, test_handle_login_user_expired);
    tcase_add_test(tcase, test_handle_login_user_too_many_failed_logins);
    tcase_add_test(tcase, test_handle_login_correct_username_incorrect_password);
    tcase_add_test(tcase, test_handle_login_correct_username_null_password);
    tcase_add_test(tcase, test_handle_login_null_username_correct_password);
    tcase_add_test(tcase, test_handle_login_correct_username_correct_password_exactly_10_prior_failed_logins);
    // Add the test case to the suite
    suite_add_tcase(suite, tcase);

    // Create a test runner and run the suite
    SRunner *runner = srunner_create(suite);
    srunner_run_all(runner, CK_NORMAL);

    int number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);

    return (number_failed == 0) ? 0 : 1;
}