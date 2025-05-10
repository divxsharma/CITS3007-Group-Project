#define CITS3007_PERMISSIVE

#include <check.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h> 
#include <arpa/inet.h>

#include "../src/login.h"
#include "../src/account.h"
#include "../src/logging.h"

/* Panic stub  */
static void panic(const char *msg) {
  fprintf(stderr, "PANIC: %s\n", msg);
  abort();
}

/* Log message clone */
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
void log_message(log_level_t level, const char *fmt, ...) {
  pthread_mutex_lock(&log_mutex);

  va_list args;
  va_start(args, fmt);

  switch (level) {
    case LOG_DEBUG: fprintf(stderr, "DEBUG: "); break;
    case LOG_INFO:  fprintf(stdout,  "INFO: ");  break;
    case LOG_WARN:  fprintf(stderr, "WARNING: "); break;
    case LOG_ERROR: fprintf(stderr, "ERROR: "); break;
    default:        panic("Invalid log level");
  }

  FILE *out = (level == LOG_INFO) ? stdout : stderr;
  vfprintf(out, fmt, args);
  fprintf(out, "\n");

  va_end(args);
  pthread_mutex_unlock(&log_mutex);
}

/* Mock database lookup for accounts – used by handle_login() in tests   */
bool account_lookup_by_userid(const char *userid, account_t *out) {
  if (!userid || !out) return false;

  /* Helper macro to bake common fields */
  #define FILL(id,nban,exp,pw)                  \
    do {                                        \
      out->account_id = id;                     \
      strcpy(out->userid, userid);              \
      out->unban_time      = (nban);            \
      out->expiration_time = (exp);             \
      account_update_password(out, pw);         \
    } while (0)

  time_t day = 24*60*60;

  if (strcmp(userid, "test1") == 0) {             
    FILL(1, 0, time(NULL)+day, "Str0ng!Pass1");
    return true;
  }
  if (strcmp(userid, "test3") == 0) {             
    FILL(3, time(NULL)+1e7, time(NULL)+day, "Str0ng!Pass3");
    return true;
  }
  if (strcmp(userid, "test4") == 0) {             
    FILL(4, 0, time(NULL)-day, "Str0ng!Pass4");
    return true;
  }
  if (strcmp(userid, "test5") == 0) {             
    FILL(5, 0, time(NULL)+day, "Str0ng!Pass5");
    out->login_fail_count = 11;
    return true;
  }
  if (strcmp(userid, "test6") == 0) {             
    FILL(6, 0, time(NULL)+day, "Str0ng!Pass6");
    return true;
  }
  if (strcmp(userid, "test7") == 0) {             
    FILL(7, 0, time(NULL)+day, "Str0ng!Pass7");
    return true;
  }
  if (strcmp(userid, "test9") == 0) {             
    FILL(9, 0, time(NULL)+day, "Str0ng!Pass9");
    out->login_fail_count = 10;
    return true;
  }
  return false;
}

#undef FILL
/*  */


/* =======================  Test‑suite proper  ========================== */
#suite handle_login_suite

#tcase core_paths


/*  1. Successful login  */
#test test_handle_login_success
  login_session_data_t session;
  const int out_fd = STDOUT_FILENO, log_fd = STDERR_FILENO;
  const time_t now = time(NULL);
  const ip4_addr_t ip = {127001};             /* 127.0.0.1 */

  login_result_t res = handle_login(
      "test1", "Str0ng!Pass1",
      ip, now, out_fd, log_fd, &session);

  ck_assert_int_eq(res, LOGIN_SUCCESS);
  ck_assert_int_eq(session.session_start, now);


/*  2. User not found  */
#test test_handle_login_user_not_found
  login_session_data_t s;
  login_result_t r = handle_login(
      "test2", "Str0ng!Pass1",
      (ip4_addr_t){127001}, time(NULL),
      STDOUT_FILENO, STDERR_FILENO, &s);

  ck_assert_int_eq(r, LOGIN_FAIL_USER_NOT_FOUND);


/*  3. Account banned  */
#test test_handle_login_user_banned
  login_session_data_t s;
  login_result_t r = handle_login(
      "test3", "Str0ng!Pass1",
      (ip4_addr_t){127001}, time(NULL),
      STDOUT_FILENO, STDERR_FILENO, &s);

  ck_assert_int_eq(r, LOGIN_FAIL_ACCOUNT_BANNED);


/*  4. Account expired  */
#test test_handle_login_user_expired
  login_session_data_t s;
  login_result_t r = handle_login(
      "test4", "Str0ng!Pass1",
      (ip4_addr_t){127001}, time(NULL),
      STDOUT_FILENO, STDERR_FILENO, &s);

  ck_assert_int_eq(r, LOGIN_FAIL_ACCOUNT_EXPIRED);


/*  5. Too many failed logins => treated as bad password  */
#test test_handle_login_user_too_many_failed_logins
  login_session_data_t s;
  login_result_t r = handle_login(
      "test5", "Str0ng!Pass5",
      (ip4_addr_t){127001}, time(NULL),
      STDOUT_FILENO, STDERR_FILENO, &s);

  ck_assert_int_eq(r, LOGIN_FAIL_BAD_PASSWORD);


/*  6. Correct username, wrong password  */
#test test_handle_login_wrong_password
  login_session_data_t s;
  login_result_t r = handle_login(
      "test6", "abc123",                  
      (ip4_addr_t){127001}, time(NULL),
      STDOUT_FILENO, STDERR_FILENO, &s);

  ck_assert_int_eq(r, LOGIN_FAIL_BAD_PASSWORD);


/*  7. Correct username, NULL password  */
#test test_handle_login_null_password
  login_session_data_t s;
  login_result_t r = handle_login(
      "test7", NULL,
      (ip4_addr_t){127001}, time(NULL),
      STDOUT_FILENO, STDERR_FILENO, &s);

  ck_assert_int_eq(r, LOGIN_FAIL_BAD_PASSWORD);


/*  8. NULL username, correct password (should map to “user not found”)  */
#test test_handle_login_null_username
  login_session_data_t s;
  login_result_t r = handle_login(
      NULL, "Str0ng!Pass6",
      (ip4_addr_t){127001}, time(NULL),
      STDOUT_FILENO, STDERR_FILENO, &s);

  ck_assert_int_eq(r, LOGIN_FAIL_USER_NOT_FOUND);


/*  9. Exactly 10 prior failures – still allowed to login  */
#test test_handle_login_exactly_10_prior_failures
  login_session_data_t s;
  login_result_t r = handle_login(
      "test9", "Str0ng!Pass9",
      (ip4_addr_t){127001}, time(NULL),
      STDOUT_FILENO, STDERR_FILENO, &s);

  ck_assert_int_eq(r, LOGIN_SUCCESS);
