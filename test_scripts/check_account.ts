#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdarg.h>
#include <unistd.h>
#include <check.h>

#include "../src/account.h"
#include "../src/login.h"
#include "../src/logging.h"

void panic(const char *msg)
{
    fprintf(stderr, "PANIC: %s\n", msg);
    abort();
}

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
void log_message(log_level_t level, const char *fmt, ...)
{
    pthread_mutex_lock(&log_mutex);
    FILE *out = (level == LOG_INFO) ? stdout : stderr;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    fprintf(out, "\n");
    va_end(ap);
    pthread_mutex_unlock(&log_mutex);
}

bool account_lookup_by_userid(const char *userid, account_t *out)
{
    if (!userid || !out) return false;

    #define FILL(id, ban, exp, pw)                \
        do {                                      \
            memset(out, 0, sizeof *out);          \
            out->account_id     = (id);           \
            strcpy(out->userid, userid);          \
            out->unban_time      = (ban);         \
            out->expiration_time = (exp);         \
            account_update_password(out, (pw));   \
        } while (0)

    time_t day = 24 * 60 * 60;
    if (strcmp(userid, "test1") == 0) { FILL(1, 0, time(NULL)+day, "Str0ng!Pass1"); return true; }
    if (strcmp(userid, "test2") == 0) { return false; }
    if (strcmp(userid, "test3") == 0) { FILL(3, time(NULL)+10000000, time(NULL)+day, "Str0ng!Pass3"); return true; }
    if (strcmp(userid, "test4") == 0) { FILL(4, 0, time(NULL)-day, "Str0ng!Pass4"); return true; }
    if (strcmp(userid, "test5") == 0) { FILL(5, 0, time(NULL)+day, "Str0ng!Pass5"); out->login_fail_count = 11; return true; }
    if (strcmp(userid, "test6") == 0) { FILL(6, 0, time(NULL)+day, "Str0ng!Pass6"); return true; }
    if (strcmp(userid, "test7") == 0) { FILL(7, 0, time(NULL)+day, "Str0ng!Pass7"); return true; }
    if (strcmp(userid, "test9") == 0) { FILL(9, 0, time(NULL)+day, "Str0ng!Pass9"); out->login_fail_count = 10; return true; }

    return false;
}
#undef FILL

#define TEST_MIN_PW_LEN   8
#define TEST_MAX_PW_LEN   128
#define TEST_MAX_DURATION 31536000

#suite account_management
#tcase account_create

#test test_account_create_works
  const char* userid = "someuser";
  const char* email = "foo@bar.com";
  const char* plaintext_password = "Str0ng!Pass1";
  const char* birthdate = "1900-01-01";
  account_t *res = account_create(userid, plaintext_password,email, birthdate);
  ck_assert_str_eq(res->userid, userid);
  ck_assert_str_eq(res->email, email);
  char copy_of_hash[HASH_LENGTH + 1 ] = { 0 };
  memcpy(copy_of_hash, res->password_hash, HASH_LENGTH);
  ck_assert_str_ne(copy_of_hash, plaintext_password);

#test test_account_create_null_args
  ck_assert_ptr_eq(account_create(NULL,"Pwd1!","a@b.com","2000-01-01"), NULL);
  ck_assert_ptr_eq(account_create("u",NULL,"a@b.com","2000-01-01"), NULL);
  ck_assert_ptr_eq(account_create("u","Pwd1!",NULL,"2000-01-01"), NULL);
  ck_assert_ptr_eq(account_create("u","Pwd1!","a@b.com",NULL), NULL);

#test test_account_set_email_works
  account_t *a=account_create("u","Strong1!","old@e.com","2000-01-01");
  ck_assert_ptr_ne(a,NULL);
  account_set_email(a,"new@e.com");
  ck_assert_str_eq(a->email,"new@e.com");
  account_free(a);

#test test_account_set_email_invalid
  account_t *a2=account_create("u","Strong1!","good@e.com","2000-01-01");
  const char *prev=a2->email;
  account_set_email(a2,"bad-email");
  ck_assert_str_eq(a2->email,prev);
  account_free(a2);

#test test_account_set_expiration_time_cap
  account_t accE = {0};
  time_t now = time(NULL);
  account_set_expiration_time(&accE, TEST_MAX_DURATION * 3);
  ck_assert(accE.expiration_time - now <= TEST_MAX_DURATION);

#test test_account_ban_and_expire
  account_t acc={0};
  ck_assert_int_eq(account_is_banned(&acc), false);
  account_set_unban_time(&acc, 1);
  ck_assert_int_eq(account_is_banned(&acc), true);
  account_set_unban_time(&acc, 0);
  ck_assert_int_eq(account_is_banned(&acc), false);
  ck_assert_int_eq(account_is_expired(&acc), false);
  account_set_expiration_time(&acc,1);
  ck_assert_int_eq(account_is_expired(&acc), false);
  acc.expiration_time = time(NULL)-1;
  ck_assert_int_eq(account_is_expired(&acc), true);

#test test_account_record_login
  account_t accL={0};
  accL.login_fail_count=5;
  account_record_login_success(&accL,INADDR_LOOPBACK);
  ck_assert_int_eq(accL.login_fail_count,0);
  ck_assert(accL.last_login_time>0);

#test test_account_set_unban_time_negative_no_change
  account_t acc7 = {0};
  acc7.unban_time = 12345;
  account_set_unban_time(&acc7, (time_t)-5);
  ck_assert_int_eq(acc7.unban_time, 12345);

#test test_account_set_unban_time_cap_to_max
  account_t acc8 = {0};
  time_t now = time(NULL);
  account_set_unban_time(&acc8, TEST_MAX_DURATION * 2);   
  ck_assert(acc8.unban_time - now <= TEST_MAX_DURATION);

#test test_account_is_banned_past_unban_time
  account_t acc9 = {0};
  acc9.unban_time = time(NULL) - 1;    
  ck_assert_int_eq(account_is_banned(&acc9), 0);

#test test_handle_login_exactly_10_prior_failures
  login_session_data_t s;
  login_result_t r = handle_login("test9", "Str0ng!Pass9",(ip4_addr_t){127001}, time(NULL),STDOUT_FILENO, STDERR_FILENO, &s);
  ck_assert_int_eq(r, LOGIN_SUCCESS);
  
#test test_print_summary_normal_account
  account_t acc = {0};
  strcpy(acc.userid, "testuser");
  strcpy(acc.email, "test@example.com");
  acc.login_count = 5;
  acc.login_fail_count = 2;
  acc.expiration_time = 0;
  acc.unban_time = 0;
  inet_pton(AF_INET, "127.0.0.1", &acc.last_ip);
  strcpy(acc.birthdate, "2000-01-01");
  acc.last_login_time = time(NULL);

  int pipefd[2]; ck_assert_int_eq(pipe(pipefd), 0);
  bool ok = account_print_summary(&acc, pipefd[1]);
  fsync(pipefd[1]); close(pipefd[1]);
  ck_assert(ok);
  char outbuf[2048] = {0}; read(pipefd[0], outbuf, sizeof(outbuf)); close(pipefd[0]);
  ck_assert_msg(strstr(outbuf, "testuser"), "userid missing");
  ck_assert_msg(strstr(outbuf, "test@example.com"), "email missing");
  ck_assert_msg(strstr(outbuf, "Login Successes: 5"), "success count missing");
  ck_assert_msg(strstr(outbuf, "Login Failures: 2"), "fail count missing");
  ck_assert_msg(strstr(outbuf, "Birthdate: 2000-01-01"), "birthdate missing");
  ck_assert_msg(strstr(outbuf, "127.0.0.1"), "IP missing");
  char year[5]; strftime(year, sizeof(year), "%Y", localtime(&acc.last_login_time));
  ck_assert_msg(strstr(outbuf, year), "year missing");

#test test_print_summary_null_input
    bool res_null = account_print_summary(NULL, STDOUT_FILENO);
    ck_assert(!res_null);

#test test_print_summary_invalid_fd
    account_t acc2 = {0}; strcpy(acc2.userid, "user");
    bool res_fd = account_print_summary(&acc2, -1);
    ck_assert(!res_fd);

#test test_login_fail_count_max
    account_t acc3 = {0}; acc3.login_fail_count = UINT_MAX;
    account_record_login_failure(&acc3);
    ck_assert_uint_eq(acc3.login_fail_count, UINT_MAX);

#test test_print_summary_pipe_closed_before_write
    account_t acc4 = {0}; strcpy(acc4.userid, "testuser"); strcpy(acc4.email, "test@example.com"); strcpy(acc4.birthdate, "2000-01-01");
    int pipefd2[2]; ck_assert_int_eq(pipe(pipefd2), 0);
    close(pipefd2[1]);
    bool res_fail = account_print_summary(&acc4, pipefd2[1]); close(pipefd2[0]);
    ck_assert(!res_fail);

#suite password_handling
#tcase password

#test test_account_update_password_neq_plaintext
  account_t acc = { 0 };
  const char* plaintext_password = "Str0ng!Pass1";
  bool res = account_update_password(&acc, plaintext_password);
  ck_assert_int_eq(res, 1);
  char copy_of_hash[HASH_LENGTH + 1 ] = { 0 };
  memcpy(copy_of_hash, acc.password_hash, HASH_LENGTH);
  ck_assert_str_ne(copy_of_hash, plaintext_password);

#test test_account_validate_password_ok
  account_t acc = { 0 };
  const char* plaintext_password = "Str0ng!Pass1";
  bool res = account_update_password(&acc, plaintext_password);
  ck_assert_int_eq(res, 1);
  res = account_validate_password(&acc, plaintext_password);
  ck_assert_int_eq(res, 1);

#test test_account_update_account_old_password_neq_hash
  account_t acc = { 0 };
  const char* plaintext_password = "Str0ng!Pass1";
  bool update1 = account_update_password(&acc, plaintext_password);
  ck_assert_int_eq(update1, 1);
  char copy_of_hash1[HASH_LENGTH + 1 ] = { 0 };
  memcpy(copy_of_hash1, acc.password_hash, HASH_LENGTH);
  bool update2 = account_update_password(&acc, plaintext_password);
  ck_assert_int_eq(update2, 1);
  char copy_of_hash2[HASH_LENGTH + 1 ] = { 0 };
  memcpy(copy_of_hash2, acc.password_hash, HASH_LENGTH);
  ck_assert_str_ne(copy_of_hash1, copy_of_hash2);

#test test_account_create_password_no_digit
  ck_assert_ptr_eq(account_create("u", "NoDigits!", "a@b.com", "2000-01-01"), NULL);

#test test_account_create_password_too_short
  ck_assert_ptr_eq(account_create("u", "Ab1!", "a@b.com", "2000-01-01"),NULL);

#test test_account_create_password_min_len_ok
  const char pw_min[TEST_MIN_PW_LEN + 1] = "P@ssw0rd"; 
  account_t *a = account_create("u", pw_min, "a@b.com", "2000-01-01");
  ck_assert_ptr_ne(a, NULL);
  account_free(a);
       
#test test_account_create_password_max_len_ok
  char pw_exact[TEST_MAX_PW_LEN + 1];
  memset(pw_exact, 'a', TEST_MAX_PW_LEN - 2);
  strcpy(pw_exact + TEST_MAX_PW_LEN - 3, "A1!"); 
  pw_exact[TEST_MAX_PW_LEN] = '\0';
  account_t *acc = account_create("u", pw_exact, "a@b.com", "2000-01-01");
  ck_assert_ptr_ne(acc, NULL);
  account_free(acc);

#test test_account_create_invalid_email_formats
  ck_assert_ptr_eq(account_create("u", "Strong1!", "noatsymbol", "2000-01-01"),NULL);
  ck_assert_ptr_eq(account_create("u", "Strong1!", "two@@ats.com", "2000-01-01"),NULL);
  ck_assert_ptr_eq(account_create("u", "Strong1!", "spaces @here.com", "2000-01-01"),NULL);

#test test_account_create_email_too_long
  char long_email[EMAIL_LENGTH + 10];
  memset(long_email, 'a', EMAIL_LENGTH);
  strcpy(long_email + EMAIL_LENGTH, "@b.com");          
  ck_assert_ptr_eq(account_create("u", "Strong1!", long_email, "2000-01-01"),NULL);

#test test_account_create_userid_too_long_rejected
  char long_uid[USER_ID_LENGTH + 10];
  memset(long_uid, 'u', sizeof long_uid - 1);
  long_uid[sizeof long_uid - 1] = '\0';
  ck_assert_ptr_eq(account_create(long_uid, "Strong1!", "good@e.com", "2000-01-01"),NULL);
      

#suite login_handling
#tcase login
  
#test test_handle_login_success
  login_session_data_t session;
  const int out_fd = STDOUT_FILENO, log_fd = STDERR_FILENO;
  const time_t now = time(NULL);
  const ip4_addr_t ip = {127001};             
  login_result_t res = handle_login("test1", "Str0ng!Pass1",ip, now, out_fd, log_fd, &session);
  ck_assert_int_eq(res, LOGIN_SUCCESS);
  ck_assert_int_eq(session.session_start, now);

#test test_handle_login_user_not_found
  login_session_data_t s;
  login_result_t r = handle_login("test2", "Str0ng!Pass1",(ip4_addr_t){127001}, time(NULL),STDOUT_FILENO, STDERR_FILENO, &s);
  ck_assert_int_eq(r, LOGIN_FAIL_USER_NOT_FOUND);

#test test_handle_login_user_banned
  login_session_data_t s;
  login_result_t r = handle_login("test3", "Str0ng!Pass1",(ip4_addr_t){127001}, time(NULL),STDOUT_FILENO, STDERR_FILENO, &s);
  ck_assert_int_eq(r, LOGIN_FAIL_ACCOUNT_BANNED);

#test test_handle_login_user_expired
  login_session_data_t s;
  login_result_t r = handle_login("test4", "Str0ng!Pass1",(ip4_addr_t){127001}, time(NULL),STDOUT_FILENO, STDERR_FILENO, &s);
  ck_assert_int_eq(r, LOGIN_FAIL_ACCOUNT_EXPIRED);

#test test_handle_login_user_too_many_failed_logins
  login_session_data_t s;
  login_result_t r = handle_login("test5", "Str0ng!Pass5",(ip4_addr_t){127001}, time(NULL),STDOUT_FILENO, STDERR_FILENO, &s);
  ck_assert_int_eq(r, LOGIN_FAIL_BAD_PASSWORD);

#test test_handle_login_wrong_password
  login_session_data_t s;
  login_result_t r = handle_login("test6", "abc123",(ip4_addr_t){127001}, time(NULL),STDOUT_FILENO, STDERR_FILENO, &s);
  ck_assert_int_eq(r, LOGIN_FAIL_BAD_PASSWORD);

#test test_handle_login_null_password
  login_session_data_t s;
  login_result_t r = handle_login("test7", NULL,(ip4_addr_t){127001}, time(NULL),STDOUT_FILENO, STDERR_FILENO, &s);
  ck_assert_int_eq(r, LOGIN_FAIL_BAD_PASSWORD);

#test test_handle_login_null_username
  login_session_data_t s;
  login_result_t r = handle_login(NULL, "Str0ng!Pass6",(ip4_addr_t){127001}, time(NULL),STDOUT_FILENO, STDERR_FILENO, &s);
  ck_assert_int_eq(r, LOGIN_FAIL_USER_NOT_FOUND);


