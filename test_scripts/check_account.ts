#define CITS3007_PERMISSIVE

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <time.h>
#include <arpa/inet.h>

#include "../src/account.h"

/* Private copies of internal‑only limits (keep in sync with account.c) */
#define TEST_MIN_PW_LEN   8          /* MIN_PASSWORD_LENGTH */
#define TEST_MAX_PW_LEN   128        /* MAX_PW_LEN          */
#define TEST_MAX_DURATION 31536000   /* MAX_DURATION (1 year) */

// Build command = gcc -std=c11 -Wall -Wextra -Wpedantic -Werror -o check_account test_scripts/check_account.c src/account.c src/stubs.c -lcheck -pthread -lm -lrt -lsubunit -lsodium
// Run command = ./test_scripts/check_account
#define ARR_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#suite account_suite

#tcase account_create_test_case

#test test_account_create_works

  const char* userid = "someuser";
  const char* email = "foo@bar.com";
  const char* plaintext_password = "Str0ng!Pass1";
  const char* birthdate = "1900-01-01";

  account_t *res = account_create(userid, plaintext_password,
                        email, birthdate
                        );

  // actual, expected
  ck_assert_str_eq(res->userid, userid);
  ck_assert_str_eq(res->email, email);
  // copy of hash
  char copy_of_hash[HASH_LENGTH + 1 ] = { 0 };
  memcpy(copy_of_hash, res->password_hash, HASH_LENGTH);
  // TODO: only if string is printable

  // password hash is NOT the same as password
  ck_assert_str_ne(copy_of_hash, plaintext_password);


#tcase account_update_password_test_case

#test test_account_update_password_neq_plaintext

  account_t acc = { 0 };

  const char* plaintext_password = "Str0ng!Pass1";

  bool res = account_update_password(&acc, plaintext_password);

  ck_assert_int_eq(res, 1);

  char copy_of_hash[HASH_LENGTH + 1 ] = { 0 };
  memcpy(copy_of_hash, acc.password_hash, HASH_LENGTH);
  // TODO: only if string is printable

  // password hash is NOT the same as password
  ck_assert_str_ne(copy_of_hash, plaintext_password);



#test test_account_validate_password_ok

  account_t acc = { 0 };

  const char* plaintext_password = "Str0ng!Pass1";

  bool res = account_update_password(&acc, plaintext_password);

  ck_assert_int_eq(res, 1);

  res = account_validate_password(&acc, plaintext_password);

  ck_assert_int_eq(res, 1);

// vim: syntax=c :
#test test_account_update_account_old_password_neq_hash

  account_t acc = { 0 };

  const char* plaintext_password = "Str0ng!Pass1";

  // Now update and extract the initial password hash for the first update:
  bool update1 = account_update_password(&acc, plaintext_password);

  ck_assert_int_eq(update1, 1);

  char copy_of_hash1[HASH_LENGTH + 1 ] = { 0 };

  memcpy(copy_of_hash1, acc.password_hash, HASH_LENGTH);

  // Now update the password again but with the same plaintext password, then assert that the hash is different:
  bool update2 = account_update_password(&acc, plaintext_password);

  ck_assert_int_eq(update2, 1);

  char copy_of_hash2[HASH_LENGTH + 1 ] = { 0 };

  memcpy(copy_of_hash2, acc.password_hash, HASH_LENGTH);

  // Check that the two hashes are different
  ck_assert_str_ne(copy_of_hash1, copy_of_hash2);

  #tcase api_misc
#test test_account_create_null_args
  ck_assert_ptr_eq(account_create(NULL,"Pwd1!","a@b.com","2000-01-01"), NULL);
  ck_assert_ptr_eq(account_create("u",NULL,"a@b.com","2000-01-01"), NULL);
  ck_assert_ptr_eq(account_create("u","Pwd1!",NULL,"2000-01-01"), NULL);
  ck_assert_ptr_eq(account_create("u","Pwd1!","a@b.com",NULL), NULL);

#test test_account_set_email_happy
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

/*   account_create() edge cases   */
#tcase account_create_edge_case

#test test_account_create_password_too_short
  ck_assert_ptr_eq(
      account_create("u", "Ab1!", "a@b.com", "2000-01-01"),
      NULL);

#test test_account_create_password_min_len_ok
  const char pw_min[TEST_MIN_PW_LEN + 1] = "P@ssw0rd"; /* 8 chars exactly*/
  account_t *a = account_create("u", pw_min, "a@b.com", "2000-01-01");
  ck_assert_ptr_ne(a, NULL);
  account_free(a);

#test test_account_create_invalid_email_formats
  ck_assert_ptr_eq(
      account_create("u", "Strong1!", "noatsymbol", "2000-01-01"),
      NULL);
  ck_assert_ptr_eq(
      account_create("u", "Strong1!", "two@@ats.com", "2000-01-01"),
      NULL);
  ck_assert_ptr_eq(
      account_create("u", "Strong1!", "spaces @here.com", "2000-01-01"),
      NULL);

#test test_account_create_email_too_long
  char long_email[EMAIL_LENGTH + 10];
  memset(long_email, 'a', EMAIL_LENGTH);
  strcpy(long_email + EMAIL_LENGTH, "@b.com");          /* valid format but too long */
  ck_assert_ptr_eq(
      account_create("u", "Strong1!", long_email, "2000-01-01"),
      NULL);

#test test_account_create_userid_too_long_rejected
  char long_uid[USER_ID_LENGTH + 10];
  memset(long_uid, 'u', sizeof long_uid - 1);
  long_uid[sizeof long_uid - 1] = '\0';

  ck_assert_ptr_eq(
      account_create(long_uid, "Strong1!", "good@e.com", "2000-01-01"),
      NULL);
      /* PASSWORD COMPLEXITY – no digit */
     #test test_account_create_password_no_digit
       ck_assert_ptr_eq(account_create("u", "NoDigits!", "a@b.com", "2000-01-01"), NULL);
     
     /* EXACT MAX LENGTH PASSWORD SHOULD PASS */
     #test test_account_create_password_max_len_ok
       char pw_exact[TEST_MAX_PW_LEN + 1];
       memset(pw_exact, 'A', TEST_MAX_PW_LEN - 2);
       strcpy(pw_exact + TEST_MAX_PW_LEN - 2, "1!"); /* ensure digit+special */
       pw_exact[TEST_MAX_PW_LEN] = '\0';
       account_t *acc = account_create("u", pw_exact, "a@b.com", "2000-01-01");
       ck_assert_ptr_ne(acc, NULL);
       account_free(acc);
     
     /* BIRTHDATE – future date */
     #test test_account_create_birthdate_future
       ck_assert_ptr_eq(
           account_create("u","Strong1!","a@b.com","2999-12-31"), NULL);
     
     /* EXPIRATION setter > MAX_DURATION should clamp */
     #test test_account_set_expiration_time_cap
       account_t accE = {0};
       time_t now = time(NULL);
       account_set_expiration_time(&accE, TEST_MAX_DURATION * 3);
       ck_assert(accE.expiration_time - now <= TEST_MAX_DURATION);
     
     /* DOUBLE FREE safety */
     #test test_account_double_free_safe
       account_t *tmp = account_create("u","Strong1!","e@e.com","2000-01-01");
       account_free(tmp);
       account_free(tmp); /* should be no-op / no crash */



/*   Account Set email tests  */
#tcase account_set_email_edge_case

#test test_account_set_email_null_args
  account_set_email(NULL, "x@y.com");   /* should not crash */

#test test_account_set_email_null_new_email
  account_t *c = account_create("u","Strong1!","start@e.com","2000-01-01");
  ck_assert_ptr_ne(c, NULL);
  account_set_email(c, NULL);           /* no change expected */
  ck_assert_str_eq(c->email, "start@e.com");
  account_free(c);

#test test_account_set_email_overlong
  account_t *d = account_create("u","Strong1!","ok@e.com","2000-01-01");
  char big_email[EMAIL_LENGTH + 10];
  memset(big_email, 'b', EMAIL_LENGTH);
  strcpy(big_email + EMAIL_LENGTH, "@e.com");
  account_set_email(d, big_email);
  ck_assert_str_eq(d->email, "ok@e.com");   /* unchanged */
  account_free(d);

/*   Password routines   */
#tcase password_edge_case

#test test_account_validate_password_wrong
  account_t acc1 = {0};
  ck_assert(account_update_password(&acc1, "Correct1!"));
  ck_assert_int_eq(account_validate_password(&acc1, "Wrong1!"), 0);

#test test_account_update_password_empty_and_too_long
  account_t acc2 = {0};
  ck_assert_int_eq(account_update_password(&acc2, ""), 0);
  char pw_big[TEST_MAX_PW_LEN + 50];
  memset(pw_big, 'A', sizeof(pw_big) - 1);
  pw_big[sizeof(pw_big) - 1] = '\0';
  ck_assert_int_eq(account_update_password(&acc2, pw_big), 0);

#test test_account_old_password_no_longer_valid
  account_t acc3 = {0};
  ck_assert(account_update_password(&acc3, "First1!00"));
  ck_assert(account_update_password(&acc3, "Second1!00"));
  ck_assert_int_eq(account_validate_password(&acc3, "First1!00"), 0);
  ck_assert_int_eq(account_validate_password(&acc3, "Second1!00"), 1);

#test test_password_null_args
  ck_assert_int_eq(account_validate_password(NULL, "x"), 0);
  ck_assert_int_eq(account_validate_password((account_t*)&(int){0}, NULL), 0);
  ck_assert_int_eq(account_update_password(NULL, "x"), 0);

/* ─  login tracking  ─ */
#tcase login_tracking_edge_case

#test test_account_record_login_failure_increment
  account_t acc4 = {0};
  account_record_login_failure(&acc4);
  ck_assert_int_eq(acc4.login_fail_count, 1);

#test test_account_record_login_failure_no_overflow
  account_t acc5 = {0};
  acc5.login_fail_count = UINT_MAX;
  account_record_login_failure(&acc5);
  ck_assert_int_eq(acc5.login_fail_count, UINT_MAX);

#test test_account_record_login_success_sets_ip_and_resets_fail
  account_t acc6 = {0};
  acc6.login_fail_count = 3;
  ip4_addr_t ip = htonl(INADDR_LOOPBACK);
  account_record_login_success(&acc6, ip);
  ck_assert_int_eq(acc6.last_ip, ip);
  ck_assert_int_eq(acc6.login_fail_count, 0);
  ck_assert(acc6.last_login_time > 0);

#test test_account_record_login_success_null
  account_record_login_success(NULL, 0);  /* should not crash */
  account_record_login_failure(NULL);     /* likewise */

/* ─  ban / expiry limits  ── */
#tcase ban_expiry_edge_case

#test test_account_set_unban_time_negative_no_change
  account_t acc7 = {0};
  acc7.unban_time = 12345;
  account_set_unban_time(&acc7, (time_t)-5);
  ck_assert_int_eq(acc7.unban_time, 12345);

#test test_account_set_unban_time_cap_to_max
  account_t acc8 = {0};
  time_t now = time(NULL);
  account_set_unban_time(&acc8, TEST_MAX_DURATION * 2);   /* request > max */
  ck_assert(acc8.unban_time - now <= TEST_MAX_DURATION);

#test test_account_is_banned_past_unban_time
  account_t acc9 = {0};
  acc9.unban_time = time(NULL) - 1;    /* already past */
  ck_assert_int_eq(account_is_banned(&acc9), 0);

/* ──  misc / safety  ─ */
#tcase misc_edge_case

/* 1. Freeing a NULL pointer must be a no-op */
#test test_account_free_null_ok
  account_free(NULL);                 /* should not crash */

/* 2. Freeing the same heap-allocated account twice must be harmless       *
 *    (requires account_free() to wipe internal pointers after the first   *
 *    free so the second call hits only NULLs).                            */


/* 3. Freeing an un-initialised, stack-allocated struct must also be safe. */
#test test_account_free_uninitialised_struct_ok
  account_t local = {0};              /* never passed to account_create() */
  account_free(&local);               /* no crash expected */

