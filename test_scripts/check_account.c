/*
 * DO NOT EDIT THIS FILE. Generated by checkmk.
 * Edit the original source file "test_scripts/check_account.ts" instead.
 */

#include <check.h>

#line 1 "test_scripts/check_account.ts"
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



START_TEST(test_account_create_works)
{
#line 27

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


}
END_TEST

START_TEST(test_account_update_password_neq_plaintext)
{
#line 52


  account_t acc = { 0 };

  const char* plaintext_password = "Str0ng!Pass1";

  bool res = account_update_password(&acc, plaintext_password);

  ck_assert_int_eq(res, 1);

  char copy_of_hash[HASH_LENGTH + 1 ] = { 0 };
  memcpy(copy_of_hash, acc.password_hash, HASH_LENGTH);
  // TODO: only if string is printable

  // password hash is NOT the same as password
  ck_assert_str_ne(copy_of_hash, plaintext_password);



}
END_TEST

START_TEST(test_account_validate_password_ok)
{
#line 71


  account_t acc = { 0 };

  const char* plaintext_password = "Str0ng!Pass1";

  bool res = account_update_password(&acc, plaintext_password);

  ck_assert_int_eq(res, 1);

  res = account_validate_password(&acc, plaintext_password);

  ck_assert_int_eq(res, 1);

// vim: syntax=c :
}
END_TEST

START_TEST(test_account_update_account_old_password_neq_hash)
{
#line 86


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


/*   account_create() edge cases   */
}
END_TEST

START_TEST(test_account_create_password_too_short)
{
#line 116
  ck_assert_ptr_eq(
      account_create("u", "Ab1!", "a@b.com", "2000-01-01"),
      NULL);

}
END_TEST

START_TEST(test_account_create_password_min_len_ok)
{
#line 121
  const char pw_min[TEST_MIN_PW_LEN + 1] = "P@ssw0rd"; /* 8 chars exactly*/
  account_t *a = account_create("u", pw_min, "a@b.com", "2000-01-01");
  ck_assert_ptr_ne(a, NULL);
  account_free(a);

}
END_TEST

START_TEST(test_account_create_invalid_email_formats)
{
#line 127
  ck_assert_ptr_eq(
      account_create("u", "Strong1!", "noatsymbol", "2000-01-01"),
      NULL);
  ck_assert_ptr_eq(
      account_create("u", "Strong1!", "two@@ats.com", "2000-01-01"),
      NULL);
  ck_assert_ptr_eq(
      account_create("u", "Strong1!", "spaces @here.com", "2000-01-01"),
      NULL);

}
END_TEST

START_TEST(test_account_create_email_too_long)
{
#line 138
  char long_email[EMAIL_LENGTH + 10];
  memset(long_email, 'a', EMAIL_LENGTH);
  strcpy(long_email + EMAIL_LENGTH, "@b.com");          /* valid format but too long */
  ck_assert_ptr_eq(
      account_create("u", "Strong1!", long_email, "2000-01-01"),
      NULL);

}
END_TEST

START_TEST(test_account_create_userid_too_long_rejected)
{
#line 146
  char long_uid[USER_ID_LENGTH + 10];
  memset(long_uid, 'u', sizeof long_uid - 1);
  long_uid[sizeof long_uid - 1] = '\0';

  ck_assert_ptr_eq(
      account_create(long_uid, "Strong1!", "good@e.com", "2000-01-01"),
      NULL);

/*   Account Set email tests  */
}
END_TEST

START_TEST(test_account_set_email_null_args)
{
#line 158
  account_set_email(NULL, "x@y.com");   /* should not crash */

}
END_TEST

START_TEST(test_account_set_email_null_new_email)
{
#line 161
  account_t *c = account_create("u","Strong1!","start@e.com","2000-01-01");
  ck_assert_ptr_ne(c, NULL);
  account_set_email(c, NULL);           /* no change expected */
  ck_assert_str_eq(c->email, "start@e.com");
  account_free(c);

}
END_TEST

START_TEST(test_account_set_email_overlong)
{
#line 168
  account_t *d = account_create("u","Strong1!","ok@e.com","2000-01-01");
  char big_email[EMAIL_LENGTH + 10];
  memset(big_email, 'b', EMAIL_LENGTH);
  strcpy(big_email + EMAIL_LENGTH, "@e.com");
  account_set_email(d, big_email);
  ck_assert_str_eq(d->email, "ok@e.com");   /* unchanged */
  account_free(d);

/*   Password routines   */
}
END_TEST

START_TEST(test_account_validate_password_wrong)
{
#line 180
  account_t acc1 = {0};
  ck_assert(account_update_password(&acc1, "Correct1!"));
  ck_assert_int_eq(account_validate_password(&acc1, "Wrong1!"), 0);

}
END_TEST

START_TEST(test_account_update_password_empty_and_too_long)
{
#line 185
  account_t acc2 = {0};
  ck_assert_int_eq(account_update_password(&acc2, ""), 0);
  char pw_big[TEST_MAX_PW_LEN + 50];
  memset(pw_big, 'A', sizeof(pw_big) - 1);
  pw_big[sizeof(pw_big) - 1] = '\0';
  ck_assert_int_eq(account_update_password(&acc2, pw_big), 0);

}
END_TEST

START_TEST(test_account_old_password_no_longer_valid)
{
#line 193
  account_t acc3 = {0};
  ck_assert(account_update_password(&acc3, "First1!00"));
  ck_assert(account_update_password(&acc3, "Second1!00"));
  ck_assert_int_eq(account_validate_password(&acc3, "First1!00"), 0);
  ck_assert_int_eq(account_validate_password(&acc3, "Second1!00"), 1);

}
END_TEST

START_TEST(test_password_null_args)
{
#line 200
  ck_assert_int_eq(account_validate_password(NULL, "x"), 0);
  ck_assert_int_eq(account_validate_password((account_t*)&(int){0}, NULL), 0);
  ck_assert_int_eq(account_update_password(NULL, "x"), 0);

/* ─  login tracking  ─ */
}
END_TEST

START_TEST(test_account_record_login_failure_increment)
{
#line 208
  account_t acc4 = {0};
  account_record_login_failure(&acc4);
  ck_assert_int_eq(acc4.login_fail_count, 1);

}
END_TEST

START_TEST(test_account_record_login_failure_no_overflow)
{
#line 213
  account_t acc5 = {0};
  acc5.login_fail_count = UINT_MAX;
  account_record_login_failure(&acc5);
  ck_assert_int_eq(acc5.login_fail_count, UINT_MAX);

}
END_TEST

START_TEST(test_account_record_login_success_sets_ip_and_resets_fail)
{
#line 219
  account_t acc6 = {0};
  acc6.login_fail_count = 3;
  ip4_addr_t ip = htonl(INADDR_LOOPBACK);
  account_record_login_success(&acc6, ip);
  ck_assert_int_eq(acc6.last_ip, ip);
  ck_assert_int_eq(acc6.login_fail_count, 0);
  ck_assert(acc6.last_login_time > 0);

}
END_TEST

START_TEST(test_account_record_login_success_null)
{
#line 228
  account_record_login_success(NULL, 0);  /* should not crash */
  account_record_login_failure(NULL);     /* likewise */

/* ─  ban / expiry limits  ── */
}
END_TEST

START_TEST(test_account_set_unban_time_negative_no_change)
{
#line 235
  account_t acc7 = {0};
  acc7.unban_time = 12345;
  account_set_unban_time(&acc7, (time_t)-5);
  ck_assert_int_eq(acc7.unban_time, 12345);

}
END_TEST

START_TEST(test_account_set_unban_time_cap_to_max)
{
#line 241
  account_t acc8 = {0};
  time_t now = time(NULL);
  account_set_unban_time(&acc8, TEST_MAX_DURATION * 2);   /* request > max */
  ck_assert(acc8.unban_time - now <= TEST_MAX_DURATION);

}
END_TEST

START_TEST(test_account_is_banned_past_unban_time)
{
#line 247
  account_t acc9 = {0};
  acc9.unban_time = time(NULL) - 1;    /* already past */
  ck_assert_int_eq(account_is_banned(&acc9), 0);

/* ──  misc / safety  ─ */
}
END_TEST

START_TEST(test_account_free_null_ok)
{
#line 255
  account_free(NULL);   /* must be a no‑op */
}
END_TEST

int main(void)
{
    Suite *s1 = suite_create("account_suite");
    TCase *tc1_1 = tcase_create("account_create_test_case");
    TCase *tc1_2 = tcase_create("account_update_password_test_case");
    TCase *tc1_3 = tcase_create("account_create_edge_case");
    TCase *tc1_4 = tcase_create("account_set_email_edge_case");
    TCase *tc1_5 = tcase_create("password_edge_case");
    TCase *tc1_6 = tcase_create("login_tracking_edge_case");
    TCase *tc1_7 = tcase_create("ban_expiry_edge_case");
    TCase *tc1_8 = tcase_create("misc_edge_case");
    SRunner *sr = srunner_create(s1);
    int nf;

    suite_add_tcase(s1, tc1_1);
    tcase_add_test(tc1_1, test_account_create_works);
    suite_add_tcase(s1, tc1_2);
    tcase_add_test(tc1_2, test_account_update_password_neq_plaintext);
    tcase_add_test(tc1_2, test_account_validate_password_ok);
    tcase_add_test(tc1_2, test_account_update_account_old_password_neq_hash);
    suite_add_tcase(s1, tc1_3);
    tcase_add_test(tc1_3, test_account_create_password_too_short);
    tcase_add_test(tc1_3, test_account_create_password_min_len_ok);
    tcase_add_test(tc1_3, test_account_create_invalid_email_formats);
    tcase_add_test(tc1_3, test_account_create_email_too_long);
    tcase_add_test(tc1_3, test_account_create_userid_too_long_rejected);
    suite_add_tcase(s1, tc1_4);
    tcase_add_test(tc1_4, test_account_set_email_null_args);
    tcase_add_test(tc1_4, test_account_set_email_null_new_email);
    tcase_add_test(tc1_4, test_account_set_email_overlong);
    suite_add_tcase(s1, tc1_5);
    tcase_add_test(tc1_5, test_account_validate_password_wrong);
    tcase_add_test(tc1_5, test_account_update_password_empty_and_too_long);
    tcase_add_test(tc1_5, test_account_old_password_no_longer_valid);
    tcase_add_test(tc1_5, test_password_null_args);
    suite_add_tcase(s1, tc1_6);
    tcase_add_test(tc1_6, test_account_record_login_failure_increment);
    tcase_add_test(tc1_6, test_account_record_login_failure_no_overflow);
    tcase_add_test(tc1_6, test_account_record_login_success_sets_ip_and_resets_fail);
    tcase_add_test(tc1_6, test_account_record_login_success_null);
    suite_add_tcase(s1, tc1_7);
    tcase_add_test(tc1_7, test_account_set_unban_time_negative_no_change);
    tcase_add_test(tc1_7, test_account_set_unban_time_cap_to_max);
    tcase_add_test(tc1_7, test_account_is_banned_past_unban_time);
    suite_add_tcase(s1, tc1_8);
    tcase_add_test(tc1_8, test_account_free_null_ok);

    srunner_run_all(sr, CK_ENV);
    nf = srunner_ntests_failed(sr);
    srunner_free(sr);

    return nf == 0 ? 0 : 1;
}
