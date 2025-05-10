
#define CITS3007_PERMISSIVE

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <arpa/inet.h>


#include "../src/account.h"
#include "../src/banned.h"
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

