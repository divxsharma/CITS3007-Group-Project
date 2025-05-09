
#define CITS3007_PERMISSIVE

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

#include "../src/account.h"
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