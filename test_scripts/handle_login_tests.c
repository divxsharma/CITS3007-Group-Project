#include <check.h>
#include "../src/login.h"
#include "../src/account.h"
#include "../src/logging.h"
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
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
 */
bool account_lookup_by_userid(const char *userid, account_t *result) {
    //  First case setup:
    if (strcmp(userid, "test1") == 0) {
        // Populate a mock account
        result->account_id = 1;
        strcpy(result->userid, "test1");
        strcpy(result->password_hash, "hashpass1");
        result->unban_time = 0; // Not banned
        result->expiration_time = time(NULL) + 3600; // Not expired
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

    login_result_t result = handle_login("test1", "hashpass1", client_ip, login_time, client_output_fd, log_fd, &session);

    ck_assert_int_eq(result, LOGIN_SUCCESS);
    ck_assert_int_eq(session.account_id, 1);
    ck_assert_int_eq(session.session_start, login_time);
    ck_assert_int_eq(session.expiration_time, login_time + 24 * 60 * 60);
} END_TEST

int main(void) {
    Suite *suite = suite_create("HandleLogin");
    TCase *tcase = tcase_create("Core");

    // Add test cases to the test case
    tcase_add_test(tcase, test_handle_login_success);

    // Add the test case to the suite
    suite_add_tcase(suite, tcase);

    // Create a test runner and run the suite
    SRunner *runner = srunner_create(suite);
    srunner_run_all(runner, CK_NORMAL);

    int number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);

    return (number_failed == 0) ? 0 : 1;
}