#define CITS3007_PERMISSIVE

#include "../src/account.h"
#include "../src/logging.h"
#include <check.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <limits.h>
#include <pthread.h>



/**
* @brief Replacement for the panic function during testing.
* Logs the panic message and aborts the program.
*
* @param msg Message to print before aborting.
*/
static void panic(const char *msg) {
    fprintf(stderr, "PANIC: %s\n", msg);
    abort();
}

/**
* @brief Mutex used to ensure thread-safe logging in unit tests.
*
* This mutex ensures that concurrent calls to `log_message` from different threads
* do not result in interleaved or corrupted log output. It is used to wrap the
* entire logging operation in a critical section.
*
* @note Only used in testing context; not designed for high-performance logging.
*/
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;


/**
* @brief Thread-safe logger function for unit testing output.
*
* This function prints formatted log messages to `stdout` or `stderr`, based on the log level:
* - LOG_INFO goes to `stdout`
* - LOG_DEBUG, LOG_WARN, LOG_ERROR go to `stderr`
*
* Each log line includes a level-specific prefix (e.g., "INFO: ") followed by the formatted message.
* It uses a mutex to ensure thread-safe output, so that messages from concurrent tests do not interleave.
*
* @param level The log severity level (LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR).
* @param fmt A `printf`-style format string.
* @param ... Additional arguments for formatting.
*
* @note This logger is intended for use in unit tests. It does not write to files or use timestamps.
*/
void log_message(log_level_t level, const char *fmt, ...) {
    pthread_mutex_lock(&log_mutex);

    va_list args;
    va_start(args, fmt);

    FILE *out = (level == LOG_INFO) ? stdout : stderr;
    switch (level) {
        case LOG_DEBUG: fprintf(out, "DEBUG: "); break;
        case LOG_INFO:  fprintf(out, "INFO: "); break;
        case LOG_WARN:  fprintf(out, "WARNING: "); break;
        case LOG_ERROR: fprintf(out, "ERROR: "); break;
        default:        fprintf(out, "UNKNOWN: "); break;
    }

    vfprintf(out, fmt, args);
    fprintf(out, "\n");

    va_end(args);
    pthread_mutex_unlock(&log_mutex);
}



/*Run with: gcc test_scripts/account_print_summary_test.c src/account.c -I./src -lcheck -lsodium -lsubunit -lpthread -lrt -lm -o test_scripts/account_print_summary_test
*/

/**
 * @test
 * @brief Verifies account_print_summary() prints correct fields for a normal account.
 *
 * This test checks for expected values in the output, including:
 * - User ID
 * - Email
 * - Login success/fail counts
 * - Birthdate
 * - IP address
 * - Last login timestamp (year match only)
 */
START_TEST(test_print_summary_normal_account) {
    log_message(LOG_INFO, "[TEST] Running test_print_summary_normal_account");

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

    log_message(LOG_DEBUG, "Initialized account with userid=%s, email=%s", acc.userid, acc.email);


    int pipefd[2];
    ck_assert_int_eq(pipe(pipefd), 0);

    bool result = account_print_summary(&acc, pipefd[1]);
    fsync(pipefd[1]);
    close(pipefd[1]);
    ck_assert(result);

    char output[2048] = {0};
    read(pipefd[0], output, sizeof(output));
    close(pipefd[0]);

    log_message(LOG_DEBUG, "Output received:\n%s", output);

    ck_assert_msg(strstr(output, "testuser"), "Expected userid in summary");
    ck_assert_msg(strstr(output, "test@example.com"), "Expected email in summary");
    ck_assert_msg(strstr(output, "Login Successes: 5"), "Expected login success count");
    ck_assert_msg(strstr(output, "Login Failures: 2"), "Expected login fail count");
    ck_assert_msg(strstr(output, "Birthdate: 2000-01-01"), "Expected birthdate");
    ck_assert_msg(strstr(output, "127.0.0.1"), "Expected last login IP");


    char year_buf[5];
    strftime(year_buf, sizeof(year_buf), "%Y", localtime(&acc.last_login_time));
    ck_assert_msg(strstr(output, year_buf), "Expected current year in last login time");
}
END_TEST

/**
 * @test
 * @brief Tests handling of a NULL account pointer.
 *
 * Ensures `account_print_summary()` safely returns false when given
 * a NULL `account_t *` input.
 *
 * @pre `account_print_summary(NULL, fd)` is called.
 * @post Function must return false and not crash.
 */
START_TEST(test_print_summary_null_input) {
    log_message(LOG_INFO, "[TEST] Starting test_print_summary_null_input");
    bool result = account_print_summary(NULL, STDOUT_FILENO);
    ck_assert(!result); 
}
END_TEST


/**
 * @test
 * @brief Tests handling of an invalid file descriptor.
 *
 * Ensures `account_print_summary()` fails and returns false
 * if the file descriptor is negative.
 *
 * @pre Valid `account_t` input, but invalid FD.
 * @post Function must return false.
 */
START_TEST(test_print_summary_invalid_fd) {
    log_message(LOG_INFO, "[TEST] Starting test_print_summary_invalid_fd");
    account_t acc = {0};
    strcpy(acc.userid, "user");


    bool result = account_print_summary(&acc, -1);
    ck_assert(!result);
}
END_TEST


/**
 * @test
 * @brief Validates that login_fail_count does not overflow at UINT_MAX.
 *
 * Simulates the login failure logic by setting the login failure count
 * to `UINT_MAX` and ensuring that invoking `account_record_login_failure()`
 * does not increment it further.
 *
 * @pre `login_fail_count == UINT_MAX`
 * @post `login_fail_count` remains unchanged after call.
 */
START_TEST(test_login_fail_count_max) {
    log_message(LOG_INFO, "[TEST] Starting test_login_fail_count_max");
    account_t acc = {0};
    acc.login_fail_count = UINT_MAX;

    account_record_login_failure(&acc);

    ck_assert_uint_eq(acc.login_fail_count, UINT_MAX);
}
END_TEST


/**
 * @test
 * @brief Simulates a write failure by closing the pipe before writing.
 *
 * Ensures `account_print_summary()` returns false if the pipe is
 * already closed (i.e., the write fails internally).
 *
 * @pre Close `pipefd[1]` before writing.
 * @post Function should return false due to write failure.
 */
START_TEST(test_print_summary_pipe_closed_before_write) {
    log_message(LOG_INFO, "[TEST] Starting test_print_summary_pipe_closed_before_write");
    account_t acc = {0};
    strcpy(acc.userid, "testuser");
    strcpy(acc.email, "test@example.com");
    strcpy(acc.birthdate, "2000-01-01");

    int pipefd[2];
    ck_assert_int_eq(pipe(pipefd), 0);

    close(pipefd[1]);  

    bool result = account_print_summary(&acc, pipefd[1]);
    ck_assert(!result);  
    close(pipefd[0]);
}
END_TEST


/**
 * @brief Creates the test suite for account_print_summary-related tests.
 *
 * This suite includes the following test cases:
 * - test_print_summary_normal_account: Validates the correctness of summary output.
 * - test_print_summary_null_input: Verifies behavior when given NULL account pointer.
 * - test_print_summary_invalid_fd: Verifies behavior with invalid file descriptor.
 * - test_login_fail_count_max: Ensures failure count doesn't wrap past UINT_MAX.
 * - Failed write detection (closed pipe)
 *
 * @return A pointer to the constructed test suite.
 */
Suite *account_summary_suite(void) {
    Suite *s = suite_create("AccountPrintSummary");
    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_print_summary_normal_account);
    tcase_add_test(tc_core, test_print_summary_null_input);
    tcase_add_test(tc_core, test_print_summary_invalid_fd);
    tcase_add_test(tc_core, test_login_fail_count_max);
    tcase_add_test(tc_core, test_print_summary_pipe_closed_before_write);


    suite_add_tcase(s, tc_core);
    return s;
}


/**
 * @brief Entry point for running the Check unit tests for account summary.
 *
 * This function constructs the test suite, runs all test cases, and reports results.
 * 
 * @return 0 if all tests pass, 1 otherwise.
 */
int main(void) {
    log_message(LOG_INFO, "[TEST SUITE] Starting account summary test suite");
    Suite *s = account_summary_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    log_message(LOG_INFO, "[TEST SUITE] Completed with %d failure(s)", failed);

    return (failed == 0) ? 0 : 1;
}