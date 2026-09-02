/* Unit tests for cardshark.c's pure helper functions.
 * Pulls in the tool's source directly (renaming its main so it doesn't
 * collide with this file's own main) rather than modifying cardshark.c. */

#include <check.h>
#include <stdlib.h>

#define main cardshark_main_unused
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wreturn-type"
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#include "../cardshark/cardshark.c"
#pragma GCC diagnostic pop
#undef main

START_TEST(test_unpack_to_string_zero)
{
    char buf[16];
    unpack_to_string(0, buf, sizeof(buf));
    ck_assert_str_eq(buf, "0.0.0.0");
}
END_TEST

START_TEST(test_unpack_to_string_typical_ip)
{
    char buf[16];
    int addr = (192 << 24) | (168 << 16) | (1 << 8) | 1;
    unpack_to_string(addr, buf, sizeof(buf));
    ck_assert_str_eq(buf, "192.168.1.1");
}
END_TEST

START_TEST(test_unpack_to_string_all_bits_set)
{
    /* addr = 0xFFFFFFFF as a signed int is negative; confirms the
     * sign-extension-then-mask arithmetic still yields 255.255.255.255. */
    char buf[16];
    unpack_to_string((int)0xFFFFFFFF, buf, sizeof(buf));
    ck_assert_str_eq(buf, "255.255.255.255");
}
END_TEST

START_TEST(test_get_cidr_slash_24)
{
    ck_assert_int_eq(get_cidr(0xFFFFFF00), 24);
}
END_TEST

START_TEST(test_get_cidr_slash_16)
{
    ck_assert_int_eq(get_cidr((int)0xFFFF0000), 16);
}
END_TEST

START_TEST(test_get_cidr_slash_32)
{
    ck_assert_int_eq(get_cidr((int)0xFFFFFFFF), 32);
}
END_TEST

static Suite *cardshark_suite(void)
{
    Suite *s = suite_create("cardshark");
    TCase *tc = tcase_create("core");

    tcase_add_test(tc, test_unpack_to_string_zero);
    tcase_add_test(tc, test_unpack_to_string_typical_ip);
    tcase_add_test(tc, test_unpack_to_string_all_bits_set);
    tcase_add_test(tc, test_get_cidr_slash_24);
    tcase_add_test(tc, test_get_cidr_slash_16);
    tcase_add_test(tc, test_get_cidr_slash_32);

    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
    SRunner *sr = srunner_create(cardshark_suite());
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
