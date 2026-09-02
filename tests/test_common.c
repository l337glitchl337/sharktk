/* Unit tests for the shared common/net.h and common/dhcp.h helpers. */

#include <check.h>
#include <stdlib.h>
#include "../common/net.h"
#include "../common/dhcp.h"

START_TEST(test_cidr_from_netmask_common_masks)
{
    ck_assert_int_eq(cidr_from_netmask(0xFFFFFF00), 24);
    ck_assert_int_eq(cidr_from_netmask(0xFFFF0000), 16);
    ck_assert_int_eq(cidr_from_netmask(0xFF000000), 8);
    ck_assert_int_eq(cidr_from_netmask(0xFFFFFFFF), 32);
    ck_assert_int_eq(cidr_from_netmask(0x00000000), 0);
    ck_assert_int_eq(cidr_from_netmask(0xFFFFFFFE), 31);
}
END_TEST

START_TEST(test_add_dhcp_option_writes_code_len_data)
{
    uint8_t options[16] = {0};
    int offset = 0;
    uint32_t data = 0x01020304;

    add_dhcp_option(options, &offset, 53, 4, &data);

    ck_assert_uint_eq(options[0], 53);
    ck_assert_uint_eq(options[1], 4);
    ck_assert_mem_eq(&options[2], &data, 4);
    ck_assert_int_eq(offset, 6);
}
END_TEST

START_TEST(test_add_dhcp_option_no_data)
{
    uint8_t options[16] = {0};
    int offset = 0;

    add_dhcp_option(options, &offset, DHCP_OPTION_END, 0, NULL);

    ck_assert_uint_eq(options[0], DHCP_OPTION_END);
    ck_assert_uint_eq(options[1], 0);
    ck_assert_int_eq(offset, 2);
}
END_TEST

START_TEST(test_add_dhcp_option_appends_sequentially)
{
    uint8_t options[16] = {0};
    int offset = 0;
    uint8_t msg_type = 1;

    add_dhcp_option(options, &offset, DHCP_OPTION_MESSAGE_TYPE, 1, &msg_type);
    add_dhcp_option(options, &offset, DHCP_OPTION_END, 0, NULL);

    ck_assert_uint_eq(options[0], DHCP_OPTION_MESSAGE_TYPE);
    ck_assert_uint_eq(options[1], 1);
    ck_assert_uint_eq(options[2], 1);
    ck_assert_uint_eq(options[3], DHCP_OPTION_END);
    ck_assert_int_eq(offset, 5);
}
END_TEST

START_TEST(test_find_dhcp_option_found)
{
    uint8_t options[16] = {0};
    int offset = 0;
    uint32_t server_id = 0xAABBCCDD;

    add_dhcp_option(options, &offset, DHCP_OPTION_SERVER_ID, 4, &server_id);
    add_dhcp_option(options, &offset, DHCP_OPTION_END, 0, NULL);

    uint8_t *found = find_dhcp_option(options, sizeof(options), DHCP_OPTION_SERVER_ID);
    ck_assert_ptr_nonnull(found);
    ck_assert_mem_eq(found, &server_id, 4);
}
END_TEST

START_TEST(test_find_dhcp_option_not_present_stops_at_end)
{
    uint8_t options[16] = {0};
    int offset = 0;
    uint8_t msg_type = 1;

    add_dhcp_option(options, &offset, DHCP_OPTION_MESSAGE_TYPE, 1, &msg_type);
    add_dhcp_option(options, &offset, DHCP_OPTION_END, 0, NULL);

    uint8_t *found = find_dhcp_option(options, sizeof(options), DHCP_OPTION_SERVER_ID);
    ck_assert_ptr_null(found);
}
END_TEST

START_TEST(test_find_dhcp_option_skips_over_unrelated_options)
{
    uint8_t options[32] = {0};
    int offset = 0;
    uint8_t msg_type = 5;
    uint32_t lease_time = 86400;

    add_dhcp_option(options, &offset, DHCP_OPTION_MESSAGE_TYPE, 1, &msg_type);
    add_dhcp_option(options, &offset, DHCP_OPTION_LEASE_TIME, 4, &lease_time);
    add_dhcp_option(options, &offset, DHCP_OPTION_END, 0, NULL);

    uint8_t *found = find_dhcp_option(options, sizeof(options), DHCP_OPTION_LEASE_TIME);
    ck_assert_ptr_nonnull(found);
    ck_assert_mem_eq(found, &lease_time, 4);
}
END_TEST

START_TEST(test_set_dhcp_magic_cookie)
{
    uint8_t cookie[4] = {0};
    set_dhcp_magic_cookie(cookie);
    uint8_t expected[4] = {99, 130, 83, 99};
    ck_assert_mem_eq(cookie, expected, 4);
}
END_TEST

static Suite *common_suite(void)
{
    Suite *s = suite_create("common");
    TCase *tc = tcase_create("core");

    tcase_add_test(tc, test_cidr_from_netmask_common_masks);
    tcase_add_test(tc, test_add_dhcp_option_writes_code_len_data);
    tcase_add_test(tc, test_add_dhcp_option_no_data);
    tcase_add_test(tc, test_add_dhcp_option_appends_sequentially);
    tcase_add_test(tc, test_find_dhcp_option_found);
    tcase_add_test(tc, test_find_dhcp_option_not_present_stops_at_end);
    tcase_add_test(tc, test_find_dhcp_option_skips_over_unrelated_options);
    tcase_add_test(tc, test_set_dhcp_magic_cookie);

    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
    SRunner *sr = srunner_create(common_suite());
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
