/* Unit tests for sharkbait.c's pure helper functions. */

#include <check.h>
#include <stdlib.h>
#include <string.h>

#define main sharkbait_main_unused
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wreturn-type"
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#include "../sharkbait/sharkbait.c"
#pragma GCC diagnostic pop
#undef main

START_TEST(test_get_number_of_ips_slash_24)
{
    ck_assert_int_eq(get_number_of_ips(0xFFFFFF00), 254);
}
END_TEST

START_TEST(test_get_number_of_ips_slash_16)
{
    ck_assert_int_eq(get_number_of_ips(0xFFFF0000), 65534);
}
END_TEST

START_TEST(test_parse_dhcp_options_discover)
{
    Packet p;
    memset(&p, 0, sizeof(p));
    int offset = 0;
    uint8_t msg_type = 0x01;
    add_dhcp_option(p.dhcp.options, &offset, DHCP_OPTION_MESSAGE_TYPE, 1, &msg_type);
    p.dhcp.options[offset++] = DHCP_OPTION_END;

    ck_assert_int_eq(parse_dhcp_options(&p), 1);
}
END_TEST

START_TEST(test_parse_dhcp_options_request)
{
    Packet p;
    memset(&p, 0, sizeof(p));
    int offset = 0;
    uint8_t msg_type = 0x03;
    add_dhcp_option(p.dhcp.options, &offset, DHCP_OPTION_MESSAGE_TYPE, 1, &msg_type);
    p.dhcp.options[offset++] = DHCP_OPTION_END;

    ck_assert_int_eq(parse_dhcp_options(&p), 2);
}
END_TEST

START_TEST(test_parse_dhcp_options_end_immediately)
{
    Packet p;
    memset(&p, 0, sizeof(p));
    p.dhcp.options[0] = DHCP_OPTION_END;

    ck_assert_int_eq(parse_dhcp_options(&p), -1);
}
END_TEST

/* Regression test for issue #11: the loop used to fall off the end of the
 * function (undefined return value) if it ran out of options bytes
 * without hitting DHCP_OPTION_END or a recognized message type. */
START_TEST(test_parse_dhcp_options_runs_out_without_end_returns_unknown)
{
    Packet p;
    memset(&p, 0, sizeof(p)); /* no DHCP_OPTION_END anywhere in options[] */

    ck_assert_int_eq(parse_dhcp_options(&p), -1);
}
END_TEST

START_TEST(test_skip_reserved_lease_no_match_stays_unchanged)
{
    ck_assert_uint_eq(skip_reserved_lease(10, 50, 200), 10);
}
END_TEST

START_TEST(test_skip_reserved_lease_matches_gateway)
{
    ck_assert_uint_eq(skip_reserved_lease(50, 50, 200), 51);
}
END_TEST

START_TEST(test_skip_reserved_lease_matches_interface_ip)
{
    ck_assert_uint_eq(skip_reserved_lease(200, 50, 200), 201);
}
END_TEST

/* Regression test for the bug this replaced: a plain `if` (checked once)
 * would advance past the gateway and land directly on the interface IP
 * when the two are adjacent addresses, handing that lease out anyway.
 * skip_reserved_lease must keep advancing until clear of both. */
START_TEST(test_skip_reserved_lease_adjacent_gateway_then_ip)
{
    uint32_t gw = 100;
    uint32_t ip = 101; /* gw + 1 */
    ck_assert_uint_eq(skip_reserved_lease(gw, gw, ip), 102);
}
END_TEST

START_TEST(test_skip_reserved_lease_adjacent_ip_then_gateway)
{
    uint32_t ip = 100;
    uint32_t gw = 101; /* ip + 1 */
    ck_assert_uint_eq(skip_reserved_lease(ip, gw, ip), 102);
}
END_TEST

START_TEST(test_calc_base_ip_masks_correctly)
{
    uint32_t ip, netmask, base;
    inet_pton(AF_INET, "192.168.1.50", &ip);
    inet_pton(AF_INET, "255.255.255.0", &netmask);
    char base_str[INET_ADDRSTRLEN];

    calc_base_ip(&ip, &netmask, &base, base_str);

    ck_assert_str_eq(base_str, "192.168.1.0");
}
END_TEST

START_TEST(test_calc_base_ip_slash_16)
{
    uint32_t ip, netmask, base;
    inet_pton(AF_INET, "10.20.30.40", &ip);
    inet_pton(AF_INET, "255.255.0.0", &netmask);
    char base_str[INET_ADDRSTRLEN];

    calc_base_ip(&ip, &netmask, &base, base_str);

    ck_assert_str_eq(base_str, "10.20.0.0");
}
END_TEST

static Suite *sharkbait_suite(void)
{
    Suite *s = suite_create("sharkbait");
    TCase *tc = tcase_create("core");

    tcase_add_test(tc, test_get_number_of_ips_slash_24);
    tcase_add_test(tc, test_get_number_of_ips_slash_16);
    tcase_add_test(tc, test_parse_dhcp_options_discover);
    tcase_add_test(tc, test_parse_dhcp_options_request);
    tcase_add_test(tc, test_parse_dhcp_options_end_immediately);
    tcase_add_test(tc, test_parse_dhcp_options_runs_out_without_end_returns_unknown);
    tcase_add_test(tc, test_skip_reserved_lease_no_match_stays_unchanged);
    tcase_add_test(tc, test_skip_reserved_lease_matches_gateway);
    tcase_add_test(tc, test_skip_reserved_lease_matches_interface_ip);
    tcase_add_test(tc, test_skip_reserved_lease_adjacent_gateway_then_ip);
    tcase_add_test(tc, test_skip_reserved_lease_adjacent_ip_then_gateway);
    tcase_add_test(tc, test_calc_base_ip_masks_correctly);
    tcase_add_test(tc, test_calc_base_ip_slash_16);

    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
    SRunner *sr = srunner_create(sharkbait_suite());
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
