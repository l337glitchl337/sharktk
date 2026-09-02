/* Unit tests for sixshark.c's pure helper functions. */

#include <check.h>
#include <stdlib.h>

#define main sixshark_main_unused
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wreturn-type"
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#include "../sixshark/sixshark.c"
#pragma GCC diagnostic pop
#undef main

START_TEST(test_generate_random_prefix_is_valid_ipv6)
{
    char prefix[INET6_ADDRSTRLEN];
    generate_random_prefix(prefix);

    ck_assert_int_eq(prefix[0], 'f');
    ck_assert_int_eq(prefix[1], 'd');

    struct in6_addr addr;
    ck_assert_int_eq(inet_pton(AF_INET6, prefix, &addr), 1);
}
END_TEST

START_TEST(test_create_packet_fills_expected_fields)
{
    Packet p;
    uint8_t mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    const char *prefix = "fd00:dead:beef::";

    int ok = create_packet(&p, mac, prefix);
    ck_assert_int_eq(ok, 1);

    ck_assert_uint_eq(p.icmp6_hdr.type, 134);
    ck_assert_uint_eq(p.icmp6_hdr.code, 0);
    ck_assert_uint_eq(p.icmp6_hdr.data.data8[0], 64);   /* hop limit */
    ck_assert_uint_eq(p.icmp6_hdr.data.data8[1], 0);    /* flags */
    ck_assert_uint_eq(ntohs(p.icmp6_hdr.data.data16[1]), 65535); /* router lifetime */
    ck_assert_uint_eq(p.icmp6_hdr.r_time, 0);
    ck_assert_uint_eq(p.icmp6_hdr.rtrans_time, 0);

    ck_assert_uint_eq(p.prefix.type, 3);
    ck_assert_uint_eq(p.prefix.length, 4);
    ck_assert_uint_eq(p.prefix.prefix_len, 64);
    ck_assert_uint_eq(p.prefix.flags, 0xC0);
    ck_assert_uint_eq(ntohl(p.prefix.valid_lifetime), 86400);
    ck_assert_uint_eq(ntohl(p.prefix.preferred_lifetime), 86400);

    struct in6_addr expected;
    inet_pton(AF_INET6, prefix, &expected);
    ck_assert_mem_eq(&p.prefix.prefix, &expected, sizeof(expected));

    ck_assert_uint_eq(p.source_ll.type, 1);
    ck_assert_uint_eq(p.source_ll.length, 1);
    ck_assert_mem_eq(p.source_ll.mac, mac, 6);
}
END_TEST

START_TEST(test_create_packet_rejects_invalid_prefix)
{
    Packet p;
    uint8_t mac[6] = {0};
    int ok = create_packet(&p, mac, "not-an-ipv6-address");
    ck_assert_int_eq(ok, 0);
}
END_TEST

static Suite *sixshark_suite(void)
{
    Suite *s = suite_create("sixshark");
    TCase *tc = tcase_create("core");

    tcase_add_test(tc, test_generate_random_prefix_is_valid_ipv6);
    tcase_add_test(tc, test_create_packet_fills_expected_fields);
    tcase_add_test(tc, test_create_packet_rejects_invalid_prefix);

    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
    SRunner *sr = srunner_create(sixshark_suite());
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
