/* Unit tests for sharkdns.c's packet-parsing functions.
 *
 * parse_msg() and build_reply() are where the 3 critical memory-safety
 * bugs (issues #1-#3) lived, so beyond basic correctness these tests
 * include regression cases that reproduce the original malformed-input
 * scenarios. Check runs each test in its own forked process by default,
 * so if a future regression reintroduces a crash here, it shows up as a
 * clean test failure instead of taking down the whole test binary. */

/* Must come before any system header (via <check.h> or otherwise) so the
 * POSIX feature-test macro is active from the start -- sharkdns.c defines
 * this itself, but only after this file's own includes would already run. */
#define _POSIX_C_SOURCE 200809L

#include <check.h>
#include <stdlib.h>
#include <string.h>

#define main sharkdns_main_unused
#include "../sharkdns/sharkdns.c"
#undef main

/* 12-byte header + "example.com" A/IN question, 29 bytes total. */
static const uint8_t valid_query[] = {
    0x12, 0x34,             /* id */
    0x01, 0x00,             /* flags: QR=0 (query), RD=1 */
    0x00, 0x01,             /* qdcount = 1 */
    0x00, 0x00,             /* ancount */
    0x00, 0x00,             /* nscount */
    0x00, 0x00,             /* arcount */
    0x07, 'e','x','a','m','p','l','e',
    0x03, 'c','o','m',
    0x00,                   /* end of qname */
    0x00, 0x01,             /* qtype = A */
    0x00, 0x01              /* qclass = IN */
};

START_TEST(test_parse_msg_valid_query)
{
    uint8_t buf[BUF_SIZE] = {0};
    memcpy(buf, valid_query, sizeof(valid_query));

    DNSMessage *msg = (DNSMessage *)buf;
    char qname[LINE_LENGTH_DOMAIN];
    char qtype_str[8];

    parse_msg(buf, msg, qname, qtype_str);

    ck_assert_str_eq(qname, "example.com");
    ck_assert_str_eq(qtype_str, "A");
}
END_TEST

START_TEST(test_parse_msg_response_packet_is_ignored)
{
    uint8_t buf[BUF_SIZE] = {0};
    memcpy(buf, valid_query, sizeof(valid_query));
    buf[2] = 0x81; /* set the QR bit: this is a response, not a query */

    DNSMessage *msg = (DNSMessage *)buf;
    char qname[LINE_LENGTH_DOMAIN];
    qname[0] = '\1'; /* sentinel so we can tell parse_msg left it alone */
    char qtype_str[8];

    parse_msg(buf, msg, qname, qtype_str);

    ck_assert_int_eq(qname[0], '\1');
}
END_TEST

/* Regression test for issue #1: a label chain that never contains a
 * terminating zero byte anywhere in the buffer. Before the fix, this
 * drove `pos` past the end of the 512-byte allocation and overflowed
 * `qname[]`. If that ever regresses, this crashes -- and Check reports
 * that as a failing test instead of losing the whole suite. */
START_TEST(test_parse_msg_non_terminating_labels_does_not_crash)
{
    uint8_t *buf = malloc(BUF_SIZE);
    ck_assert_ptr_nonnull(buf);
    memset(buf, 0, sizeof(DNSMessage));

    /* Fill the entire question section with an alternating
     * [length=1][content] pattern that never contains a literal 0x00. */
    for(size_t i = sizeof(DNSMessage); i < BUF_SIZE; i += 2)
    {
        buf[i] = 0x01;
        if(i + 1 < BUF_SIZE)
        {
            buf[i + 1] = 'A';
        }
    }

    DNSMessage *msg = (DNSMessage *)buf;
    char qname[LINE_LENGTH_DOMAIN];
    char qtype_str[8];

    parse_msg(buf, msg, qname, qtype_str);

    ck_assert_uint_lt(strnlen(qname, LINE_LENGTH_DOMAIN), LINE_LENGTH_DOMAIN);

    free(buf);
}
END_TEST

START_TEST(test_build_reply_valid_query)
{
    uint8_t buf[BUF_SIZE] = {0};
    memcpy(buf, valid_query, sizeof(valid_query));
    DNSMessage *msg = (DNSMessage *)buf;

    int reply_len = 0;
    uint8_t *reply = build_reply(msg, buf, &reply_len, "93.184.216.34");
    ck_assert_ptr_nonnull(reply);

    DNSMessage *reply_hdr = (DNSMessage *)reply;
    ck_assert_uint_eq(reply_hdr->id, msg->id);
    ck_assert_uint_eq(ntohs(reply_hdr->an_count), 1);

    struct in_addr expected;
    inet_pton(AF_INET, "93.184.216.34", &expected);
    ck_assert_mem_eq(reply + reply_len - sizeof(expected), &expected, sizeof(expected));

    free(reply);
}
END_TEST

/* Regression test for issue #2: a question section with no terminating
 * zero byte anywhere in the 512-byte buffer. Before the fix, build_reply
 * would still compute a `len` that, combined with the trailing answer
 * record, overflowed the fixed-size 512-byte reply_buf allocation. */
START_TEST(test_build_reply_long_question_stays_in_bounds)
{
    uint8_t *buf = malloc(BUF_SIZE);
    ck_assert_ptr_nonnull(buf);
    memset(buf, 0, sizeof(DNSMessage));
    /* Fill the rest of the buffer with non-zero bytes: no terminator. */
    memset(buf + sizeof(DNSMessage), 'A', BUF_SIZE - sizeof(DNSMessage));

    DNSMessage *msg = (DNSMessage *)buf;
    int reply_len = 0;
    uint8_t *reply = build_reply(msg, buf, &reply_len, "1.2.3.4");
    ck_assert_ptr_nonnull(reply);

    /* This is the exact invariant that was violated by the original bug:
     * reply_len must never exceed reply_buf's actual allocation size. */
    ck_assert_int_le(reply_len, BUF_SIZE);

    free(reply);
    free(buf);
}
END_TEST

START_TEST(test_format_timestamp_produces_nonempty_string)
{
    char timestamp[32];
    format_timestamp(timestamp, sizeof(timestamp));
    ck_assert_uint_gt(strlen(timestamp), 0);
}
END_TEST

static Suite *sharkdns_suite(void)
{
    Suite *s = suite_create("sharkdns");
    TCase *tc = tcase_create("core");

    tcase_add_test(tc, test_parse_msg_valid_query);
    tcase_add_test(tc, test_parse_msg_response_packet_is_ignored);
    tcase_add_test(tc, test_parse_msg_non_terminating_labels_does_not_crash);
    tcase_add_test(tc, test_build_reply_valid_query);
    tcase_add_test(tc, test_build_reply_long_question_stays_in_bounds);
    tcase_add_test(tc, test_format_timestamp_produces_nonempty_string);

    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
    SRunner *sr = srunner_create(sharkdns_suite());
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
