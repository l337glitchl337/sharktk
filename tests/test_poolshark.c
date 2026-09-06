/* Unit tests for poolshark.c's pure helper functions. */

#include <check.h>
#include <stdlib.h>
#include <string.h>

#define main poolshark_main_unused
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wreturn-type"
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#include "../poolshark/poolshark.c"
#pragma GCC diagnostic pop
#undef main

START_TEST(test_spoof_mac_sets_locally_administered_bit)
{
    uint8_t mac[6] = {0};
    spoof_mac(mac);

    ck_assert_uint_eq(mac[0] & 0x01, 0);    /* multicast bit must be clear */
    ck_assert_uint_eq(mac[0] & 0x02, 0x02); /* locally-administered bit must be set */
}
END_TEST

START_TEST(test_rand_transaction_id_carries_magic_tag)
{
    uint8_t id[4] = {0};
    rand_transaction_id(id);

    uint32_t xid;
    memcpy(&xid, id, 4);
    xid = ntohl(xid);

    ck_assert_uint_eq(xid >> 16, MAGIC_TAG);
}
END_TEST

START_TEST(test_calc_ip_checksum_validates)
{
    Packet p;
    memset(&p, 0, sizeof(p));
    p.ip.version_ihl = 0x45;
    p.ip.total_len = htons(20 + 8 + 552);
    p.ip.ttl = 64;
    p.ip.proto = 17;
    memset(p.ip.src_ip, 0x0A, sizeof(p.ip.src_ip));
    memset(p.ip.dst_ip, 0xC0, sizeof(p.ip.dst_ip));

    calc_ip_checksum(&p);

    /* Standard checksum validation: summing every 16-bit word of the
     * header, including the checksum field itself, must fold to 0xFFFF. */
    uint32_t sum = 0;
    uint16_t word;
    for(size_t i = 0; i < sizeof(p.ip) / 2; i++)
    {
        memcpy(&word, (uint8_t *)&p.ip + (i * 2), sizeof(uint16_t));
        sum += ntohs(word);
    }
    while(sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    ck_assert_uint_eq(sum, 0xFFFF);
}
END_TEST

START_TEST(test_netmask_to_cidr_slash_24)
{
    ck_assert_int_eq(netmask_to_cidr(0xFFFFFF00UL), 24);
}
END_TEST

START_TEST(test_netmask_to_cidr_slash_8)
{
    ck_assert_int_eq(netmask_to_cidr(0xFF000000UL), 8);
}
END_TEST

START_TEST(test_get_lease_time_extracts_value)
{
    Packet offer;
    memset(&offer, 0, sizeof(offer));
    int offset = 0;
    uint32_t lease_time = htonl(86400);
    add_dhcp_option(offer.dhcp.options, &offset, DHCP_OPTION_LEASE_TIME, 4, &lease_time);
    offer.dhcp.options[offset++] = DHCP_OPTION_END;

    Exausted new_node;
    memset(&new_node, 0, sizeof(new_node));
    get_lease_time(&offer, &new_node);

    ck_assert_uint_eq(new_node.lease_time, 86400);
}
END_TEST

START_TEST(test_init_packet_builds_valid_discover_shaped_packet)
{
    Packet *p = init_packet();
    ck_assert_ptr_nonnull(p);

    ck_assert_uint_eq(ntohs(p->eth.eth_type), 0x0800);
    ck_assert_uint_eq(p->ip.version_ihl, 0x45);
    ck_assert_uint_eq(ntohs(p->ip.total_len), 20 + 8 + 552);
    ck_assert_uint_eq(ntohs(p->ip.flags_offset), 0x4000); /* DF bit */
    ck_assert_uint_eq(p->ip.proto, 17);                   /* UDP */
    ck_assert_uint_eq(ntohs(p->udp.src_port), 68);
    ck_assert_uint_eq(ntohs(p->udp.dst_port), 67);
    ck_assert_uint_eq(p->dhcp.flags[0], 0x80);            /* BROADCAST flag */
    ck_assert_mem_eq(p->dhcp.client_mac, p->eth.src_mac, sizeof(p->eth.src_mac));

    /* Locally-administered spoofed source MAC, same invariant spoof_mac()
     * guarantees on its own -- see test_spoof_mac_sets_locally_administered_bit. */
    ck_assert_uint_eq(p->eth.src_mac[0] & 0x02, 0x02);

    /* calc_ip_checksum() ran as the last step: the IP header must already
     * fold to 0xFFFF, the same invariant test_calc_ip_checksum_validates
     * checks directly. */
    uint32_t sum = 0;
    uint16_t word;
    for(size_t i = 0; i < sizeof(p->ip) / 2; i++)
    {
        memcpy(&word, (uint8_t *)&p->ip + (i * 2), sizeof(uint16_t));
        sum += ntohs(word);
    }
    while(sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    ck_assert_uint_eq(sum, 0xFFFF);

    free(p);
}
END_TEST

static Suite *poolshark_suite(void)
{
    Suite *s = suite_create("poolshark");
    TCase *tc = tcase_create("core");

    tcase_add_test(tc, test_spoof_mac_sets_locally_administered_bit);
    tcase_add_test(tc, test_rand_transaction_id_carries_magic_tag);
    tcase_add_test(tc, test_calc_ip_checksum_validates);
    tcase_add_test(tc, test_netmask_to_cidr_slash_24);
    tcase_add_test(tc, test_netmask_to_cidr_slash_8);
    tcase_add_test(tc, test_get_lease_time_extracts_value);
    tcase_add_test(tc, test_init_packet_builds_valid_discover_shaped_packet);

    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
    SRunner *sr = srunner_create(poolshark_suite());
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
