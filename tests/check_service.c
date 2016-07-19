#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "check.h"
#include "mdns.h"
#include "mdnsd.h"


struct mdnsd *svr;
char *hostname = "my_host.local";

static void setup(void) {
	svr = mdnsd_start();
	ck_assert_ptr_ne(svr, NULL);
}

static void teardown(void) {
	mdnsd_stop(svr);
}

START_TEST(Daemon_set_hostname) {
		mdnsd_set_hostname(svr, hostname, inet_addr("10.100.0.1"));
	}
END_TEST

START_TEST(Daemon_set_alternative_hostname) {
		struct rr_entry *a2_e = NULL;
		a2_e = rr_create_a(create_nlabel(hostname), inet_addr("192.168.0.10"));
		mdnsd_add_rr(svr, a2_e);
	}
END_TEST

START_TEST(Daemon_add_service) {
		const char *txt[] = {
				"path=/mywebsite",
				NULL
		};
		struct mdns_service *svc = mdnsd_register_svc(svr, "My Website",
													  "_http._tcp.local", 8080, NULL, txt);
		mdns_service_destroy(svc);
	}
END_TEST


static Suite* testSuite_mdns(void) {
	Suite *s = suite_create("mDNS test suite");
	TCase *tc_daemon = tcase_create("mDNS Daemon");
	tcase_add_unchecked_fixture(tc_daemon, setup, teardown);
	tcase_add_test(tc_daemon, Daemon_set_hostname);
	tcase_add_test(tc_daemon, Daemon_set_alternative_hostname);
	tcase_add_test(tc_daemon, Daemon_add_service);
	suite_add_tcase(s,tc_daemon);
	return s;
}

int main(void) {
	Suite *s = testSuite_mdns();
	SRunner *sr = srunner_create(s);
	srunner_set_fork_status(sr, CK_NOFORK);
	srunner_run_all(sr,CK_NORMAL);
	int number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
