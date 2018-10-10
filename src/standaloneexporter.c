
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <zmq.h>

#include <libtrace_parallel.h>
#include <libwandder.h>
#include <libwandder_etsili.h>

#include "collector_export.h"
#include "util.h"
#include "logger.h"

volatile int collector_halt = 0;

static void cleanup_signal(int signal UNUSED)
{
        collector_halt = 1;
}


static void *start_export_thread(void *params) {
    export_thread_data_t *glob = (export_thread_data_t *)params;
    collector_export_t *exp = init_exporter(glob);

    if (exp == NULL) {
        logger(LOG_INFO, "OpenLI: exporting thread is not functional!");
        collector_halt = 1;
        pthread_exit(NULL);
    }

    while (collector_halt == 0) {
        if (exporter_thread_main(exp, &collector_halt) <= 0) {
            break;
        }
    }

    destroy_exporter(exp);
    logger(LOG_DEBUG, "OpenLI: exiting export thread.");
    pthread_exit(NULL);
}


int main(int argc, char *argv[]) {

    export_thread_data_t exporter;
    void *zmq_ctxt = NULL;
    struct sigaction sigact;
    sigset_t sig_before, sig_block_all;
    int i, ret;
    shared_global_info_t shared;

    sigact.sa_handler = cleanup_signal;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    signal(SIGPIPE, SIG_IGN);

    shared.operatorid = "whocares";
    shared.networkelemid = "teste";
    shared.intpointid = NULL;
    shared.provisionerip = NULL;
    shared.provisionerport = NULL;
    shared.operatorid_len = strlen(shared.operatorid);
    shared.networkelemid_len = strlen(shared.networkelemid);
    shared.intpointid_len = 0;

    zmq_ctxt = zmq_ctx_new();

    sigemptyset(&sig_block_all);
    if (pthread_sigmask(SIG_SETMASK, &sig_block_all, &sig_before) < 0) {
        logger(LOG_INFO, "Unable to disable signals before starting threads.");
        return 1;
    }

    memset(&exporter, 0, sizeof(exporter));
    exporter.zmq_ctxt = zmq_ctxt;
    exporter.workers = 2;
    exporter.shared = &shared;
    ret = pthread_create(&(exporter.threadid), NULL,
                start_export_thread, (void *)&(exporter));
    if (ret != 0) {
        return 1;
    }

    if (pthread_sigmask(SIG_SETMASK, &sig_before, NULL)) {
        logger(LOG_INFO, "Unable to re-enable signals after starting threads.");
        return 1;
    }

    while (!collector_halt) {
        sleep(1);
    }

    pthread_join(exporter.threadid, NULL);

    printf("done?\n");
    zmq_ctx_destroy(zmq_ctxt);
    return 0;


}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
