/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "android/audit_rate.h"

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/netlink.h>
#include <sys/socket.h>

#include <cstring>

namespace selogger {

bool SetAuditRateLimit(uint32_t rate) {
    android::base::unique_fd fd(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_AUDIT));
    if (fd < 0) {
        PLOG(ERROR) << "Cannot open the audit netlink socket";
        return false;
    }
    timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct {
        nlmsghdr header;
        audit_status status;
    } request = {};
    request.header.nlmsg_len = sizeof(request);
    request.header.nlmsg_type = AUDIT_SET;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.header.nlmsg_seq = 1;
    request.status.mask = AUDIT_STATUS_RATE_LIMIT;
    request.status.rate_limit = rate;

    sockaddr_nl kernel = {};
    kernel.nl_family = AF_NETLINK;
    if (TEMP_FAILURE_RETRY(sendto(fd, &request, sizeof(request), 0,
                                  reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel))) < 0) {
        PLOG(ERROR) << "Cannot send the audit rate limit";
        return false;
    }

    struct {
        nlmsghdr header;
        nlmsgerr error;
    } reply = {};
    ssize_t n = TEMP_FAILURE_RETRY(recv(fd, &reply, sizeof(reply), 0));
    if (n < static_cast<ssize_t>(sizeof(reply)) || reply.header.nlmsg_type != NLMSG_ERROR) {
        LOG(ERROR) << "No acknowledgement for the audit rate limit";
        return false;
    }
    if (reply.error.error != 0) {
        LOG(ERROR) << "Kernel refused the audit rate limit: " << strerror(-reply.error.error);
        return false;
    }
    LOG(INFO) << "Audit rate limit is now " << rate << "/s";
    return true;
}

}  // namespace selogger
