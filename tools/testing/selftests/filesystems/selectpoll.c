// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <asm/unistd.h>
#include <poll.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/select.h>
#include <sys/socket.h>
#include "../kselftest_harness.h"

const unsigned long timeout_us = 5UL * 1000;
const unsigned long timeout_ns = timeout_us * 1000;

/* (p)select: basic invocation, optionally with data waiting */

FIXTURE(select_basic)
{
	fd_set readfds;
	int sfd[2];
};

FIXTURE_VARIANT(select_basic)
{
	bool time_out;		/* expect select call to time out */
};

FIXTURE_VARIANT_ADD(select_basic, time_out)
{
	.time_out = true,
};

FIXTURE_VARIANT_ADD(select_basic, data_ready)
{
	.time_out = false,
};

FIXTURE_SETUP(select_basic)
{
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, self->sfd), 0);

	if (!variant->time_out)
		ASSERT_EQ(write(self->sfd[1], "w", 1), 1);

	FD_ZERO(&self->readfds);
	FD_SET(self->sfd[0], &self->readfds);
	FD_SET(self->sfd[1], &self->readfds);
}

FIXTURE_TEARDOWN(select_basic)
{
	if (variant->time_out) {
		ASSERT_EQ(FD_ISSET(self->sfd[0], &self->readfds), 0);
	} else {
		ASSERT_NE(FD_ISSET(self->sfd[0], &self->readfds), 0);
	}

	ASSERT_EQ(FD_ISSET(self->sfd[1], &self->readfds), 0);

	EXPECT_EQ(close(self->sfd[0]), 0);
	EXPECT_EQ(close(self->sfd[1]), 0);
}

TEST_F(select_basic, select)
{
	/* do not time out unless timeout limit is set */
	if (variant->time_out) {
		FD_ZERO(&self->readfds);
		return;
	}

	ASSERT_EQ(select(self->sfd[1] + 1, &self->readfds,
			 NULL, NULL, NULL), 1);
}

TEST_F(select_basic, select_timeout)
{
	struct timeval tv = { .tv_usec = timeout_us };

	ASSERT_EQ(select(self->sfd[1] + 1, &self->readfds,
			 NULL, NULL, &tv), !variant->time_out);

	if (!variant->time_out)
		ASSERT_GE(tv.tv_usec, 1000);
}

TEST_F(select_basic, pselect)
{
	/* do not time out unless timeout limit is set */
	if (variant->time_out) {
		FD_ZERO(&self->readfds);
		return;
	}

	ASSERT_EQ(pselect(self->sfd[1] + 1, &self->readfds,
			  NULL, NULL, NULL, NULL), 1);
}

TEST_F(select_basic, pselect_timeout)
{
	struct timespec ts = { .tv_nsec = timeout_ns };

	ASSERT_EQ(pselect(self->sfd[1] + 1, &self->readfds,
			  NULL, NULL, &ts, NULL), !variant->time_out);

	if (!variant->time_out)
		ASSERT_GE(ts.tv_nsec, 1000);
}

TEST_F(select_basic, pselect_sigset)
{
	sigset_t sigmask;

	/* do not time out unless timeout limit is set */
	if (variant->time_out) {
		FD_ZERO(&self->readfds);
		return;
	}

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGUSR1);
	sigprocmask(SIG_SETMASK, &sigmask, NULL);
	sigemptyset(&sigmask);

	ASSERT_EQ(pselect(self->sfd[1] + 1, &self->readfds,
			  NULL, NULL, NULL, &sigmask), 1);
}

TEST_F(select_basic, pselect_sigset_timeout)
{
	struct timespec ts = { .tv_nsec = timeout_ns };
	sigset_t sigmask;

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGUSR1);
	sigprocmask(SIG_SETMASK, &sigmask, NULL);
	sigemptyset(&sigmask);

	ASSERT_EQ(pselect(self->sfd[1] + 1, &self->readfds,
			  NULL, NULL, &ts, &sigmask), !variant->time_out);

	if (!variant->time_out)
		ASSERT_GE(ts.tv_nsec, 1000);
}

/* (p)poll: basic invocation with data waiting */

FIXTURE(poll_basic)
{
	struct pollfd pfds[2];
	int sfd[2];
};

FIXTURE_VARIANT(poll_basic)
{
	bool time_out;		/* expect poll call to time out */
};

FIXTURE_VARIANT_ADD(poll_basic, time_out)
{
	.time_out = true,
};

FIXTURE_VARIANT_ADD(poll_basic, data_ready)
{
	.time_out = false,
};

FIXTURE_SETUP(poll_basic)
{
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, self->sfd), 0);

	if (!variant->time_out)
		ASSERT_EQ(write(self->sfd[1], "w", 1), 1);

	self->pfds[0].events = POLLIN;
	self->pfds[0].revents = 0;
	self->pfds[0].fd = self->sfd[0];
	self->pfds[1].events = POLLIN;
	self->pfds[1].revents = 0;
	self->pfds[1].fd = self->sfd[1];
}

FIXTURE_TEARDOWN(poll_basic)
{
	if (variant->time_out) {
		EXPECT_EQ(self->pfds[0].revents & POLLIN, 0);
	} else {
		EXPECT_EQ(self->pfds[0].revents & POLLIN, POLLIN);
	}
	EXPECT_EQ(self->pfds[1].revents & POLLIN, 0);

	EXPECT_EQ(close(self->sfd[0]), 0);
	EXPECT_EQ(close(self->sfd[1]), 0);
}

TEST_F(poll_basic, poll)
{
	/* do not time out unless timeout limit is set */
	if (variant->time_out)
		return;

	EXPECT_EQ(poll(self->pfds, ARRAY_SIZE(self->pfds), 0), 1);
}

TEST_F(poll_basic, poll_timeout)
{
	EXPECT_EQ(poll(self->pfds, ARRAY_SIZE(self->pfds), 1001),
		  !variant->time_out);
}

TEST_F(poll_basic, ppoll)
{
	/* do not time out unless timeout limit is set */
	if (variant->time_out)
		return;

	EXPECT_EQ(ppoll(self->pfds, ARRAY_SIZE(self->pfds), NULL, NULL),
		  !variant->time_out);
}

TEST_F(poll_basic, ppoll_timeout)
{
	struct timespec ts = { .tv_nsec = timeout_ns };

	EXPECT_EQ(ppoll(self->pfds, ARRAY_SIZE(self->pfds), &ts, NULL),
		  !variant->time_out);

	if (!variant->time_out)
		ASSERT_GE(ts.tv_nsec, 1000);
}

TEST_F(poll_basic, ppoll_sigset)
{
	sigset_t sigmask;

	/* do not time out unless timeout limit is set */
	if (variant->time_out)
		return;

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGUSR1);
	sigprocmask(SIG_SETMASK, &sigmask, NULL);
	sigemptyset(&sigmask);

	EXPECT_EQ(ppoll(self->pfds, ARRAY_SIZE(self->pfds), NULL, &sigmask), 1);
}

TEST_F(poll_basic, ppoll_sigset_timeout)
{
	struct timespec ts = { .tv_nsec = timeout_ns };
	sigset_t sigmask;

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGUSR1);
	sigprocmask(SIG_SETMASK, &sigmask, NULL);
	sigemptyset(&sigmask);

	EXPECT_EQ(ppoll(self->pfds, ARRAY_SIZE(self->pfds), &ts, &sigmask),
		  !variant->time_out);

	if (!variant->time_out)
		ASSERT_GE(ts.tv_nsec, 1000);
}

TEST_HARNESS_MAIN
