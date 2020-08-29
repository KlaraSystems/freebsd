# $FreeBSD$

PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/posixshm

ATF_TESTS_C+=	posixshm_test

CFLAGS.posixshm_test+= -I${SRCTOP}/lib/libc/include

.include <bsd.test.mk>
