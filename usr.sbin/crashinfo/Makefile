SCRIPTS= crashinfo.sh
MAN=	crashinfo.8

PYTHON?= /usr/local/bin/python3.12
.PHONY: privacy-test
privacy-test:
	${PYTHON} -B ${.CURDIR}/tests/privacy_test.py

.include <bsd.prog.mk>
