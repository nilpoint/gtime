AC_INIT([gtime], [1.0-12])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.9 no-define foreign])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AC_PROG_LN_S
AC_CHECK_LIB([crypto], [SHA256_Init], [], [AC_MSG_FAILURE([Could not find OpenSSL 0.9.8+ development library])])
# AC_CHECK_LIB([gtbase], [GT_init], [LIBS="-Wl,-Bstatic -lgtbase -Wl,-Bdynamic $LIBS"], [AC_MSG_FAILURE([Could not find GuardTime C API base library])])
AC_CHECK_LIB([gtbase], [GT_init], [], [AC_MSG_FAILURE([Could not find Guardtime C API base library])])
AC_CHECK_LIB([curl], [curl_global_init], [], [AC_MSG_FAILURE([Could not find libcurl])])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

