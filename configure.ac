AC_INIT([gtime], [1.0-14])
AC_PREREQ([2.59])
AC_CONFIG_AUX_DIR([build-aux])
AC_CANONICAL_TARGET
dnl # AM_INIT_AUTOMAKE([1.9 no-define foreign])
AM_INIT_AUTOMAKE(
  1.9 
  no-define foreign
  m4_ifndef([AM_PROG_INSTALL], [serial-tests]) 
)
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AC_PROG_LN_S
AC_CHECK_LIB([crypto], [SHA256_Init], [], [AC_MSG_FAILURE([Could not find OpenSSL 0.9.8+ development library])])
dnl # AC_CHECK_LIB([gtbase], [GT_init], [LIBS="-Wl,-Bstatic -lgtbase -Wl,-Bdynamic $LIBS"], [AC_MSG_FAILURE([Could not find GuardTime C API base library])])
AC_CHECK_LIB([gtbase], [GT_init], [], [AC_MSG_FAILURE([Could not find Guardtime C API base library])])
AC_CHECK_LIB([curl], [curl_global_init], [], [AC_MSG_FAILURE([Could not find libcurl])])

case "${target_os}" in
    darwin*)
        CFLAGS="$CFLAGS -mmacosx-version-min=10.5"
        LDFLAGS="$LDFALGS -mmacosx-version-min=10.5"
        ;;
esac

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
