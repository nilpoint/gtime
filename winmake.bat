rem place of platform sdk here:
set SDK=C:\Program Files\sdk
set INCLUDE=%SDK%\include;.;%INCLUDE%;\bld\capi\out\include;\bld\openssl\include
set LIB=%SDK%\lib;%LIB%;\bld\capi\out\lib;\bld\openssl\lib

cl /Ox /MT /DWIN32 /D_CRT_SECURE_NO_DEPRECATE /EHsc /Tp gtime-test.c hashchain.c gt_http.c getopt.c /link libgtbaseMT.lib libeay32MT.lib  user32.lib gdi32.lib advapi32.lib ws2_32.lib wininet.lib
