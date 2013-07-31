mkdir tmp

cp -f ../gtime-test gtime/usr/bin/gtime
cp -f ../gtime-sign gtime/usr/bin/
cp -f ../gtime-verify gtime/usr/bin/
ln -f -s gtime gtime/usr/bin/gtime-test
gzip -c ../doc/gtime.1 > gtime/usr/share/man/man1/gtime.1.gz
gzip -c ../doc/gtime-test.1 > gtime/usr/share/man/man1/gtime-test.1.gz
cp -f ../doc/trust.pem gtime/usr/share/doc/gtime/
strip gtime*/usr/bin/gtime*

VER="`grep ^AC_INIT ../configure.ac | sed -e 's/^[^0-9.-]*//' -e 's/\].*$//'`"
echo ver: $VER
# REV=`svn info | grep Revision | sed "s/Revision:\s//i"`
REV=`git describe`
ARCH=`dpkg-architecture -qDEB_BUILD_ARCH`

do_subst="sed -e s/@VER@/$VER/g -e s/@REV@/$REV/g -e s/@ARCH@/$ARCH/g"

cp -r gtime tmp/
rm -rf `find tmp -name .svn`
rm -rf `find tmp -name .git`
$do_subst < gtime/DEBIAN/control > tmp/gtime/DEBIAN/control
fakeroot dpkg-deb --build tmp/gtime
mv tmp/gtime.deb gtime_${VER}_${ARCH}.deb

rm -rf tmp
