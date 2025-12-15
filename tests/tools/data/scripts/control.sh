# sysbox sh control-flow smoke script
# Intentionally minimal: no vars except `for` loop variable.

rm -f /tmp/sysbox-test-flag

echo x > /tmp/sysbox-test-flag

if test -e /tmp/sysbox-test-flag; then
  echo IF_OK
else
  echo IF_BAD
fi

while test -e /tmp/sysbox-test-flag; do
  echo LOOP
  rm /tmp/sysbox-test-flag
done

echo AFTER

for x in a bb c; do
  echo $x
done
