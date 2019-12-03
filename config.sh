#!/bin/sh

cd ace
mvn eclipse:eclipse
cd ..

cd californium-group-oscore
mvn eclipse:eclipse
cd ..

cd vinnova-prototype
mvn eclipse:eclipse
cd ..

#Check that the ace/db.pwd file exists
FILE=ace/db.pwd
if [ ! -f "$FILE" ]; then
 echo
 echo "Warning: File ace/db.pwd is missing!"
 echo
fi

#Check that the vinnova-prototype/db.pwd file exists
FILE=vinnova-prototype/db.pwd
if [ ! -f "$FILE" ]; then
 echo
 echo "Warning: File vinnova-prototype/db.pwd is missing!"
 echo
fi

