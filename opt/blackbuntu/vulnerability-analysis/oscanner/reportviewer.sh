#!/bin/sh
#
#

JAVA=java
CP=.:ojdbc14.jar:java-getopt-1.0.9.jar:oscanner.jar:oracleplugins.jar:reportengine.jar
$JAVA -cp $CP cqure.repeng.ReportViewer $*