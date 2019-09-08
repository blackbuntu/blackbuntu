@echo off
@set CP=.;ojdbc14.jar;java-getopt-1.0.9.jar;oscanner.jar;oracleplugins.jar;reportengine.jar

java -classpath %CP% ork.OracleScanner %*
