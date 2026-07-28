@echo off
echo Building Anti-RAT Security Mod with Java 21...
set "JAVA_EXE=%JAVA_HOME%\bin\java.exe"
"%JAVA_EXE%" -classpath gradle/wrapper/gradle-wrapper.jar org.gradle.wrapper.GradleWrapperMain build %*
