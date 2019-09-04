IF (NOT EXISTS "/opt/pentest/sniffing-spoofing/sniffjoke/build/install_manifest.txt")
    MESSAGE(FATAL_ERROR "Cannot find install manifest: \"/opt/pentest/sniffing-spoofing/sniffjoke/build/install_manifest.txt\"")
ENDIF(NOT EXISTS "/opt/pentest/sniffing-spoofing/sniffjoke/build/install_manifest.txt")

FILE(READ "/opt/pentest/sniffing-spoofing/sniffjoke/build/install_manifest.txt" files)
STRING(REGEX REPLACE "\n" ";" files "${files}")
FOREACH (file ${files})
    IF (EXISTS "$ENV{DESTDIR}${file}")
        EXECUTE_PROCESS(
            COMMAND /usr/bin/cmake -E remove "$ENV{DESTDIR}${file}"
            OUTPUT_VARIABLE rm_out
            RESULT_VARIABLE rm_retval
        )
        IF(NOT ${rm_retval} EQUAL 0)
            MESSAGE(FATAL_ERROR "Problem when removing \"$ENV{DESTDIR}${file}\"")
        ENDIF (NOT ${rm_retval} EQUAL 0)
    ELSE (EXISTS "$ENV{DESTDIR}${file}")
        MESSAGE(STATUS "File \"$ENV{DESTDIR}${file}\" does not exist.")
    ENDIF (EXISTS "$ENV{DESTDIR}${file}")
ENDFOREACH(file)
