cmake_minimum_required(VERSION 3.16)
project(c2_framework LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Тип сборки по умолчанию
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# --- Клиент (C) ---
add_executable(client client.c)

find_package(Threads REQUIRED)
target_link_libraries(client PRIVATE Threads::Threads)

if(WIN32)
    target_link_libraries(client PRIVATE ws2_32 advapi32)
    target_compile_definitions(client PRIVATE _CRT_SECURE_NO_WARNINGS)
elseif(UNIX AND NOT APPLE)
    target_link_libraries(client PRIVATE m) # на всякий случай
endif()

if(MSVC)
    target_compile_options(client PRIVATE /W4 /O2)
else()
    target_compile_options(client PRIVATE -Wall -Wextra -O2)
endif()

# --- Сервер (Python) ---
# Находим Python и проверяем синтаксис server.py при сборке
find_package(Python3 COMPONENTS Interpreter REQUIRED)

add_custom_target(server_check ALL
    COMMAND ${Python3_EXECUTABLE} -m py_compile ${CMAKE_CURRENT_SOURCE_DIR}/server.py
    COMMENT "Checking server.py syntax..."
    VERBATIM
)

# --- Установка ---
include(GNUInstallDirs)
install(TARGETS client RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES server.py DESTINATION ${CMAKE_INSTALL_DATADIR}/c2)
