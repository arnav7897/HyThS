cmake_minimum_required(VERSION 3.16)
project(hta_schnorr LANGUAGES CXX)

add_library(hta_framing src/framing.cpp)
target_include_directories(hta_framing PUBLIC include)
target_compile_features(hta_framing PUBLIC cxx_std_17)

enable_testing()
add_executable(framing_test tests/framing_test.cpp)
target_link_libraries(framing_test PRIVATE hta_framing)
add_test(NAME framing COMMAND framing_test)
