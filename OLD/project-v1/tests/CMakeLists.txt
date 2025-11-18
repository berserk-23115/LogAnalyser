cmake_minimum_required(VERSION 3.10)

# Test executable
add_executable(test_loganalyser
    test_main.c
    test_parser.c
    test_analyzer.c
)

# Link with core library
target_link_libraries(test_loganalyser PRIVATE loganalyser_core)

# Add tests
add_test(NAME ParserTests COMMAND test_loganalyser parser)
add_test(NAME AnalyzerTests COMMAND test_loganalyser analyzer)
add_test(NAME BufferTests COMMAND test_loganalyser buffer)

message(STATUS "Tests configured. Run 'ctest' or 'make test' to execute.")
