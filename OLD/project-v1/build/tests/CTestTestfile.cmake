# CMake generated Testfile for 
# Source directory: /Users/anushkkumar/Downloads/Project_Aks/tests
# Build directory: /Users/anushkkumar/Downloads/Project_Aks/build/tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(ParserTests "/Users/anushkkumar/Downloads/Project_Aks/build/tests/test_loganalyser" "parser")
set_tests_properties(ParserTests PROPERTIES  _BACKTRACE_TRIPLES "/Users/anushkkumar/Downloads/Project_Aks/tests/CMakeLists.txt;14;add_test;/Users/anushkkumar/Downloads/Project_Aks/tests/CMakeLists.txt;0;")
add_test(AnalyzerTests "/Users/anushkkumar/Downloads/Project_Aks/build/tests/test_loganalyser" "analyzer")
set_tests_properties(AnalyzerTests PROPERTIES  _BACKTRACE_TRIPLES "/Users/anushkkumar/Downloads/Project_Aks/tests/CMakeLists.txt;15;add_test;/Users/anushkkumar/Downloads/Project_Aks/tests/CMakeLists.txt;0;")
add_test(BufferTests "/Users/anushkkumar/Downloads/Project_Aks/build/tests/test_loganalyser" "buffer")
set_tests_properties(BufferTests PROPERTIES  _BACKTRACE_TRIPLES "/Users/anushkkumar/Downloads/Project_Aks/tests/CMakeLists.txt;16;add_test;/Users/anushkkumar/Downloads/Project_Aks/tests/CMakeLists.txt;0;")
