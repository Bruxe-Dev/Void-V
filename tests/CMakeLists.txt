foreach(test_name storage_test auth_test encryption_test vault_test broker_test)
    add_executable(${test_name} ${test_name}.cpp test_util.hpp)
    target_link_libraries(${test_name} PRIVATE void_vault_core)
    add_test(NAME ${test_name} COMMAND ${test_name})
    set_tests_properties(${test_name} PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
endforeach()

# End-to-end: the real application executed as separate processes.
add_test(
    NAME app_e2e_test
    COMMAND ${CMAKE_COMMAND}
        -DAPP=$<TARGET_FILE:void_vault>
        -DWORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/e2e_data
        -P ${CMAKE_CURRENT_SOURCE_DIR}/app_e2e_test.cmake
)