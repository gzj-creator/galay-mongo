function(add_mongo_benchmark target_name source_file)
    add_executable(${target_name} ${source_file})
    target_link_libraries(${target_name} PRIVATE ${PROJECT_NAME})
    target_include_directories(${target_name} PRIVATE ${CMAKE_SOURCE_DIR})
    galay_mongo_apply_cxx(${target_name})
endfunction()

add_mongo_benchmark(b1_ping b1_ping.cc)
add_mongo_benchmark(b2_ping b2_ping.cc)
