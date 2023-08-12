cmake_minimum_required(VERSION 3.5)
set(CMAKE_CXX_STANDARD 17)

project(parabilium-get-card-data LANGUAGES CXX)
set(aws-lambda-runtime_DIR "/root/lambda-install/lib64/aws-lambda-runtime/cmake/")

find_package(aws-lambda-runtime REQUIRED)
#find_package(AWSSDK COMPONENTS core)
find_package(httplib CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(OpenCV REQUIRED COMPONENTS core imgproc imgcodecs)

include_directories(${OpenCV_INCLUDE_DIRS})

add_executable(${PROJECT_NAME} "main.cpp")
target_link_libraries(${PROJECT_NAME} 
	PUBLIC 
	AWS::aws-lambda-runtime 
	#${AWSSDK_LINK_LIBRARIES} 
	httplib::httplib
	nlohmann_json::nlohmann_json
	OpenSSL::SSL 
	OpenSSL::Crypto
	${OpenCV_LIBS}
	)

aws_lambda_package_target(${PROJECT_NAME} NO_LIBC)