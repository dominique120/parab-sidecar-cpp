#ifndef CREATE_CARD_H
#define CREATE_CARD_H
#include <iostream>
#include <string>
#include <string_view>
#include <array>
#include <thread>
#include <future>
#include <random>

#include <aws/lambda-runtime/runtime.h>

#include <nlohmann/json.hpp>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>

// Library to include for
// drawing shapes
#include <opencv2/core/core.hpp>
#include <opencv2/highgui/highgui.hpp>
#include <opencv2/imgproc.hpp>

using namespace cv;
using namespace aws::lambda_runtime;
using namespace nlohmann;

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

std::random_device dev;
std::mt19937 rng(dev());
std::uniform_int_distribution<std::mt19937::result_type> dist(0, 9); // distribution in range [1, 6]

#endif
