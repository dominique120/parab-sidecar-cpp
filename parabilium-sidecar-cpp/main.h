#pragma once
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <array>

#include <aws/core/Aws.h>
#include <aws/lambda-runtime/runtime.h>

#include <nlohmann/json.hpp>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <opencv2/core/core.hpp>

// Library to include for
// drawing shapes
#include <opencv2/highgui/highgui.hpp>
#include <opencv2/imgproc.hpp>

using namespace cv;
using namespace aws::lambda_runtime;
using namespace nlohmann;

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";