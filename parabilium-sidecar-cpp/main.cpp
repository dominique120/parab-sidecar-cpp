#include "main.h"

std::string CalcHmacSHA256(std::string_view decodedKey, std::string_view msg) {
	std::array<unsigned char, EVP_MAX_MD_SIZE> hash;
	unsigned int hashLen;

	HMAC(
		EVP_sha256(),
		decodedKey.data(),
		static_cast<int>(decodedKey.size()),
		reinterpret_cast<unsigned char const*>(msg.data()),
		static_cast<int>(msg.size()),
		hash.data(),
		&hashLen
	);

	return std::string{ reinterpret_cast<char const*>(hash.data()), hashLen };
}

std::string base64_encode(BYTE const* buf, unsigned int bufLen) {
	std::string ret;
	int i = 0;
	int j = 0;
	BYTE char_array_3[3];
	BYTE char_array_4[4];

	while (bufLen--) {
		char_array_3[i++] = *(buf++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; (i < 4); i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 3; j++)
			char_array_3[j] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];

		while ((i++ < 3))
			ret += '=';
	}

	return ret;
}

static invocation_response my_handler(invocation_request const& req) {


	// test to see if the payload the function got is a well formatted json
	json payload;
	try {
		payload = json::parse(req.payload);
	} catch (json::exception& e) {
		return invocation_response::failure(e.what(), "Payload parsing failed");
	}

	//set up initial rsponse params
	json response;
	response["isBase64Encoded"] = false;
	response["headers"]["Content-Type"] = "application/json";
	//response["headers"]["Access-Control-Allow-Origin"] = "todo";
	response["headers"]["Access-Control-Allow-Credentials"] = "true";
	response["headers"]["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
	response["headers"]["Access-Control-Max-Age"] = 8600;
	response["headers"]["Access-Control-Allow-Headers"] = "x-hmac-key";


	// verify that hmac key was supplied
	std::string_view hmac_key;
	try {
		hmac_key = payload.at("headers").at("x-hmac-key").get<std::string_view>();
	} catch (json::exception& ex) {
		response["statusCode"] = 403;
		response["message"] = "hmac - key header not found.Must supply \"x-hmac-key\" header with key.";
		response["error"] = ex.what();
		return invocation_response::failure(response.dump(), "application/json");
	}

	std::string_view msg = payload.at("body").get<std::string_view>();
	// verify that hmac is ok:
	std::string hmac_sha256 = CalcHmacSHA256(hmac_key, msg);

	if (hmac_sha256 != "wherever this key comes from ") {
		response["statusCode"] = 403;
		response["message"] = "hmac decryption failed";
		return invocation_response::failure(response.dump(), "application/json");
	}


	// setup https client to contact parabilium
	httplib::SSLClient cli("https://path/to/parabilium", 80); // host, port
	// set cert bundle
	cli.set_ca_cert_path("./ca-bundle.crt");
	// Disable cert verification
	cli.enable_server_certificate_verification(false);

	// fetch card details from parabilium
	auto cardDetails = cli.Get("/fetch/details"); // TODO set payload and req params
	json card;
	if (cardDetails->status != 200) {
		return invocation_response::failure("parabilium failed", "could not parse data from request to /fetch/card/details");
	} else {
		try {
			card = json::parse(cardDetails->body);
		} catch (json::exception& e) {
			return invocation_response::failure(e.what(), "could not parse data from request to /fetch/card/details");
		}
	}

	// fetch cvv
	auto cvvDetails = cli.Get("/fetch/details/cvv"); // TODO set payload and req params
	json cvv;
	if (cvvDetails->status != 200) {
		return invocation_response::failure("parabilium failed", "could not parse data from request to /fetch/card/details/cvv");
	} else {
		try {
			cvv = json::parse(cvvDetails->body);
		} catch (json::exception& e) {
			return invocation_response::failure(e.what(), "could not parse data from request to /fetch/card/details/cvv");
		}
	}

	//store it locally with the cert bundle 
	Mat image = imread("/path/to/image.png",
		IMREAD_COLOR);

	//check if image is present
	if (!image.data) {
		return invocation_response::failure("image not found", "could not get image");
	}

	// write on image
	Point pan_point(1, 30);
	putText(image, card.at("pan").get<std::string>(), pan_point,
		FONT_HERSHEY_SIMPLEX, 1.0,
		Scalar(0, 255, 0), 2, LINE_AA);

	Point exp_point(31, 60);
	putText(image, card.at("exp").get<std::string>(), exp_point,
		FONT_HERSHEY_SIMPLEX, 1.0,
		Scalar(0, 255, 0), 2, LINE_AA);

	Point cvv_point(61, 90);
	putText(image, cvv.at("cvv").get<std::string>(), cvv_point,
		FONT_HERSHEY_SIMPLEX, 1.0,
		Scalar(0, 255, 0), 2, LINE_AA);

	std::vector<uchar> buf;
	cv::imencode(".jpg", image, buf);
	auto* enc_msg = reinterpret_cast<unsigned char*>(buf.data());
	std::string encoded_image = base64_encode(enc_msg, buf.size());

	response["image"] = encoded_image;
	response["statusCode"] = 200;
	response["message"] = "ok";

	return invocation_response::success(response.dump(), "application/json");
}

int main() {
	run_handler(my_handler);
	return 0;
}