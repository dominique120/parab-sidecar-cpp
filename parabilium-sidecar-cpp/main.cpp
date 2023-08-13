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

std::string base64_encode(unsigned char const* buf, unsigned int bufLen) {
	std::string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];

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

std::string get_image() {
	httplib::Client imgCli("http://dv-image-test.s3.us-east-2.amazonaws.com"); // host, port
	auto img = imgCli.Get("/card.png");

	if (img->status != 200) {
		return "";
	} else {
		return img->body;
	}
}

std::pair<std::string, std::string> get_pan_and_exp() {
	httplib::Client cli("http://dv-image-test.s3.us-east-2.amazonaws.com"); // host, port

	auto cardDetails = cli.Get("/cards.json"); // TODO set payload and req params
	json card;
	std::cout << "parsing data pan" << std::endl;
	if (cardDetails->status != 200) {
		return std::make_pair<std::string, std::string>("error", "parabilium failed");
	} else {
		try {
			card = json::parse(cardDetails->body);
			return std::make_pair<std::string, std::string>(card[dist(rng)].at("pan").get<std::string>(), card[dist(rng)].at("exp").get<std::string>());
		} catch (json::exception& e) {
			return std::make_pair<std::string, std::string>("error", "could not parse /get/card");
		}
	}
}

std::string get_cvv() {
	httplib::Client cli("http://dv-image-test.s3.us-east-2.amazonaws.com"); // host, port

	auto cardDetails = cli.Get("/cards.json"); // TODO set payload and req params
	json cvvData;
	std::cout << "parsing data cvv" << std::endl;
	if (cardDetails->status != 200) {
		return  "";
	} else {
		try {
			cvvData = json::parse(cardDetails->body);
			return std::to_string(cvvData[dist(rng)].at("cvv").get<int>());
		} catch (json::exception& e) {
			return "";
		}
	}
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
	response["isBase64Encoded"] = true;
	response["headers"]["Content-Type"] = "image/png";
	//response["headers"]["Access-Control-Allow-Origin"] = "todo";
	response["headers"]["Access-Control-Allow-Credentials"] = "true";
	response["headers"]["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
	response["headers"]["Access-Control-Max-Age"] = 8600;
	response["headers"]["Access-Control-Allow-Headers"] = "x-hmac-key";


	// verify that hmac key was supplied
	std::string_view hmac_key;
	try {
		//hmac_key = payload.at("headers").at("x-hmac-key").get<std::string_view>();
	} catch (json::exception& ex) {
		response["statusCode"] = 403;
		response["message"] = "hmac - key header not found.Must supply \"x-hmac-key\" header with key.";
		response["error"] = ex.what();
		return invocation_response::failure(response.dump(), "application/json");
	}

	std::string_view msg = "msg";
	// verify that hmac is ok:
	std::string hmac_sha256 = CalcHmacSHA256(hmac_key, msg);

	if (hmac_sha256 == "wherever this key comes from ") { //invert this condition
		response["statusCode"] = 403;
		response["message"] = "hmac decryption failed";
		return invocation_response::failure(response.dump(), "application/json");
	}

	// validations done, now exec parallel tasks

	// run tasks
	std::future<std::string> image_future = std::async(std::launch::async, get_image);
	std::future<std::pair<std::string, std::string>> pan_future = std::async(std::launch::async, get_pan_and_exp);
	std::future<std::string> cvv_future = std::async(std::launch::async, get_cvv);


	auto pan_exp = pan_future.get();
	if (pan_exp.first == "error") {
		return invocation_response::failure("could not get pan", "could not get pan");
	}

	auto cvv = cvv_future.get();
	if (cvv.empty()) {
		return invocation_response::failure("could not get cvv", "could not get cvv");
	}

	std::cout << "setting up image" << std::endl;

	auto imgResponse = image_future.get();
	if (imgResponse.empty()) {
		return invocation_response::failure("image not found", "could not get image");
	}
	std::vector<uchar> imgArr(imgResponse.begin(), imgResponse.end());
	Mat image = imdecode(imgArr, -1);

	std::cout << "write to image" << std::endl;

	// write on image
	Point pan_point(120, 270);
	putText(image, pan_exp.first, pan_point, FONT_HERSHEY_SIMPLEX, 1.3, Scalar(240, 240, 240), 2, LINE_AA);

	Point exp_point(440, 330);
	putText(image, pan_exp.second, exp_point, FONT_HERSHEY_SIMPLEX, 1.1, Scalar(240, 240, 240), 2, LINE_AA);

	Point cvv_point(250, 330);
	putText(image, cvv, cvv_point, FONT_HERSHEY_SIMPLEX, 1.1, Scalar(240, 240, 240), 2, LINE_AA);

	std::cout << "encode image" << std::endl;
	std::vector<uchar> buf;

	std::vector<int> compression_params;
	compression_params.push_back(IMWRITE_PNG_COMPRESSION);
	compression_params.push_back(9);

	cv::imencode(".png", image, buf, compression_params);

	auto* enc_msg = reinterpret_cast<unsigned char*>(buf.data());

	std::cout << "base64 to image" << std::endl;

	std::string encoded_image = base64_encode(enc_msg, buf.size());

	response["body"] = encoded_image;
	response["statusCode"] = 200;
	response["message"] = "ok";

	return invocation_response::success(response.dump(), "image/png");
}

int main() {
	run_handler(my_handler);
	/*
	auto req = invocation_request();
	req.payload = "";
	my_handler(req);
	*/
	return 0;
}