#pragma once

#include "cnetlib_auth_global.h"

#include "cnetlib.h"
#include <json.hpp>
#include <gcutils.h>

#define LICENSE_FILE "licenses.json"

#define CONFIG_LICENSE_LEN 128
#define CONFIG_LICENSE_DIVISOR 23

using nlohmann::json;

enum AuthDataType : int {
	KeyQuery = 0x191,			//Checks if key is present
	KeyQueryResponse = 0x192,	//Returns whether key is present or not
	RequestNewLicense = 0x193,	//Requests creation of a new license for provided key
	CreatedLicense = 0x194,		//Server sends the created license back to the client
	ValidateLicense = 0x195,	//Requests validation for a uid/license pair
	LicenseValid = 0x196,		//Successful validation response
	LicenseInvalid = 0x197,		//Unsuccessful validation response
};

namespace CN {

struct AuthServer {
	CN::Server server = CN::Server(5555);
	json m_licences = {};
	std::vector<std::string> used_licenses;

	std::vector<int> m_opt_sums;
	void init_license_generator();

	void import_licences();
	void export_licenses();

	void add_license(std::string key,std::string value);
	std::string get_license(std::string key);

	bool has_key(std::string key);

	void update_auth_keys();

	std::string generate_license();
	bool validate_license(std::string license);

	AuthServer(short int port);
};

struct AuthClient {
	std::string m_key;
	std::string m_license;
	void fetch_credentials();
	std::string get_device_fingerprint();

	void validate(std::string);

	CN::Client client = CN::Client(5555);
	AuthClient();
};

}
