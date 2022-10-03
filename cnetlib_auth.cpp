#include "cnetlib_auth.h"

#include <fstream>

namespace CN {

AuthServer::AuthServer(short port) {

	srand(time(NULL));


	this->init_license_generator();
	//Generate test license
	if(this->validate_license(this->generate_license()) == false) {
		gcutils::print("Error in license generation");
	} else {
		gcutils::print("License generation valid");
	}

	this->import_licences();

	this->server.add_typespec_handler((CN::DataType)KeyQuery,[this](CN::UserMessage *msg) {
		std::string query = msg->str();
		if(this->has_key(query)) {
			gcutils::print("key \"",query,"\" is present");
			msg->connection->package_and_send((CN::DataType)KeyQueryResponse,"true");
		} else {
			gcutils::print("key \"",query,"\" is NOT present");
			msg->connection->package_and_send((CN::DataType)KeyQueryResponse,"false");
		}
	});
	this->server.add_typespec_handler((CN::DataType)RequestNewLicense,[this](CN::UserMessage *msg) {
		std::string key = msg->str();
		std::string license = gcutils::random_hex_string(64);
		this->add_license(key,license);
		gcutils::print("Got request for new license for key ",key);
		msg->connection->package_and_send((CN::DataType)CreatedLicense,gcutils::simple_encrypt(license));
	});

	this->server.add_typespec_handler(CN::DataType::ARRAY,[this](CN::UserMessage *msg) {
		std::vector<std::string> keypair = msg->try_get_array();
		std::string key = keypair[0];
		std::string license = keypair[1];
		std::vector<std::string> used = this->m_licences["used"];

		if(gcutils::contains(used,license)) {
			if(this->has_key(key) == false or this->get_license(key) != license) {
				msg->connection->package_and_send((CN::DataType)LicenseInvalid,"License is registered to different user");
				return;
			}
		}

		if(this->validate_license(license) == false) {
			msg->connection->package_and_send((CN::DataType)LicenseInvalid,"Invalid license");
			return;
		}

		if(this->has_key(key) == false) {
			this->add_license(key,license);
		}

		msg->connection->package_and_send((CN::DataType)LicenseValid,"Success");
	});
}

void AuthServer::init_license_generator() {
	unsigned seq_len = CONFIG_LICENSE_LEN/4;
	int target_divisor = CONFIG_LICENSE_DIVISOR;
	unsigned max_multiple = (seq_len*9)/target_divisor;

	std::string license = gcutils::random_hex_string(CONFIG_LICENSE_LEN);
	for(int i=0;i<=max_multiple;i++) {
		int sum = i*target_divisor;
		if(sum >= CONFIG_LICENSE_LEN/4*3 and sum <= (CONFIG_LICENSE_LEN/4*9)-(CONFIG_LICENSE_LEN/4*3)) this->m_opt_sums.push_back(i*target_divisor);
	}

	if(this->m_opt_sums.size() == 0) {
		gcutils::print("WARNING Fatal error in license generation");
	}
}

void AuthServer::import_licences() {
	std::ifstream in(LICENSE_FILE);
	json licences;
	try {
		this->m_licences = json::parse(in);
	} catch(const std::exception &e) {
		this->m_licences = json::parse(R"({"used":[]})");
		gcutils::create_file(LICENSE_FILE);
		this->export_licenses();
	}
	in.close();
}

void AuthServer::export_licenses() {
	std::ofstream out(LICENSE_FILE);
	out << this->m_licences;
	out.close();
}

void AuthServer::add_license(std::string key, std::string value) {
	this->m_licences[key] = value;
	this->m_licences["used"].push_back(value);
	this->export_licenses();
}

std::string AuthServer::get_license(std::string key) {
	return this->m_licences[key];
}

bool AuthServer::has_key(std::string key) {
	this->import_licences();
	try {
		std::string license = this->m_licences[key];
		return true;
	} catch(const std::exception &e) {
		return false;
	}
}

int sum_vec(std::vector<int> v) {
	int sum = 0;
	for(auto i : v) sum += i;
	return sum;
}

std::string AuthServer::generate_license() {
	unsigned seq_len = CONFIG_LICENSE_LEN/4;
	int target_divisor = CONFIG_LICENSE_DIVISOR;
	unsigned max_multiple = (seq_len*9)/target_divisor;

	std::vector<int> opt_sums;
	std::string license = gcutils::random_hex_string(CONFIG_LICENSE_LEN);
	for(int i=0;i<=max_multiple;i++) {
		int sum = i*target_divisor;
		if(sum >= CONFIG_LICENSE_LEN/4*3 and sum <= (CONFIG_LICENSE_LEN/4*9)-(CONFIG_LICENSE_LEN/4*3)) opt_sums.push_back(i*target_divisor);
	}

	if(opt_sums.empty()) {
		//Throw some kind of error...
	}

	int target_sum = opt_sums[rand()%opt_sums.size()];

	std::vector<int> values = {};
	for(int i=0;i<seq_len;i++) {
		values.push_back(0);
	}

	while(sum_vec(values) != target_sum) {
		values[rand()%values.size()] = rand()%10;
	}

	for(int i=0;i<CONFIG_LICENSE_LEN;i+=4) {
		char c = std::to_string(values[i/4])[0];
		license[i] = c;
	}


	return license;
}

bool AuthServer::validate_license(std::string license) {
	bool valid = true;
	int sum = 0;
	for(int i=0;i<CONFIG_LICENSE_LEN;i+=4) {
		if(!isdigit(license[i])) {
			valid = false;
			break;
		} else {
			std::string s;
			s += license[i];
			sum += std::stoi(s);
		}
	}
	if(valid == false) return false;
	if(sum%CONFIG_LICENSE_DIVISOR != 0) return false;
	return true;
}

void AuthClient::fetch_credentials() {
	CNetLib::make_directory("auth");
	std::string license_file = "auth/license";

	if(!gcutils::file_exists(license_file)) gcutils::create_file(license_file);

	std::vector<char> license_data = gcutils::import_file(license_file);

	if(license_data.empty()) gcutils::print("License empty");

	this->m_key = this->get_device_fingerprint();
	std::string s_license(license_data.data());
	this->m_license = s_license;
}

#if defined(_WIN32) || defined(WIN32)
#include <windows.h>
#define PLATFORM "Windows"
#define _IS_WIN 1
#elif defined(_UNIX)
#define PLATFORM "Linux"
#define _IS_WIN 0
#endif

//TODO: Unix fingerprinting
std::string AuthClient::get_device_fingerprint() {
	std::string fingerprint;
	if(_IS_WIN) {
		system("wmic csproduct get name, identifyingnumber, uuid > auth/info");
		std::vector<char> machine_info = gcutils::import_file("auth/info");
		std::string machine_string;
		for(auto c : machine_info) machine_string+=c;
		std::vector<std::string> machine_string_info = gcutils::split(machine_string,' ');
		fingerprint += machine_string_info[49];
		system("wmic baseboard get product,version,serialnumber > auth/info");
		std::vector<char> mobo_info = gcutils::import_file("auth/info");
		std::string mobo_string;
		for(auto c : mobo_info) mobo_string+=c;
		std::vector<std::string> mobo_string_info = gcutils::split(mobo_string,' ');
		fingerprint += mobo_string_info[33];
		const char* empty = {""};
		gcutils::export_file("auth/info",(unsigned char*)empty,0);
		return fingerprint;
	}
	return "Info undefined";
}

void AuthClient::validate(std::string authority) {
	CN::Connection *cn = this->client.connect(authority);

	cn->send_array({m_key,m_license});
}

AuthClient::AuthClient() {
	this->fetch_credentials();
	this->client.add_typespec_handler((CN::DataType)KeyQueryResponse,[&](CN::UserMessage *msg) {
		std::string response = msg->str();
		gcutils::print("Got key query response: \"",response,"\"");
		if(response == "false") {
			//Request creation of new license for our key
			msg->connection->send_array({m_key,m_license}); //Implicit key validation
		}
	});

	this->client.add_typespec_handler((CN::DataType)LicenseValid,[&](CN::UserMessage *msg) {
		gcutils::print("CLIENT License validated: ",msg->str());
	});

	this->client.add_typespec_handler((CN::DataType)LicenseInvalid,[&](CN::UserMessage *msg) {
		gcutils::print("CLIENT License NOT validated: ",msg->str());
	});
}

}
