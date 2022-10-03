# cnetlib-licensing-auth
A software licensing client and authority built using cnetlib

## Example

A Windows client requesting license validation from a Google Cloud Platform Linux VM running the authority
![Auth](https://raw.githubusercontent.com/gmbows/cnetlib-licensing-auth/main/validauth.png)

## Usage

To request validation for a license in default file `./auth/license`:
```cpp
CN::AuthClient client = CN::AuthClient(); //Default port 5555
this->client.add_typespec_handler((CN::DataType)LicenseValid,[&](CN::UserMessage *msg) {
  gcutils::print("CLIENT License validated: ",msg->str());
});

this->client.add_typespec_handler((CN::DataType)LicenseInvalid,[&](CN::UserMessage *msg) {
  gcutils::print("CLIENT License NOT validated: ",msg->str());
});
  
std::string validation_authority;
std::cin >> validation_authority;
client.validate(validation_authority);
```

To create a validation authority on port 5555 (default):
```cpp
CN::AuthServer serv = CN::AuthServer(5555);
serv.start_listener();

std::string _wait;
std::cin >> _wait;
```
