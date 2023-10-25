/**
 * @file src/confighttp.cpp
 * @brief todo
 *
 * @todo Authentication, better handling of routes common to nvhttp, cleanup
 */

#define BOOST_BIND_GLOBAL_PLACEHOLDERS

#include "process.h"

#include <filesystem>
#include <set>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <boost/algorithm/string.hpp>

#include <boost/asio/ssl/context.hpp>

#include <boost/filesystem.hpp>

#include <Simple-Web-Server/crypto.hpp>
#include <Simple-Web-Server/server_https.hpp>
#include <boost/asio/ssl/context_base.hpp>

#include "config.h"
#include "confighttp.h"
#include "crypto.h"
#include "httpcommon.h"
#include "main.h"
#include "network.h"
#include "nvhttp.h"
#include "platform/common.h"
#include "rtsp.h"
#include "utility.h"
#include "uuid.h"
#include "version.h"

#include "src/shaga/shaga_payload_builder.h"
#include "src/shaga/store_encrypted.h"
#include <src/json.hpp>

using namespace std::literals;

namespace confighttp {
  namespace fs = std::filesystem;
  namespace pt = boost::property_tree;

  using https_server_t = SimpleWeb::Server<SimpleWeb::HTTPS>;

  using args_t = SimpleWeb::CaseInsensitiveMultimap;
  using resp_https_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTPS>::Response>;
  using req_https_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTPS>::Request>;

  enum class op_e {
    ADD,
    REMOVE
  };

  void
  print_req(const req_https_t &request) {
    BOOST_LOG(debug) << "METHOD :: "sv << request->method;
    BOOST_LOG(debug) << "DESTINATION :: "sv << request->path;

    for (auto &[name, val] : request->header) {
      BOOST_LOG(debug) << name << " -- " << (name == "Authorization" ? "CREDENTIALS REDACTED" : val);
    }

    BOOST_LOG(debug) << " [--] "sv;

    for (auto &[name, val] : request->parse_query_string()) {
      BOOST_LOG(debug) << name << " -- " << val;
    }

    BOOST_LOG(debug) << " [--] "sv;
  }

  void
  send_unauthorized(resp_https_t response, req_https_t request) {
    auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
    BOOST_LOG(info) << "Web UI: ["sv << address << "] -- not authorized"sv;
    const SimpleWeb::CaseInsensitiveMultimap headers {
      { "WWW-Authenticate", R"(Basic realm="Sunshine Gamestream Host", charset="UTF-8")" }
    };
    response->write(SimpleWeb::StatusCode::client_error_unauthorized, headers);
  }

  void
  send_redirect(resp_https_t response, req_https_t request, const char *path) {
    auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
    BOOST_LOG(info) << "Web UI: ["sv << address << "] -- not authorized"sv;
    const SimpleWeb::CaseInsensitiveMultimap headers {
      { "Location", path }
    };
    response->write(SimpleWeb::StatusCode::redirection_temporary_redirect, headers);
  }

  bool
  authenticate(resp_https_t response, req_https_t request) {
    auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
    auto ip_type = net::from_address(address);

    if (ip_type > http::origin_web_ui_allowed) {
      BOOST_LOG(info) << "Web UI: ["sv << address << "] -- denied"sv;
      response->write(SimpleWeb::StatusCode::client_error_forbidden);
      return false;
    }

    // If credentials are shown, redirect the user to a /welcome page
    if (config::sunshine.username.empty()) {
      send_redirect(response, request, "/welcome");
      return false;
    }

    auto fg = util::fail_guard([&]() {
      send_unauthorized(response, request);
    });

    auto auth = request->header.find("authorization");
    if (auth == request->header.end()) {
      return false;
    }

    auto &rawAuth = auth->second;
    auto authData = SimpleWeb::Crypto::Base64::decode(rawAuth.substr("Basic "sv.length()));

    int index = authData.find(':');
    if (index >= authData.size() - 1) {
      return false;
    }

    auto username = authData.substr(0, index);
    auto password = authData.substr(index + 1);
    auto hash = util::hex(crypto::hash(password + config::sunshine.salt)).to_string();

    if (!boost::iequals(username, config::sunshine.username) || hash != config::sunshine.password) {
      return false;
    }

    fg.disable();
    return true;
  }

  void
  not_found(resp_https_t response, req_https_t request) {
    pt::ptree tree;
    tree.put("root.<xmlattr>.status_code", 404);

    std::ostringstream data;

    pt::write_xml(data, tree);
    response->write(data.str());

    *response << "HTTP/1.1 404 NOT FOUND\r\n"
              << data.str();
  }

  // todo - combine these functions into a single function that accepts the page, i.e "index", "pin", "apps"
  void
  getIndexPage(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string header = read_file(WEB_DIR "header.html");
    std::string content = read_file(WEB_DIR "index.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(header + content, headers);
  }

  void
  getPinPage(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string header = read_file(WEB_DIR "header.html");
    std::string content = read_file(WEB_DIR "pin.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(header + content, headers);
  }

  void
  getAppsPage(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string header = read_file(WEB_DIR "header.html");
    std::string content = read_file(WEB_DIR "apps.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    headers.emplace("Access-Control-Allow-Origin", "https://images.igdb.com/");
    response->write(header + content, headers);
  }

  void
  getClientsPage(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string header = read_file(WEB_DIR "header.html");
    std::string content = read_file(WEB_DIR "clients.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(header + content, headers);
  }

  void
  getConfigPage(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string header = read_file(WEB_DIR "header.html");
    std::string content = read_file(WEB_DIR "config.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(header + content, headers);
  }

  void
  getPasswordPage(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string header = read_file(WEB_DIR "header.html");
    std::string content = read_file(WEB_DIR "password.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(header + content, headers);
  }

  void
  getWelcomePage(resp_https_t response, req_https_t request) {
    print_req(request);
    if (!config::sunshine.username.empty()) {
      send_redirect(response, request, "/");
      return;
    }
    std::string header = read_file(WEB_DIR "header-no-nav.html");
    std::string content = read_file(WEB_DIR "welcome.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(header + content, headers);
  }

  void
  getTroubleshootingPage(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string header = read_file(WEB_DIR "header.html");
    std::string content = read_file(WEB_DIR "troubleshooting.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(header + content, headers);
  }

  void
  getFaviconImage(resp_https_t response, req_https_t request) {
    // todo - combine function with getSunshineLogoImage and possibly getNodeModules
    // todo - use mime_types map
    print_req(request);

    std::ifstream in(WEB_DIR "images/sunshine.ico", std::ios::binary);
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "image/x-icon");
    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
  }

  void
  getSunshineLogoImage(resp_https_t response, req_https_t request) {
    // todo - combine function with getFaviconImage and possibly getNodeModules
    // todo - use mime_types map
    print_req(request);

    std::ifstream in(WEB_DIR "images/logo-sunshine-45.png", std::ios::binary);
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "image/png");
    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
  }

  void
  getShagaLogoImage(resp_https_t response, req_https_t request) {
    // todo - combine function with getFaviconImage and possibly getNodeModules
    // todo - use mime_types map
    print_req(request);

    std::ifstream in(WEB_DIR "images/SHAGA-REAL-LOGO.png", std::ios::binary);
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "image/png");
    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
  }

  bool
  isChildPath(fs::path const &base, fs::path const &query) {
    auto relPath = fs::relative(base, query);
    return *(relPath.begin()) != fs::path("..");
  }

  void
  getNodeModules(resp_https_t response, req_https_t request) {
    print_req(request);
    fs::path webDirPath(WEB_DIR);
    fs::path nodeModulesPath(webDirPath / "node_modules");

    // .relative_path is needed to shed any leading slash that might exist in the request path
    auto filePath = fs::weakly_canonical(webDirPath / fs::path(request->path).relative_path());

    // Don't do anything if file does not exist or is outside the node_modules directory
    if (!isChildPath(filePath, nodeModulesPath)) {
      BOOST_LOG(warning) << "Someone requested a path " << filePath << " that is outside the node_modules folder";
      response->write(SimpleWeb::StatusCode::client_error_bad_request, "Bad Request");
    }
    else if (!fs::exists(filePath)) {
      response->write(SimpleWeb::StatusCode::client_error_not_found);
    }
    else {
      auto relPath = fs::relative(filePath, webDirPath);
      // get the mime type from the file extension mime_types map
      // remove the leading period from the extension
      auto mimeType = mime_types.find(relPath.extension().string().substr(1));
      // check if the extension is in the map at the x position
      if (mimeType != mime_types.end()) {
        // if it is, set the content type to the mime type
        SimpleWeb::CaseInsensitiveMultimap headers;
        headers.emplace("Content-Type", mimeType->second);
        std::ifstream in(filePath.string(), std::ios::binary);
        response->write(SimpleWeb::StatusCode::success_ok, in, headers);
      }
      // do not return any file if the type is not in the map
    }
  }

  //Shaga
  void getJavaScriptLibs(resp_https_t response, req_https_t request) {
    print_req(request);
    fs::path webDirPath(WEB_DIR);
    fs::path libsPath(webDirPath / "libs");

    // .relative_path is needed to shed any leading slash that might exist in the request path
    auto filePath = fs::weakly_canonical(webDirPath / fs::path(request->path).relative_path());

    // Don't do anything if file does not exist or is outside the libs directory
    if (!isChildPath(filePath, libsPath)) {
      BOOST_LOG(warning) << "Someone requested a path " << filePath << " that is outside the libs folder";
      response->write(SimpleWeb::StatusCode::client_error_bad_request, "Bad Request");
      return;
    }

    if (!fs::exists(filePath)) {
      response->write(SimpleWeb::StatusCode::client_error_not_found);
      return;
    }

    auto relPath = fs::relative(filePath, webDirPath);
    auto mimeType = mime_types.find(relPath.extension().string().substr(1));

    if (mimeType != mime_types.end()) {
      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Content-Type", mimeType->second);
      std::ifstream in(filePath.string(), std::ios::binary);
      response->write(SimpleWeb::StatusCode::success_ok, in, headers);
    }
  }

  //Shaga

  void
  getApps(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string content = read_file(config::stream.file_apps.c_str());
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "application/json");
    response->write(content, headers);
  }

  void
  getLogs(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string content = read_file(config::sunshine.log_file.c_str());
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/plain");
    response->write(SimpleWeb::StatusCode::success_ok, content, headers);
  }

  void
  saveApp(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    pt::ptree inputTree, fileTree;

    BOOST_LOG(info) << config::stream.file_apps;
    try {
      // TODO: Input Validation
      pt::read_json(ss, inputTree);
      pt::read_json(config::stream.file_apps, fileTree);

      if (inputTree.get_child("prep-cmd").empty()) {
        inputTree.erase("prep-cmd");
      }

      if (inputTree.get_child("detached").empty()) {
        inputTree.erase("detached");
      }

      auto &apps_node = fileTree.get_child("apps"s);
      int index = inputTree.get<int>("index");

      inputTree.erase("index");

      if (index == -1) {
        apps_node.push_back(std::make_pair("", inputTree));
      }
      else {
        // Unfortunately Boost PT does not allow to directly edit the array, copy should do the trick
        pt::ptree newApps;
        int i = 0;
        for (const auto &kv : apps_node) {
          if (i == index) {
            newApps.push_back(std::make_pair("", inputTree));
          }
          else {
            newApps.push_back(std::make_pair("", kv.second));
          }
          i++;
        }
        fileTree.erase("apps");
        fileTree.push_back(std::make_pair("apps", newApps));
      }
      pt::write_json(config::stream.file_apps, fileTree);
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "SaveApp: "sv << e.what();

      outputTree.put("status", "false");
      outputTree.put("error", "Invalid Input JSON");
      return;
    }

    outputTree.put("status", "true");
    proc::refresh(config::stream.file_apps);
  }

  void
  deleteApp(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      response->write(data.str());
    });
    pt::ptree fileTree;
    try {
      pt::read_json(config::stream.file_apps, fileTree);
      auto &apps_node = fileTree.get_child("apps"s);
      int index = stoi(request->path_match[1]);

      if (index < 0) {
        outputTree.put("status", "false");
        outputTree.put("error", "Invalid Index");
        return;
      }
      else {
        // Unfortunately Boost PT does not allow to directly edit the array, copy should do the trick
        pt::ptree newApps;
        int i = 0;
        for (const auto &kv : apps_node) {
          if (i++ != index) {
            newApps.push_back(std::make_pair("", kv.second));
          }
        }
        fileTree.erase("apps");
        fileTree.push_back(std::make_pair("apps", newApps));
      }
      pt::write_json(config::stream.file_apps, fileTree);
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "DeleteApp: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", "Invalid File JSON");
      return;
    }

    outputTree.put("status", "true");
    proc::refresh(config::stream.file_apps);
  }

  void
  uploadCover(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    std::stringstream ss;
    std::stringstream configStream;
    ss << request->content.rdbuf();
    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      SimpleWeb::StatusCode code = SimpleWeb::StatusCode::success_ok;
      if (outputTree.get_child_optional("error").has_value()) {
        code = SimpleWeb::StatusCode::client_error_bad_request;
      }

      pt::write_json(data, outputTree);
      response->write(code, data.str());
    });
    pt::ptree inputTree;
    try {
      pt::read_json(ss, inputTree);
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "UploadCover: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", e.what());
      return;
    }

    auto key = inputTree.get("key", "");
    if (key.empty()) {
      outputTree.put("error", "Cover key is required");
      return;
    }
    auto url = inputTree.get("url", "");

    const std::string coverdir = platf::appdata().string() + "/covers/";
    if (!boost::filesystem::exists(coverdir)) {
      boost::filesystem::create_directories(coverdir);
    }

    std::basic_string path = coverdir + http::url_escape(key) + ".png";
    if (!url.empty()) {
      if (http::url_get_host(url) != "images.igdb.com") {
        outputTree.put("error", "Only images.igdb.com is allowed");
        return;
      }
      if (!http::download_file(url, path)) {
        outputTree.put("error", "Failed to download cover");
        return;
      }
    }
    else {
      auto data = SimpleWeb::Crypto::Base64::decode(inputTree.get<std::string>("data"));

      std::ofstream imgfile(path);
      imgfile.write(data.data(), (int) data.size());
    }
    outputTree.put("path", path);
  }

  void
  getConfig(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    outputTree.put("status", "true");
    outputTree.put("platform", SUNSHINE_PLATFORM);
    outputTree.put("version", PROJECT_VER);

    auto vars = config::parse_config(read_file(config::sunshine.config_file.c_str()));

    for (auto &[name, value] : vars) {
      outputTree.put(std::move(name), std::move(value));
    }
  }

  void
  saveConfig(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    std::stringstream configStream;
    ss << request->content.rdbuf();
    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      response->write(data.str());
    });
    pt::ptree inputTree;
    try {
      // TODO: Input Validation
      pt::read_json(ss, inputTree);
      for (const auto &kv : inputTree) {
        std::string value = inputTree.get<std::string>(kv.first);
        if (value.length() == 0 || value.compare("null") == 0) continue;

        configStream << kv.first << " = " << value << std::endl;
      }
      write_file(config::sunshine.config_file.c_str(), configStream.str());
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "SaveConfig: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", e.what());
      return;
    }
  }

  void
  restart(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    // We may not return from this call
    platf::restart();
  }

  void
  savePassword(resp_https_t response, req_https_t request) {
    if (!config::sunshine.username.empty() && !authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    std::stringstream configStream;
    ss << request->content.rdbuf();

    pt::ptree inputTree, outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    try {
      // TODO: Input Validation
      pt::read_json(ss, inputTree);
      auto username = inputTree.count("currentUsername") > 0 ? inputTree.get<std::string>("currentUsername") : "";
      auto newUsername = inputTree.get<std::string>("newUsername");
      auto password = inputTree.count("currentPassword") > 0 ? inputTree.get<std::string>("currentPassword") : "";
      auto newPassword = inputTree.count("newPassword") > 0 ? inputTree.get<std::string>("newPassword") : "";
      auto confirmPassword = inputTree.count("confirmNewPassword") > 0 ? inputTree.get<std::string>("confirmNewPassword") : "";
      if (newUsername.length() == 0) newUsername = username;
      if (newUsername.length() == 0) {
        outputTree.put("status", false);
        outputTree.put("error", "Invalid Username");
      }
      else {
        auto hash = util::hex(crypto::hash(password + config::sunshine.salt)).to_string();
        if (config::sunshine.username.empty() || (boost::iequals(username, config::sunshine.username) && hash == config::sunshine.password)) {
          if (newPassword.empty() || newPassword != confirmPassword) {
            outputTree.put("status", false);
            outputTree.put("error", "Password Mismatch");
          }
          else {
            http::save_user_creds(config::sunshine.credentials_file, newUsername, newPassword);
            http::reload_user_creds(config::sunshine.credentials_file);
            outputTree.put("status", true);
          }
        }
        else {
          outputTree.put("status", false);
          outputTree.put("error", "Invalid Current Credentials");
        }
      }
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "SavePassword: "sv << e.what();
      outputTree.put("status", false);
      outputTree.put("error", e.what());
      return;
    }
  }

  void
  savePin(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();

    pt::ptree inputTree, outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    try {
      // TODO: Input Validation
      pt::read_json(ss, inputTree);
      std::string pin = inputTree.get<std::string>("pin");
      outputTree.put("status", nvhttp::pin(pin));
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "SavePin: "sv << e.what();
      outputTree.put("status", false);
      outputTree.put("error", e.what());
      return;
    }
  }

  void
  unpairAll(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    pt::ptree outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });
    nvhttp::erase_all_clients();
    outputTree.put("status", true);
  }

  void
  closeApp(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    pt::ptree outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    proc::proc.terminate();
    outputTree.put("status", true);
  }

  void
  getShagaPage(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return; // Assuming you want authentication, remove if unnecessary

    print_req(request); // Debugging - to print request info

    std::string header = read_file(WEB_DIR "header.html");
    std::string content = read_file(WEB_DIR "shaga.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(header + content, headers);
  }

  void verifyPassword(resp_https_t response, req_https_t request) {
    try {
      // Reading incoming JSON data
      std::stringstream ss;
      ss << request->content.rdbuf();
      pt::ptree inputTree;
      pt::read_json(ss, inputTree);

      // Getting incoming password from request JSON
      auto incomingPassword = inputTree.get<std::string>("password");

      // Hashing incoming password with the salt read from config::sunshine.salt
      auto hashedIncomingPassword = util::hex(crypto::hash(incomingPassword + config::sunshine.salt)).to_string();

      // Comparing hashed password with stored password
      if (hashedIncomingPassword == config::sunshine.password) {
        response->write(SimpleWeb::StatusCode::success_ok, "Password verified.");
      } else {
        response->write(SimpleWeb::StatusCode::client_error_unauthorized, "Invalid password.");
      }
    }
    catch(const std::exception& e) {
      response->write(SimpleWeb::StatusCode::client_error_bad_request, e.what());
    }
  }


  void storeMnemonic(resp_https_t response, req_https_t request) {
    try {
      std::string mnemonic = request->content.string();
      shaga::store_encrypted_mnemonic(mnemonic);
      response->write(SimpleWeb::StatusCode::success_ok, "Stored successfully.");
    }
    catch(const std::exception& e) {
      response->write(SimpleWeb::StatusCode::client_error_bad_request, e.what());
    }
  }

  void storeKeypair(resp_https_t response, req_https_t request) {
    try {
      // Parse the incoming request to JSON
      nlohmann::json json_request = nlohmann::json::parse(request->content.string());

      // Extract the three separate fields
      std::string encrypted = json_request["encrypted"];
      std::string nonce = json_request["nonce"];
      std::string salt = json_request["salt"];

      if (encrypted.empty() || nonce.empty() || salt.empty()) {
        response->write(SimpleWeb::StatusCode::client_error_bad_request, "Missing or null fields");
        return;
      }
      shaga::store_encrypted_keypair(encrypted, nonce, salt);

      response->write(SimpleWeb::StatusCode::success_ok, "Keypair stored successfully.");
    }
    catch (const std::exception& e) {
      response->write(SimpleWeb::StatusCode::client_error_bad_request, e.what());
    }
  }


  void fetchMnemonic(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) {
      response->write(SimpleWeb::StatusCode::client_error_unauthorized, "Unauthorized");
      return;
    }

    std::ifstream file("secure_mnemonic_storage.txt");
    std::string encrypted_mnemonic;

    if (file.is_open()) {
      std::getline(file, encrypted_mnemonic);
      file.close();
      response->write(SimpleWeb::StatusCode::success_ok, encrypted_mnemonic);
    } else {
      response->write(SimpleWeb::StatusCode::client_error_bad_request, "Failed to open the file.");
    }
  }

  void fetchKeypair(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) {
      response->write(SimpleWeb::StatusCode::client_error_unauthorized, "Unauthorized");
      return;
    }

    std::ifstream file("secure_ed25519_storage.txt");
    std::string line;

    if (file.is_open()) {
      std::getline(file, line);
      file.close();
      nlohmann::json json_data = nlohmann::json::parse(line);  // Parse the line into a JSON object
      response->write(SimpleWeb::StatusCode::success_ok, json_data.dump());  // Send the JSON string
    } else {
      response->write(SimpleWeb::StatusCode::client_error_bad_request, "Failed to open the keypair storage file.");
    }
  }


  void getSystemInfo(resp_https_t response, req_https_t request) {
    try {
      // Build the payload using your existing buildPayload() function
      SystemInfoPayload payload = buildPayload();

      // Create a property tree object
      pt::ptree pt;

      // Populate the property tree with payload
      pt.put("coordinates", payload.coordinates);
      pt.put("ipAddress", payload.ipAddress);
      pt.put("cpuName", payload.cpuName);
      pt.put("gpuName", payload.gpuName);
      pt.put("totalRamMB", payload.totalRamMB);
      // TODO: more info can be added

      // Serialize the property tree to a JSON string
      std::ostringstream buf;
      pt::write_json(buf, pt);

      // Respond with the JSON payload
      response->write(SimpleWeb::StatusCode::success_ok, buf.str());
    }
    catch (const std::exception &e) {
      // Handle exceptions and respond with an error
      response->write(SimpleWeb::StatusCode::client_error_bad_request, e.what());
    }
  }

  void getSalt(resp_https_t response, req_https_t request) {
    try {
      // Reading salt from config::sunshine.salt
      auto salt = config::sunshine.salt;

      // Respond with the salt
      response->write(SimpleWeb::StatusCode::success_ok, salt);
    }
    catch(const std::exception& e) {
      response->write(SimpleWeb::StatusCode::client_error_bad_request, e.what());
    }
  }

  // Shaga
  void saveShagaConfig(std::shared_ptr<typename SimpleWeb::Server<SimpleWeb::HTTPS>::Response> response, std::shared_ptr<typename SimpleWeb::Server<SimpleWeb::HTTPS>::Request> request) {
    try {
      auto content = request->content.string();
      std::ofstream configFile("path/to/shagaConfig.txt");
      if (configFile.is_open()) {
        configFile << content;
        configFile.close();
      } else {
        throw std::ios_base::failure("Couldn't open config file");
      }
      response->write(SimpleWeb::StatusCode::success_ok, "Config saved successfully");
    }
    catch (const std::exception &e) {
      response->write(SimpleWeb::StatusCode::client_error_bad_request, "Failed to save config: " + std::string(e.what()));
    }
  }

  void fetchShagaConfig(std::shared_ptr<typename SimpleWeb::Server<SimpleWeb::HTTPS>::Response> response, std::shared_ptr<typename SimpleWeb::Server<SimpleWeb::HTTPS>::Request> request) {
    try {
      std::ifstream configFile("path/to/shagaConfig.txt");
      if (configFile.is_open()) {
        std::string content((std::istreambuf_iterator<char>(configFile)), std::istreambuf_iterator<char>());
        configFile.close();
        response->write(SimpleWeb::StatusCode::success_ok, content);
      } else {
        throw std::ios_base::failure("Couldn't open config file");
      }
    }
    catch (const std::exception &e) {
      response->write(SimpleWeb::StatusCode::client_error_bad_request, "Failed to fetch config: " + std::string(e.what()));
    }
  }

  void storeWalletStatus(resp_https_t response, req_https_t request) {
    try {
      std::string walletStatus = request->content.string(); // Assuming 'true' or 'false' as content
      std::ofstream file("wallet_status.txt", std::ios::out); // Use std::ios::out to create the file if it doesn't exist

      if (file.is_open()) {
        file << walletStatus;
        file.close();
        response->write(SimpleWeb::StatusCode::success_ok, "Wallet status stored successfully.");
      } else {
        throw std::ios_base::failure("Failed to open or create the wallet_status.txt file.");
      }
    }
    catch(const std::exception& e) {
      response->write(SimpleWeb::StatusCode::client_error_bad_request, e.what());
    }
  }

  void fetchWalletStatus(resp_https_t response, req_https_t request) {
    try {
      if (!std::filesystem::exists("wallet_status.txt")) {
        std::ofstream createFile("wallet_status.txt", std::ios::out); // Create the file if it doesn't exist
        createFile << "false"; // Initialize with a default value
        createFile.close();
      }

      std::ifstream file("wallet_status.txt");
      std::string walletStatus;

      if (file.is_open()) {
        std::getline(file, walletStatus);
        file.close();
        response->write(SimpleWeb::StatusCode::success_ok, walletStatus);
      } else {
        throw std::ios_base::failure("Failed to open the wallet_status.txt file.");
      }
    }
    catch(const std::exception& e) {
      response->write(SimpleWeb::StatusCode::client_error_bad_request, e.what());
    }
  }

  // Global variables here
  std::mutex decryptedPin_mutex;
  std::condition_variable decryptedPin_cv;
  SharedState pairingPayload;

  void SharedState::setEncryptedPinAndKeys(const std::string& pin, const std::string& edKey, const std::string& xKey) {
    std::unique_lock<std::mutex> lock(state_mutex);
    encryptedPinShared = pin;
    EdPublicKeyShared = edKey;
    XPublicKeyShared = xKey;
  }

  std::tuple<std::string, std::string, std::string> SharedState::getEncryptedPinAndKeys() {
    std::unique_lock<std::mutex> lock(state_mutex);
    return {encryptedPinShared, EdPublicKeyShared, XPublicKeyShared};
  }

  void SharedState::setReceivedDecryptedPin(const std::string& pin) {
    std::unique_lock<std::mutex> lock(state_mutex);
    received_decryptedPin = pin;
  }

  std::string SharedState::getReceivedDecryptedPin() {
    std::unique_lock<std::mutex> lock(state_mutex);
    return received_decryptedPin;
  }

  std::string postDataToFrontend(const std::string& encryptedPin, const std::string& edPublicKey, const std::string& xPublicKey) {
    try {
      pairingPayload.setEncryptedPinAndKeys(encryptedPin, edPublicKey, xPublicKey);

      std::string receivedDecryptedPin;

      {
        std::unique_lock<std::mutex> lock(decryptedPin_mutex);  // Begin lock scope
        if(decryptedPin_cv.wait_for(lock, std::chrono::seconds(15)) == std::cv_status::timeout) {
          throw std::runtime_error("Timed out waiting for decryptedPin");
        }
        // Fetch and clear the decrypted PIN within the lock scope to avoid race conditions.
        receivedDecryptedPin = pairingPayload.getReceivedDecryptedPin();
        pairingPayload.setReceivedDecryptedPin("");  // Clear the decrypted PIN from the global state
      }  // End lock scope

      return receivedDecryptedPin;
    }
    catch (const std::runtime_error& e) {
      std::cerr << "Runtime Error: " << e.what() << std::endl;
      return "Runtime Error";
    }
    catch (const std::exception& e) {
      std::cerr << "General Exception in postDataToFrontend: " << e.what() << std::endl;
      return "";
    }
    catch (...) {
      std::cerr << "Unknown Exception in postDataToFrontend" << std::endl;
      return "";
    }
  }

  void shagaPIN_endpoint(resp_https_t response, req_https_t request) {
    try {
      // Parse the incoming request to JSON
      nlohmann::json json_request = nlohmann::json::parse(request->content.string());

      // Check if decryptedPin is present in JSON body
      if (json_request.find("decryptedPin") == json_request.end() || json_request["decryptedPin"].get<std::string>().empty()) {
        response->write(SimpleWeb::StatusCode::client_error_bad_request, "Missing or empty decryptedPin parameter");
        return;
      }

      // Get the decryptedPin value from JSON body
      std::string decryptedPin = json_request["decryptedPin"].get<std::string>();
      pairingPayload.setReceivedDecryptedPin(decryptedPin);

      std::unique_lock<std::mutex> lock(decryptedPin_mutex);
      decryptedPin_cv.notify_one();

      // Send a response to indicate success
      response->write(SimpleWeb::StatusCode::success_ok, "Received decryptedPin successfully");
    }
    catch (const std::exception& e) {
      std::cerr << "shagaPIN_endpoint Error: " << e.what() << std::endl;
      response->write(SimpleWeb::StatusCode::client_error_bad_request, "An error occurred");
    }
  }



  void checkForPair_endpoint(resp_https_t response, req_https_t request) {
    if (pairingPayload.isNull()) {
      pairingPayload.initialize();
    }
    // Fetch all three variables: encryptedPin, EdPublicKey, and XPublicKey
    auto [encryptedPin, EdPublicKey, XPublicKey] = pairingPayload.getEncryptedPinAndKeys();
    // Check if all variables are non-empty
    if(!encryptedPin.empty() && !EdPublicKey.empty() && !XPublicKey.empty()) {
      // Prepare the response JSON including both Ed and X public keys
      std::string responseData = R"({ "encryptedPin": ")" + encryptedPin
                                 + R"(", "EdPublicKey": ")" + EdPublicKey
                                 + R"(", "XPublicKey": ")" + XPublicKey + R"(" })";
      // Clear the variables
      pairingPayload.setEncryptedPinAndKeys("", "", "");
      // Write the response
      response->write(SimpleWeb::StatusCode::success_ok, responseData);
    } else {
      // In case any of the variables are empty, indicate that pairing hasn't been achieved yet
      response->write(SimpleWeb::StatusCode::success_ok, R"({ "status": "Not yet" })");
    }
  }


  void backupSharedStateToBackend_endpoint(resp_https_t response, req_https_t request) {
    try {
      std::string sharedState = request->content.string();
      std::ofstream file("sharedState.txt", std::ios::out);

      if (file.is_open()) {
        file << sharedState;
        file.close();
        response->write(SimpleWeb::StatusCode::success_ok, "Shared state stored successfully.");
      } else {
        throw std::ios_base::failure("Failed to open or create the sharedState.txt file.");
      }
    }
    catch(const std::exception& e) {
      response->write(SimpleWeb::StatusCode::client_error_bad_request, e.what());
    }
  }


  void loadSharedStateFromBackend_endpoint(resp_https_t response, req_https_t request) {
    try {
      if (!std::filesystem::exists("sharedState.txt")) {
        std::ofstream createFile("sharedState.txt", std::ios::out);
        createFile << "{}"; // Initialize with an empty JSON object
        createFile.close();
      }

      std::ifstream file("sharedState.txt");
      std::string sharedState;

      if (file.is_open()) {
        std::getline(file, sharedState);
        file.close();
        response->write(SimpleWeb::StatusCode::success_ok, sharedState);
      } else {
        throw std::ios_base::failure("Failed to open the sharedState.txt file.");
      }
    }
    catch(const std::exception& e) {
      response->write(SimpleWeb::StatusCode::client_error_bad_request, e.what());
    }
  }



  void
  start() {
    auto shutdown_event = mail::man->event<bool>(mail::shutdown);

    auto port_https = map_port(PORT_HTTPS);
    auto address_family = net::af_from_enum_string(config::sunshine.address_family);

    https_server_t server { config::nvhttp.cert, config::nvhttp.pkey };
    server.default_resource["GET"] = not_found;
    server.resource["^/$"]["GET"] = getIndexPage;
    server.resource["^/pin$"]["GET"] = getPinPage;
    server.resource["^/apps$"]["GET"] = getAppsPage;
    server.resource["^/clients$"]["GET"] = getClientsPage;
    server.resource["^/config$"]["GET"] = getConfigPage;
    server.resource["^/password$"]["GET"] = getPasswordPage;
    server.resource["^/welcome$"]["GET"] = getWelcomePage;
    server.resource["^/troubleshooting$"]["GET"] = getTroubleshootingPage;
    server.resource["^/api/pin$"]["POST"] = savePin;
    server.resource["^/api/apps$"]["GET"] = getApps;
    server.resource["^/api/logs$"]["GET"] = getLogs;
    server.resource["^/api/apps$"]["POST"] = saveApp;
    server.resource["^/api/config$"]["GET"] = getConfig;
    server.resource["^/api/config$"]["POST"] = saveConfig;
    server.resource["^/api/restart$"]["POST"] = restart;
    server.resource["^/api/password$"]["POST"] = savePassword;
    server.resource["^/api/apps/([0-9]+)$"]["DELETE"] = deleteApp;
    server.resource["^/api/clients/unpair$"]["POST"] = unpairAll;
    server.resource["^/api/apps/close$"]["POST"] = closeApp;
    server.resource["^/api/covers/upload$"]["POST"] = uploadCover;
    server.resource["^/images/sunshine.ico$"]["GET"] = getFaviconImage;
    server.resource["^/images/logo-sunshine-45.png$"]["GET"] = getSunshineLogoImage;
    server.resource["^/node_modules\\/.+$"]["GET"] = getNodeModules;
    // Shaga
    server.resource["^/images/SHAGA-REAL-LOGO.png$"]["GET"] = getShagaLogoImage;
    server.resource["^/libs/.*$"]["GET"] = getJavaScriptLibs;
    server.resource["^/shaga$"]["GET"] = getShagaPage;
    server.resource["^/api/system_info$"]["GET"] = getSystemInfo;
    server.resource["^/api/verify_password$"]["POST"] = verifyPassword;
    server.resource["^/api/store_mnemonic$"]["POST"] = storeMnemonic;
    server.resource["^/api/fetch_mnemonic$"]["GET"] = fetchMnemonic;
    server.resource["^/api/store_keypair$"]["POST"] = storeKeypair;
    server.resource["^/api/fetch_keypair$"]["GET"] = fetchKeypair;
    server.resource["^/api/shagaConfig$"]["POST"] = saveShagaConfig;
    server.resource["^/api/shagaConfig$"]["GET"] = fetchShagaConfig;
    server.resource["^/api/get_wallet_status$"]["GET"] = fetchWalletStatus;
    server.resource["^/api/store_wallet_status$"]["POST"] = storeWalletStatus;
    server.resource["^/api/get_salt$"]["GET"] = getSalt;
    server.resource["^/api/shagaPIN$"]["POST"] = shagaPIN_endpoint; // TODO: MAKE ALL ENDPOINTS NAMING CONSISTENT
    server.resource["^/api/checkForPair"]["GET"] = checkForPair_endpoint;
    server.resource["^/api/backupSharedState$"]["POST"] = backupSharedStateToBackend_endpoint;
    server.resource["^/api/loadSharedState$"]["GET"] = loadSharedStateFromBackend_endpoint;
    // Shaga
    server.config.reuse_address = true;
    server.config.address = net::af_to_any_address_string(address_family);
    server.config.port = port_https;

    auto accept_and_run = [&](auto *server) {
      try {
        server->start([](unsigned short port) {
          BOOST_LOG(info) << "Configuration UI available at [https://localhost:"sv << port << "]";
        });
      }
      catch (boost::system::system_error &err) {
        // It's possible the exception gets thrown after calling server->stop() from a different thread
        if (shutdown_event->peek()) {
          return;
        }

        BOOST_LOG(fatal) << "Couldn't start Configuration HTTPS server on port ["sv << port_https << "]: "sv << err.what();
        shutdown_event->raise(true);
        return;
      }
    };
    std::thread tcp { accept_and_run, &server };

    // Wait for any event
    shutdown_event->view();

    server.stop();

    tcp.join();
  }
}  // namespace confighttp
