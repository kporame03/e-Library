#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include "httplib.h"
#include "json.hpp"
#include <curl/curl.h>
#include <libpq-fe.h>

using json = nlohmann::json;
using namespace std;

// --- Helper: Get Environment Variable ---
string getEnv(const char* key) {
    const char* val = getenv(key);
    return val ? string(val) : "";
}

// --- Helper: Load File ---
string loadFile(const string& path) {
    ifstream file(path, ios::binary);
    if (!file.is_open()) return "";
    ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

// --- Helper: Write Callback for CURL ---
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// --- CURL Request Helper ---
json curlRequest(string method, string url, vector<string> headers, string body = "") {
    cout << "\n[CURL] " << method << " -> " << url << endl;
    
    CURL* curl;
    CURLcode res;
    string readBuffer;

    curl = curl_easy_init();
    if (curl) {
        struct curl_slist* chunk = NULL;
        for (const auto& h : headers) {
            chunk = curl_slist_append(chunk, h.c_str());
        }

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        if (method == "POST") {
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        }

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            cerr << "[CURL ERROR] " << curl_easy_strerror(res) << endl;
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);
    }
    
    try {
        return json::parse(readBuffer);
    } catch (...) {
        return json{{"error", "Invalid JSON"}, {"raw", readBuffer}};
    }
}

// --- DGA Logic ---
string getGdxToken() {
    cout << "\n--- STEP 1: Requesting GDX Token ---" << endl;
    string url = getEnv("DGA_AUTH_URL") + 
                 "?ConsumerSecret=" + getEnv("CONSUMER_SECRET") + 
                 "&AgentID=" + getEnv("AGENT_ID");
    vector<string> headers = { "Consumer-Key: " + getEnv("CONSUMER_KEY") };
    
    json res = curlRequest("GET", url, headers);
    
    if (res.contains("Result")) {
        string token = res["Result"].get<string>();
        cout << "✅ GDX Token Received" << endl;
        return token;
    }
    cout << "❌ Failed to get GDX Token" << endl;
    return "";
}

json verifyMToken(string accessToken, string appId, string mToken) {
    cout << "\n--- STEP 2: Verifying mToken with DGA ---" << endl;
    string url = getEnv("DGA_DEPROC_URL");
    vector<string> headers = {
        "Consumer-Key: " + getEnv("CONSUMER_KEY"),
        "Token: " + accessToken,
        "Content-Type: application/json"
    };
    json payload = { {"appId", appId}, {"mToken", mToken} };
    return curlRequest("POST", url, headers, payload.dump());
}

// --- DB Logic: Check User ---
json findUserByCitizenID(string citizenId) {
    cout << "\n--- STEP 3: Check User in Database ---" << endl;
    string connStr = "host=" + getEnv("DB_HOST") + " port=" + getEnv("DB_PORT") + 
                     " dbname=" + getEnv("DB_NAME") + " user=" + getEnv("DB_USER") + 
                     " password=" + getEnv("DB_PASS");
    
    PGconn* conn = PQconnectdb(connStr.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        cerr << "❌ DB Connection Error: " << PQerrorMessage(conn) << endl;
        PQfinish(conn);
        return nullptr;
    }

    const char* paramValues[1] = { citizenId.c_str() };
    PGresult* res = PQexecParams(conn, "SELECT * FROM users WHERE citizen_id = $1", 
                                 1, NULL, paramValues, NULL, NULL, 0);

    json userObj = nullptr;
    if (PQntuples(res) > 0) {
        cout << "✅ User Found!" << endl;
        userObj = {
            {"id", PQgetvalue(res, 0, 0)},
            {"citizen_id", PQgetvalue(res, 0, 1)},
            {"firstname", PQgetvalue(res, 0, 2)},
            {"lastname", PQgetvalue(res, 0, 3)}
        };
    } else {
        cout << "⚠️ User Not Found (New User)" << endl;
    }
    PQclear(res);
    PQfinish(conn);
    return userObj;
}

// --- DB Logic: Insert User (Register) ---
bool insertUser(string citizenId, string firstname, string lastname, string mobile) {
    cout << "\n--- STEP 4: Registering New User ---" << endl;
    string connStr = "host=" + getEnv("DB_HOST") + " port=" + getEnv("DB_PORT") + 
                     " dbname=" + getEnv("DB_NAME") + " user=" + getEnv("DB_USER") + 
                     " password=" + getEnv("DB_PASS");
    
    PGconn* conn = PQconnectdb(connStr.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        cerr << "❌ DB Connection Error: " << PQerrorMessage(conn) << endl;
        PQfinish(conn);
        return false;
    }

    const char* paramValues[4] = { citizenId.c_str(), firstname.c_str(), lastname.c_str(), mobile.c_str() };
    
    PGresult* res = PQexecParams(conn, 
        "INSERT INTO users (citizen_id, firstname, lastname, mobile) VALUES ($1, $2, $3, $4)", 
        4, NULL, paramValues, NULL, NULL, 0);

    bool success = true;
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        cerr << "❌ Insert Error: " << PQresultErrorMessage(res) << endl;
        success = false;
    }
    
    PQclear(res);
    PQfinish(conn);
    return success;
}

int main() {
    httplib::Server svr;

    // Load HTML
    auto serveIndex = [&](const httplib::Request&, httplib::Response& res) {
        string html = loadFile("/app/public/index.html");
        if(html.empty()) res.set_content("Error: index.html missing", "text/plain");
        else res.set_content(html, "text/html");
    };
    auto serveRegister = [&](const httplib::Request&, httplib::Response& res) {
        string html = loadFile("/app/public/register.html");
        if(html.empty()) res.set_content("Error: register.html missing", "text/plain");
        else res.set_content(html, "text/html");
    };

    svr.Get("/", serveIndex);
    svr.Get("/test1", serveIndex);
    svr.Get("/test1/", serveIndex);
    svr.Get("/register", serveRegister);
    svr.Get("/test1/register", serveRegister);

    // --- API: Login ---
    auto loginHandler = [&](const httplib::Request& req, httplib::Response& res) {
        cout << "\n\n📢 [API HIT] /api/auth/login" << endl;
        
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400; res.set_content("Invalid JSON", "text/plain"); return;
        }

        string appId = body.value("appId", "");
        string mToken = body.value("mToken", "");

        if (appId.empty() || mToken.empty()) {
            res.status = 400; res.set_content("Missing parameters", "text/plain"); return;
        }

        string gdxToken = getGdxToken();
        if (gdxToken.empty()) {
            res.status = 502; res.set_content("Failed to get GDX Token", "text/plain"); return;
        }

        json dgaResponse = verifyMToken(gdxToken, appId, mToken);
        cout << "🔍 DGA Response: " << dgaResponse.dump() << endl;

        // แกะ response จาก DGA (ตามโครงสร้างจริงที่เจอใน Log)
        if (!dgaResponse.contains("result")) { 
             cout << "❌ DGA Verification Failed" << endl;
             res.status = 401; res.set_content(dgaResponse.dump(), "application/json"); return;
        }

        json resultObj = dgaResponse["result"];
        string citizenId = resultObj.value("citizenId", "");
        string firstName = resultObj.value("firstName", "");
        string lastName = resultObj.value("lastName", "");

        json existingUser = findUserByCitizenID(citizenId);
        json responsePayload;
        
        if (existingUser != nullptr) {
            responsePayload = { {"status", "success"}, {"type", "LOGIN"}, {"user", existingUser} };
        } else {
            responsePayload = {
                {"status", "success"},
                {"type", "REGISTER_NEEDED"},
                {"prefill_data", {
                    {"citizen_id", citizenId},
                    {"firstname", firstName},
                    {"lastname", lastName}
                }}
            };
        }

        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(responsePayload.dump(), "application/json");
    };

    // --- API: Register ---
    auto registerHandler = [&](const httplib::Request& req, httplib::Response& res) {
        cout << "\n📢 [API HIT] /api/auth/register" << endl;
        
        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400; res.set_content("Invalid JSON", "text/plain"); return;
        }

        string citizenId = body.value("citizen_id", "");
        string firstname = body.value("firstname", "");
        string lastname = body.value("lastname", "");
        string mobile = body.value("mobile", "");

        if (citizenId.empty()) {
            res.status = 400; res.set_content("Missing citizen_id", "text/plain"); return;
        }

        if (insertUser(citizenId, firstname, lastname, mobile)) {
            cout << "✅ Registered Success: " << firstname << endl;
            json response = { {"status", "success"}, {"message", "User registered successfully"} };
            res.set_content(response.dump(), "application/json");
        } else {
            cout << "❌ Registration Failed" << endl;
            res.status = 500; 
            res.set_content("Database Insert Failed", "text/plain");
        }
    };

    // Routing
    svr.Post("/api/auth/login", loginHandler);
    svr.Post("/test1/api/auth/login", loginHandler);

    svr.Get("/index.html", serveIndex);
    svr.Get("/test1/index.html", serveIndex);

    svr.Post("/api/auth/register", registerHandler);
    svr.Post("/test1/api/auth/register", registerHandler);

    cout << "🚀 Server starting on port 8080 (Login + Register Ready)..." << endl;
    svr.listen("0.0.0.0", 8080);

    return 0;
}