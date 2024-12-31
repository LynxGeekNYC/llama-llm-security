#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <filesystem>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

// g++ -std=c++17 -o log_analyzer log_analyzer.cpp -lcurl -lstdc++fs

// Function to read file content
std::string read_log_file(const std::string& filepath) {
    std::ifstream file(filepath);
    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Function to send logs to LLaMA API
std::string send_to_llama_api(const std::string& log_data, const std::string& api_url, const std::string& api_key) {
    CURL* curl;
    CURLcode res;
    std::string response_data;
    
    // Initialize CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    
    if (curl) {
        // Set API endpoint and headers
        curl_easy_setopt(curl, CURLOPT_URL, api_url.c_str());
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, ("Authorization: Bearer " + api_key).c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        // Prepare JSON payload
        nlohmann::json json_data = {
            {"prompt", "Please analyze the following logs for cybersecurity threats. Highlight any suspicious activity or anomalies: " + log_data},
            {"max_tokens", 1000}
        };
        
        // Convert JSON data to string
        std::string json_string = json_data.dump();
        
        // Set the POST data
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_string.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, json_string.size());

        // Write the response
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](void* ptr, size_t size, size_t nmemb, std::string* data) -> size_t {
            size_t total_size = size * nmemb;
            data->append((char*)ptr, total_size);
            return total_size;
        });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
        
        // Perform the request
        res = curl_easy_perform(curl);
        
        if (res != CURLE_OK) {
            std::cerr << "CURL request failed: " << curl_easy_strerror(res) << std::endl;
        }
        
        // Clean up
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
    
    curl_global_cleanup();
    return response_data;
}

// Function to analyze logs from a directory
void analyze_logs_from_directory(const std::string& logs_dir, const std::string& api_url, const std::string& api_key) {
    // Iterate over all log files in the directory
    for (const auto& entry : std::filesystem::directory_iterator(logs_dir)) {
        if (entry.is_regular_file()) {
            std::string filepath = entry.path().string();
            std::string log_data = read_log_file(filepath);
            
            // Send the logs to LLaMA API
            std::string api_response = send_to_llama_api(log_data, api_url, api_key);
            
            // Parse and display the response
            try {
                auto json_response = nlohmann::json::parse(api_response);
                std::cout << "Analysis for file: " << filepath << "\n";
                std::cout << "Response: " << json_response.dump(4) << "\n";
            } catch (const nlohmann::json::parse_error& e) {
                std::cerr << "Error parsing API response: " << e.what() << "\n";
            }
        }
    }
}

int main() {
    // Set up directories and API configuration
    std::string logs_dir = "/var/log";  // Path to log directory
    std::string api_url = "https://api.llama.com/v1/analysis";  // URL for LLaMA API
    std::string api_key = "YOUR_API_KEY";  // Replace with your actual LLaMA API key
    
    // Analyze logs in the specified directory
    analyze_logs_from_directory(logs_dir, api_url, api_key);
    
    return 0;
}
