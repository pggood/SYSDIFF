// sysdiff.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <map>
#include <vector>
#include <windows.h>
#include <winreg.h>
#include <wincrypt.h>
#include <ctime>
#include <array>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;

// Base64 encoding/decoding functions
static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

// Structure to hold registry key/value information
struct RegistryEntry {
    std::wstring value_name;
    DWORD type;
    std::vector<BYTE> data;
};



static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(const std::vector<BYTE>& bytes_to_encode) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    int in_len = bytes_to_encode.size();
    const unsigned char* bytes = bytes_to_encode.data();

    while (in_len--) {
        char_array_3[i++] = *(bytes++);
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

std::vector<BYTE> base64_decode(const std::string& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::vector<BYTE> ret;

    while (in_len-- && (encoded_string[in] != '=') && is_base64(encoded_string[in])) {
        char_array_4[i++] = encoded_string[in]; in++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
    }

    return ret;
}

// Function to compute MD5 checksum of a file
std::string computeMD5(const std::string& filePath) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return "";
    }
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    const size_t bufferSize = 4096;
    std::vector<BYTE> buffer(bufferSize);
    while (file.read(reinterpret_cast<char*>(buffer.data()), bufferSize)) {
        if (!CryptHashData(hHash, buffer.data(), static_cast<DWORD>(bufferSize), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
    }
    size_t bytesRead = file.gcount();
    if (bytesRead > 0) {
        if (!CryptHashData(hHash, buffer.data(), static_cast<DWORD>(bytesRead), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
    }

    DWORD hashSize = 0;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, nullptr, &hashSize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    std::vector<BYTE> hash(hashSize);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashSize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    // Convert to hex string
    std::stringstream ss;
    for (BYTE b : hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}

// Function to capture file system snapshot (path to MD5 checksum)
std::map<std::string, std::string> captureFileSnapshot(const std::string& directory) {
    std::map<std::string, std::string> snapshot;
    try {
        for (const auto& entry : fs::recursive_directory_iterator(directory, fs::directory_options::skip_permission_denied)) {
            if (entry.is_regular_file()) {
                std::string path = entry.path().string();
                std::string checksum = computeMD5(path);
                if (!checksum.empty()) {
                    snapshot[path] = checksum;
                }
            }
        }
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << "\n";
    }
    return snapshot;
}

// Function to capture registry snapshot recursively
void captureRegistrySnapshot(HKEY rootHive, const std::wstring& subKey, std::map<std::wstring, RegistryEntry>& snapshot, const std::wstring& rootPath) {
    std::wstring currentPath = rootPath + (subKey.empty() ? L"" : L"\\" + subKey);
    HKEY hOpenedKey;
    if (RegOpenKeyExW(rootHive, subKey.c_str(), 0, KEY_READ, &hOpenedKey) != ERROR_SUCCESS) {
        std::cerr << "Failed to open registry key: " << std::string(currentPath.begin(), currentPath.end()) << "\n";
        return;
    }

    // Capture values under this key
    DWORD valueCount, maxValueNameLen, maxValueDataLen;
    if (RegQueryInfoKeyW(hOpenedKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &valueCount, &maxValueNameLen, &maxValueDataLen, nullptr, nullptr) == ERROR_SUCCESS) {
        std::vector<wchar_t> valueName(maxValueNameLen + 1);
        std::vector<BYTE> valueData(maxValueDataLen);
        for (DWORD i = 0; i < valueCount; ++i) {
            DWORD valueNameLen = maxValueNameLen + 1;
            DWORD valueDataLen = maxValueDataLen;
            DWORD type;
            if (RegEnumValueW(hOpenedKey, i, valueName.data(), &valueNameLen, nullptr, &type, valueData.data(), &valueDataLen) == ERROR_SUCCESS) {
                RegistryEntry entry;
                entry.value_name = std::wstring(valueName.data(), valueNameLen);
                entry.type = type;
                entry.data = std::vector<BYTE>(valueData.begin(), valueData.begin() + valueDataLen);
                std::wstring keyPath = currentPath + L"\\" + entry.value_name;
                snapshot[keyPath] = entry;
            }
        }
    }

    // Enumerate subkeys and recurse
    DWORD subKeyCount, maxSubKeyLen;
    if (RegQueryInfoKeyW(hOpenedKey, nullptr, nullptr, nullptr, &subKeyCount, &maxSubKeyLen, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        std::vector<wchar_t> subKeyName(maxSubKeyLen + 1);
        for (DWORD i = 0; i < subKeyCount; ++i) {
            DWORD subKeyLen = maxSubKeyLen + 1;
            if (RegEnumKeyExW(hOpenedKey, i, subKeyName.data(), &subKeyLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                std::wstring nextSubKey = subKey.empty() ? std::wstring(subKeyName.data(), subKeyLen) : subKey + L"\\" + std::wstring(subKeyName.data(), subKeyLen);
                std::wstring nextPath = currentPath + L"\\" + std::wstring(subKeyName.data(), subKeyLen);
                captureRegistrySnapshot(rootHive, nextSubKey, snapshot, nextPath);
            }
        }
    }

    RegCloseKey(hOpenedKey);
}
// INF file generation structures and functions
struct INFGenerator {
    std::ofstream inf_file;
    std::string inf_filename;
    std::string output_dir;

    INFGenerator(const std::string& diff_file, const std::string& output_directory)
        : output_dir(output_directory) {
        // Generate INF filename based on diff file name
        std::filesystem::path diff_path(diff_file);
        std::string base_name = diff_path.stem().string();
        inf_filename = output_directory + "\\" + base_name + ".inf";
    }

    bool Initialize() {
        inf_file.open(inf_filename);
        if (!inf_file.is_open()) {
            return false;
        }

        // Write INF header
        inf_file << "[Version]\n";
        inf_file << "Signature=\"$CHICAGO$\"\n";
        inf_file << "Class=System\n";
        inf_file << "ClassGUID={4D36E97D-E325-11CE-BFC1-08002BE10318}\n";
        inf_file << "Provider=SysDiff\n";
        inf_file << "DriverVer=" << GetCurrentDateString() << "\n";
        inf_file << "\n";

        inf_file << "[DefaultInstall]\n";
        inf_file << "AddReg=Registry.Add\n";
        inf_file << "DelReg=Registry.Delete\n";
        inf_file << "CopyFiles=Files.Copy\n";
        inf_file << "DelFiles=Files.Delete\n";
        inf_file << "\n";

        inf_file << "[Registry.Add]\n";
        return true;
    }

    void WriteRegistryAdd(const std::string& key, const std::string& value_name,
        DWORD type, const std::vector<BYTE>& data) {
        inf_file << "\"" << key << "\",\"" << value_name << "\",";

        // Convert registry type to INF format
        switch (type) {
        case REG_SZ:
            inf_file << "0x00000000,\"" << BytesToString(data) << "\"\n";
            break;
        case REG_DWORD:
            if (data.size() >= 4) {
                DWORD value = *reinterpret_cast<const DWORD*>(data.data());
                inf_file << "0x00010001,0x" << std::hex << value << std::dec << "\n";
            }
            break;
        case REG_BINARY:
            inf_file << "0x00000001,";
            for (size_t i = 0; i < data.size(); ++i) {
                if (i > 0) inf_file << ",";
                inf_file << "0x" << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(data[i]) << std::dec;
            }
            inf_file << "\n";
            break;
        default:
            inf_file << "0x00000000,\"" << BytesToString(data) << "\"\n";
            break;
        }
    }

    void WriteRegistryDelete(const std::string& key, const std::string& value_name) {
        inf_file << "\"" << key << "\",\"" << value_name << "\"\n";
    }

    void WriteFileAdd(const std::string& filepath) {
        std::filesystem::path path(filepath);
        std::string filename = path.filename().string();
        std::string directory = path.parent_path().string();

        inf_file << filename << ",,,0x00000000\n";
    }

    void WriteFileDelete(const std::string& filepath) {
        std::filesystem::path path(filepath);
        std::string filename = path.filename().string();
        inf_file << filename << "\n";
    }

    void StartSection(const std::string& section_name) {
        inf_file << "\n[" << section_name << "]\n";
    }

    void Close() {
        if (inf_file.is_open()) {
            inf_file.close();
        }
    }

private:
    std::string BytesToString(const std::vector<BYTE>& data) {
        return std::string(data.begin(), data.end());
    }

    std::string GetCurrentDateString() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::tm tm;
        localtime_s(&tm, &time_t);

        std::ostringstream oss;
        oss << std::put_time(&tm, "%m/%d/%Y");
        return oss.str();
    }
};

// Function to generate INF file from diff file
DWORD GenerateINFFromDiff(const std::string& diff_file, const std::string& output_dir) {
    std::ifstream in(diff_file);
    if (!in.is_open()) {
        std::cerr << "Cannot read diff file: " << diff_file << "\n";
        return ERROR_FILE_NOT_FOUND;
    }

    // Create output directory if it doesn't exist
    if (!std::filesystem::exists(output_dir)) {
        if (!std::filesystem::create_directories(output_dir)) {
            std::cerr << "Cannot create output directory: " << output_dir << "\n";
            return ERROR_PATH_NOT_FOUND;
        }
    }

    INFGenerator inf_gen(diff_file, output_dir);
    if (!inf_gen.Initialize()) {
        std::cerr << "Cannot create INF file\n";
        return ERROR_FILE_NOT_FOUND;
    }

    // Parse diff file and generate INF sections
    std::string line;
    bool in_registry_section = true;
    bool in_files_section = false;

    while (std::getline(in, line)) {
        if (line.empty()) continue;

        if (line.rfind("ADD|", 0) == 0) {
            std::string path = line.substr(4);

            if (in_files_section) {
                inf_gen.WriteFileAdd(path);
            }
        }
        else if (line.rfind("MOD|", 0) == 0) {
            std::string path = line.substr(4);

            if (in_files_section) {
                inf_gen.WriteFileAdd(path);  // Modified files treated as adds
            }
        }
        else if (line.rfind("DEL|", 0) == 0) {
            std::string path = line.substr(4);

            if (in_files_section) {
                if (!in_files_section) {
                    inf_gen.StartSection("Files.Delete");
                    in_files_section = true;
                }
                inf_gen.WriteFileDelete(path);
            }
        }
        else if (line.rfind("REG|", 0) == 0) {
            // Parse registry entry
            auto delim1 = line.find('|', 4);
            auto delim2 = line.find('|', delim1 + 1);

            if (delim1 != std::string::npos && delim2 != std::string::npos) {
                std::string key = line.substr(4, delim1 - 4);
                std::string type_str = line.substr(delim1 + 1, delim2 - delim1 - 1);
                std::string data_str = line.substr(delim2 + 1);

                DWORD type = std::stoul(type_str);
                std::vector<BYTE> data = base64_decode(data_str);

                // Extract value name from key (assuming format: HKLM\Path\ValueName)
                size_t last_backslash = key.find_last_of('\\');
                std::string reg_key = key.substr(0, last_backslash);
                std::string value_name = key.substr(last_backslash + 1);

                inf_gen.WriteRegistryAdd(reg_key, value_name, type, data);
            }
        }

        // Switch to files section when we encounter file operations
        if (line.rfind("ADD|", 0) == 0 || line.rfind("MOD|", 0) == 0 || line.rfind("DEL|", 0) == 0) {
            if (in_registry_section) {
                inf_gen.StartSection("Registry.Delete");
                inf_gen.StartSection("Files.Copy");
                in_registry_section = false;
                in_files_section = true;
            }
        }
    }

    inf_gen.Close();

    std::cout << "INF file generated: " << inf_gen.inf_filename << "\n";
    return NO_ERROR;
}
// Main function
int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage:\n"
            << "  sysdiff /snap <snapshot_file>\n"
            << "  sysdiff /diff <snapshot_file> <diff_file>\n"
            << "  sysdiff /inf <diff_file> <output_dir>\n";
        return 1;
    }

    std::string mode = argv[1];

    if (mode == "/snap") {
        std::string snapshot_file = argv[2];
        std::ofstream out(snapshot_file, std::ios::binary);
        if (!out) {
            std::cerr << "Cannot write to snapshot file\n";
            return 1;
        }

        auto fs_snap = captureFileSnapshot("C:\\");
        for (auto& [path, checksum] : fs_snap) {
            out << "FILE|" << path << "|" << checksum << "\n";
        }

        std::map<std::wstring, RegistryEntry> reg_snap;
        captureRegistrySnapshot(HKEY_LOCAL_MACHINE, L"", reg_snap, L"HKLM");
        for (auto& [key, entry] : reg_snap) {
            std::string encoded_data = base64_encode(entry.data); // Convert binary to Base64
            out << "REG|" << std::string(key.begin(), key.end()) << "|"
                << entry.type << "|"
                << encoded_data << "\n";
        }

        out.close();
        std::cout << "Snapshot saved to " << snapshot_file << "\n";
    }
    else if (mode == "/diff") {
        if (argc < 4) {
            std::cerr << "Missing parameters for /diff\n";
            return 1;
        }
        std::string snapshot_file = argv[2];
        std::string diff_file = argv[3];

        std::ifstream in(snapshot_file);
        if (!in) {
            std::cerr << "Cannot read snapshot file\n";
            return 1;
        }

        std::map<std::string, std::string> fs_snap_before;
        std::map<std::wstring, RegistryEntry> reg_snap_before;

        std::string line;
        while (std::getline(in, line)) {
            if (line.rfind("FILE|", 0) == 0) {
                auto delim1 = line.find('|', 5);
                auto delim2 = line.find('|', delim1 + 1);
                std::string path = line.substr(5, delim1 - 5);
                std::string hash = line.substr(delim1 + 1);
                fs_snap_before[path] = hash;
            }
            else if (line.rfind("REG|", 0) == 0) {
                auto delim1 = line.find('|', 4);          // After "REG|"
                auto delim2 = line.find('|', delim1 + 1); // After key
                std::string key_str = line.substr(4, delim1 - 4);
                std::wstring key(key_str.begin(), key_str.end());
                DWORD type = std::stoul(line.substr(delim1 + 1, delim2 - delim1 - 1));
                std::string encoded_data = line.substr(delim2 + 1);
                std::vector<BYTE> data = base64_decode(encoded_data); // Decode back to binary
                RegistryEntry entry;
                entry.value_name = L""; // Adjust if value_name is separate in key
                entry.type = type;
                entry.data = data;
                reg_snap_before[key] = entry;
            }
        }

        in.close();

        std::ofstream out(diff_file);
        auto fs_snap_after = captureFileSnapshot("C:\\");

        for (auto& [path, hash] : fs_snap_after) {
            if (fs_snap_before.find(path) == fs_snap_before.end()) {
                out << "ADD|" << path << "\n";
            }
            else if (fs_snap_before[path] != hash) {
                out << "MOD|" << path << "\n";
            }
        }

        for (auto& [path, hash] : fs_snap_before) {
            if (fs_snap_after.find(path) == fs_snap_after.end()) {
                out << "DEL|" << path << "\n";
            }
        }

        out.close();
        std::cout << "Diff saved to " << diff_file << "\n";
    }
    else if (mode == "/inf") {
        if (argc < 4) {
            std::cerr << "Missing parameters for /inf\n";
            return 1;
        }

        std::string diff_file = argv[2];
        std::string output_dir = argv[3];

        DWORD result = GenerateINFFromDiff(diff_file, output_dir);
        if (result != NO_ERROR) {
            std::cerr << "INF generation failed with error: " << result << "\n";
            return 1;
        }

        std::cout << "INF generation completed successfully\n";
    }
    else {
        std::cerr << "Unknown mode: " << mode << "\n";
        return 1;
    }

    return 0;
}


