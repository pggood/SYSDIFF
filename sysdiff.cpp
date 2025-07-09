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

// Structure to hold registry key/value information
struct RegistryEntry {
    std::wstring value_name;
    DWORD type;
    std::vector<BYTE> data;
};

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
            out << "REG|" << std::string(key.begin(), key.end()) << "|"
                << entry.type << "|"
                << std::string(entry.data.begin(), entry.data.end()) << "\n";  // simplistic
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
                // Simplified parser — ideally base64 or hex encode REG data
                // Not production safe as-is
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
        std::cerr << "INF generation not implemented (yet)\n";
        return 1;
    }
    else {
        std::cerr << "Unknown mode: " << mode << "\n";
        return 1;
    }

    return 0;
}
