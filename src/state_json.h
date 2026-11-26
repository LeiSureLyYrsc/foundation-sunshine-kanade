#pragma once

#include <chrono>
#include <exception>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>

#include <nlohmann/json.hpp>

#include "src/logging.h"
#include "src/utility.h"
#include "src/uuid.h"

#ifdef _WIN32
  #include <windows.h>
  #include <aclapi.h>
#else
  #include <cerrno>
  #include <fcntl.h>
  #include <sys/file.h>
  #include <sys/stat.h>
  #include <unistd.h>
#endif

namespace state_json {
  namespace fs = std::filesystem;
  using nlohmann::json;
  inline std::mutex writer_mutex;

  // Program writers (including --creds) serialize on the resolved parent and
  // filename, not on an inode that is replaced on every commit. Never remove
  // the lock file during normal operation. No lock data is stored in it.
  template<class Update>
  bool transact(const fs::path &path, Update update) {
    std::lock_guard writer { writer_mutex };
    const auto report = [](const char *stage, unsigned long code = 0) {
      BOOST_LOG(error) << "Could not update Sunshine state: stage=" << stage << " error=" << code;
      return false;
    };
    try {
      if (path.empty() || !path.has_filename()) return report("path");
#ifdef _WIN32
      const auto leaf = path.filename().native();
      if (leaf.find(L':') != std::wstring::npos || leaf.back() == L'.' || leaf.back() == L' ') return report("path");
#endif
      const auto parent = fs::canonical(path.has_parent_path() ? path.parent_path() : fs::current_path());
      const auto target = parent / path.filename();
      auto lock_path = target;
      lock_path += ".lock";
#ifdef _WIN32
      const auto lock = CreateFileW(lock_path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
      if (lock == INVALID_HANDLE_VALUE) return report("open_lock", GetLastError());
      const auto close_lock = util::fail_guard([&] { CloseHandle(lock); });
      BY_HANDLE_FILE_INFORMATION lock_info {};
      if (!GetFileInformationByHandle(lock, &lock_info)) return report("lock_info", GetLastError());
      if (lock_info.nNumberOfLinks != 1 || (lock_info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) return report("lock_type");
      OVERLAPPED range {};
      const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
      while (!LockFileEx(lock, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &range)) {
        const auto code = GetLastError();
        if (code != ERROR_LOCK_VIOLATION || std::chrono::steady_clock::now() >= deadline) return report("lock_busy_or_denied", code);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
#else
      const int lock = ::open(lock_path.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
      if (lock < 0) return report("open_lock", errno);
      const auto close_lock = util::fail_guard([&] { ::close(lock); });
      struct stat lock_info {};
      if (::fstat(lock, &lock_info) != 0) return report("lock_info", errno);
      if (!S_ISREG(lock_info.st_mode) || lock_info.st_nlink != 1) return report("lock_type");
      const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
      while (::flock(lock, LOCK_EX | LOCK_NB) != 0) {
        const auto code = errno;
        if ((code != EWOULDBLOCK && code != EINTR) || std::chrono::steady_clock::now() >= deadline) return report("lock_busy_or_denied", code);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
#endif
      json document = json::object();
      const auto status = fs::symlink_status(target);
      const bool exists = fs::exists(status);
      if (exists) {
        if (!fs::is_regular_file(status) || fs::hard_link_count(target) != 1) return report("target_type");
#ifdef _WIN32
        const auto attributes = GetFileAttributesW(target.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) return report("target_attributes", GetLastError());
        if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) return report("target_type");
#endif
        std::ifstream input { target, std::ios::binary };
        if (!input) return report("read");
        document = json::parse(input, nullptr, false);
        if (!document.is_object() || input.bad()) return report("parse");
      }
      if (!update(document)) return report("merge");
      const auto contents = document.dump(2) + '\n';
      auto temporary = target;
      temporary += ".tmp-" + uuid_util::uuid_t::generate().string();
#ifdef _WIN32
      if (contents.size() > MAXDWORD) return report("write_size");
      // Keep an existing file's explicit DACL on its new sibling before writing
      // any bytes. A newly created state uses the configured directory's ACL.
      PSECURITY_DESCRIPTOR descriptor = nullptr;
      const auto free_descriptor = util::fail_guard([&] { if (descriptor) LocalFree(descriptor); });
      if (exists) {
        PACL dacl = nullptr;
        auto filename = target.native();
        const auto access = GetNamedSecurityInfoW(filename.data(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
          nullptr, nullptr, &dacl, nullptr, &descriptor);
        if (access != ERROR_SUCCESS) return report("read_target_dacl", access);
      }
      SECURITY_ATTRIBUTES security { sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE };
      auto file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, descriptor ? &security : nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (file == INVALID_HANDLE_VALUE) return report("create_temp", GetLastError());
      auto cleanup = util::fail_guard([&] {
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
        if (!DeleteFileW(temporary.c_str())) {
          const auto code = GetLastError();
          if (code != ERROR_FILE_NOT_FOUND) report("delete_temp", code);
        }
      });
      DWORD written = 0;
      if (!WriteFile(file, contents.data(), static_cast<DWORD>(contents.size()), &written, nullptr)) return report("write_temp", GetLastError());
      if (written != contents.size()) return report("short_write");
      if (!FlushFileBuffers(file)) return report("flush_temp", GetLastError());
      if (!CloseHandle(file)) return report("close_temp", GetLastError());
      file = INVALID_HANDLE_VALUE;
      const DWORD flags = MOVEFILE_WRITE_THROUGH | (exists ? MOVEFILE_REPLACE_EXISTING : 0);
      if (!MoveFileExW(temporary.c_str(), target.c_str(), flags)) return report("publish", GetLastError());
#else
      const int file = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
      if (file < 0) return report("create_temp", errno);
      const auto close_file = util::fail_guard([&] { ::close(file); });
      auto cleanup = util::fail_guard([&] {
        if (::unlink(temporary.c_str()) != 0 && errno != ENOENT) report("delete_temp", errno);
      });
      for (std::size_t offset = 0; offset < contents.size();) {
        const auto written = ::write(file, contents.data() + offset, contents.size() - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return report("write_temp", written < 0 ? errno : 0);
        offset += static_cast<std::size_t>(written);
      }
      if (::fsync(file) != 0) return report("flush_temp", errno);
      if (::rename(temporary.c_str(), target.c_str()) != 0) return report("replace", errno);
#endif
      cleanup.disable();
      return true;
    } catch (const std::exception &) {
      // Parser exceptions may contain credentials or certificate bytes.
      return report("path_or_json");
    }
  }
}  // namespace state_json
