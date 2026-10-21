#include <filesystem>
#include <string>

#include "storage.hpp"
#include "test_util.hpp"

using tu::check;

int main()
{
    std::cout << "=== Storage Tests ===\n";
    tu::TempDir dir("storage");
    const std::string test_file = dir.file("storage_test_data.dat");
    Storage storage(test_file);

    const std::string expected = "Void Vault storage test";
    std::string loaded = "sentinel";

    check(!storage.exists(), "File absent initially");
    check(!storage.load(loaded), "Loading a missing file fails");
    check(loaded == "sentinel", "Failed load leaves output untouched");

    check(storage.save(expected), "Save data");
    check(storage.exists(), "File exists after save");
    check(storage.load(loaded) && loaded == expected, "Load returns saved content");

    check(storage.save("second version"), "Overwrite save succeeds");
    check(storage.load(loaded) && loaded == "second version", "Atomic overwrite replaced content");
    check(!std::filesystem::exists(test_file + ".tmp"), "No temp file left behind");

    const std::string binary("a\0b\0c", 5);
    check(storage.save(binary) && storage.load(loaded) && loaded == binary, "Binary data with NULs round-trips");

    check(storage.save("") && storage.load(loaded) && loaded.empty(), "Empty data round-trips");

    const std::string bad_path = dir.file("missing_dir/sub/file.dat");
    Storage bad(bad_path);
    check(!bad.save("x"), "Save into nonexistent directory fails");
    check(!std::filesystem::exists(bad_path) && !std::filesystem::exists(bad_path + ".tmp"),
          "Failed save creates no files");

    const std::string no_replace = dir.file("noreplace.dat");
    check(Storage::atomicWrite(no_replace, "original", false), "allow_replace=false creates new file");
    check(!Storage::atomicWrite(no_replace, "attacker", false), "allow_replace=false refuses to overwrite");
    check(tu::readAll(no_replace) == "original", "Existing file preserved");
    check(!std::filesystem::exists(no_replace + ".tmp"), "No temp file after refused write");

    // --- FileLock concurrency & contention tests ---
    {
        const std::string lock_target = dir.file("lock_target.dat");
        FileLock lock1(lock_target);
        check(lock1.isLocked(), "First FileLock acquires exclusive lock");
        {
            FileLock lock2(lock_target);
            check(!lock2.isLocked(), "Second FileLock on same target fails immediately");
            Storage locked_storage(lock_target);
            check(!locked_storage.save("blocked"), "Storage::save fails while external FileLock is held");
        }
        lock1.unlock();
        check(!lock1.isLocked(), "FileLock::unlock releases lock");
        FileLock lock3(lock_target);
        check(lock3.isLocked(), "Subsequent FileLock succeeds after unlock");
    }

    // --- Owner-only permissions test ---
    check(Storage::restrictPermissions(test_file), "restrictPermissions succeeds on existing regular file");

    // --- Directory read rejection ---
    {
        std::string dir_out = "unchanged";
        check(!Storage::readFile(dir.path().string(), dir_out) && dir_out == "unchanged",
              "readFile rejects directory paths");
    }

    // --- MAX_FILE_SIZE enforcement ---
    {
        const std::string oversized_path = dir.file("oversized.dat");
        std::string huge(Storage::MAX_FILE_SIZE + 1, 'X');
        check(!Storage::atomicWrite(oversized_path, huge, true),
              "atomicWrite rejects payload exceeding MAX_FILE_SIZE");
    }

    return tu::finish("storage");
}
