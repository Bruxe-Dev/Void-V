#include <filesystem>
#include <string>

#include "security/auth.hpp"
#include "test_util.hpp"

using tu::check;

int main()
{
    std::cout << "=== Authentication Tests ===\n";
    const std::string password = "SecurePassword123!";

    // --- In-memory authorizer (original behaviour) ---
    {
        Authorizer authorizer;
        check(authorizer.setPassword(password), "Password setup");
        check(!authorizer.setPassword("AnotherPassword123!"), "Second setup rejected");
        check(authorizer.verifyPassword(password), "Correct password accepted");
    }
    {
        Authorizer authorizer;
        check(!authorizer.setPassword("short"), "Reject short password");
        check(!authorizer.setPassword("aaaaaaaaaaaa"), "Reject single-character repeated password");
        check(!authorizer.setPassword("            "), "Reject all-whitespace password");
        check(!authorizer.setPassword(std::string("ValidPrefix1\0hidden", 19)), "Reject password with NUL/control char");
        check(!authorizer.isInitialized(), "Rejected passwords leave account uninitialized");
    }

    tu::TempDir dir("auth");
    const std::string auth_file = dir.file("auth.dat");

    // --- Persistent initialization ---
    {
        Authorizer a(auth_file);
        check(!a.hasStorageError(), "Missing file is not an error");
        check(!a.isInitialized(), "Missing file means uninitialized");
        check(!a.verifyPassword(password), "Verify before setup fails");
        check(a.setPassword(password), "Persistent setup succeeds");
    }
    const std::string record = tu::readAll(auth_file);
    check(record.find(password) == std::string::npos, "Plaintext password absent from auth file");
    check(record.rfind("VVAUTH1\n$argon2id$", 0) == 0, "Auth file uses VVAUTH1 format");
    check(!std::filesystem::exists(auth_file + ".tmp"), "No temp file after setup");

    // --- Restart: separate instance ---
    {
        Authorizer b(auth_file);
        check(b.isInitialized() && !b.hasStorageError(), "Account loads after restart");
        check(!b.setPassword("OverwritePassword123!"), "Existing account cannot be overwritten");
        check(!b.isAuthorized(), "Not authorized right after construction");
        check(b.verifyPassword(password), "Correct password accepted after restart");
        check(b.isAuthorized(), "Authorized after correct password");
    }
    check(tu::readAll(auth_file) == record || tu::readAll(auth_file).find("failed=0") != std::string::npos,
          "Counter is 0 after success");

    // --- Wrong passwords, persistent lockout ---
    {
        Authorizer c(auth_file);
        check(!c.verifyPassword("WrongPassword123!"), "Wrong password rejected");
        check(!c.isAuthorized(), "Failed attempt leaves unauthorized");
        check(c.failedAttempts() == 1, "Failed attempt counted");
    }
    {
        Authorizer d(auth_file);
        check(d.failedAttempts() == 1, "Failed counter persisted across restart");
        check(d.verifyPassword(password), "Correct password before lockout succeeds");
        check(d.failedAttempts() == 0, "Success resets counter");
    }
    {
        Authorizer e(auth_file);
        check(e.failedAttempts() == 0, "Counter reset persisted");
        for (int i = 0; i < Authorizer::MAX_FAILED_ATTEMPTS; ++i)
        {
            e.verifyPassword("WrongPassword123!");
        }
        check(e.isLockedOut(), "Locked out after 5 failures");
        check(!e.verifyPassword(password), "Correct password rejected while locked out");
    }
    {
        Authorizer f(auth_file);
        check(f.isLockedOut(), "Lockout persists across restart");
        check(!f.verifyPassword(password), "Correct password still rejected after restart");
    }

    // --- Corrupted / malformed records must fail closed ---
    const char *bad_records[] = {
        "",
        "garbage",
        "VVAUTH1\n",
        "VVAUTH1\nnot-a-hash\nfailed=0\n",
        "VVAUTH1\n$argon2id$v=19$m=65536,t=2,p=1$broken\nfailed=0\n",
        "plain text password\n",
    };
    int idx = 0;
    for (const char *content : bad_records)
    {
        const std::string path = dir.file("bad" + std::to_string(idx++) + ".dat");
        tu::writeAll(path, content);
        Authorizer g(path);
        check(g.hasStorageError(), "Malformed auth record -> storage error");
        check(!g.setPassword(password), "Malformed record not replaced by a new account");
        check(!g.verifyPassword(password), "Malformed record cannot authenticate");
        check(tu::readAll(path) == content, "Malformed record left untouched");
    }

    // Valid hash but bad counter
    {
        std::string valid = tu::readAll(auth_file);
        const auto pos = valid.find("failed=");
        const std::string bad = valid.substr(0, pos) + "failed=abc\n";
        const std::string path = dir.file("badcounter.dat");
        tu::writeAll(path, bad);
        Authorizer h(path);
        check(h.hasStorageError(), "Non-numeric counter -> storage error");
    }

    // --- Legacy single-line hash is accepted ---
    {
        const std::string fresh = dir.file("fresh.dat");
        {
            Authorizer i(fresh);
            check(i.setPassword(password), "Setup for legacy test");
        }
        std::string content = tu::readAll(fresh);
        const auto start = content.find('\n') + 1;
        const auto end = content.find('\n', start);
        const std::string legacy_path = dir.file("legacy.dat");
        tu::writeAll(legacy_path, content.substr(start, end - start) + "\n");
        Authorizer j(legacy_path);
        check(j.isInitialized() && !j.hasStorageError(), "Legacy single-line hash accepted");
        check(j.verifyPassword(password), "Legacy account authenticates");
        check(tu::readAll(legacy_path).rfind("VVAUTH1\n", 0) == 0, "Legacy file upgraded to VVAUTH1");
    }

    // --- Write failure leaves account uninitialized ---
    {
        Authorizer k(dir.file("no_such_dir/auth.dat"));
        check(!k.hasStorageError(), "Missing parent dir: treated as no account");
        check(!k.setPassword(password), "Setup fails when the file cannot be written");
        check(!k.isInitialized(), "Failed setup leaves account uninitialized");
    }

    // --- Persistent password rotation ---
    {
        const std::string rot_file = dir.file("rotate.dat");
        const std::string new_pw = "RotatedPassword456!";
        {
            Authorizer r(rot_file);
            check(r.setPassword(password), "Initial setup for rotation");
            check(!r.changePassword("WrongCurrent123!", new_pw), "Rotation with wrong current password fails");
            check(r.failedAttempts() == 1, "Failed rotation increments failed counter");
            check(!r.changePassword(password, "short"), "Rotation to weak password fails");
            check(r.changePassword(password, new_pw), "Rotation with valid current and new password succeeds");
            check(r.failedAttempts() == 0, "Rotation resets failed counter");
        }
        {
            Authorizer r2(rot_file);
            check(!r2.verifyPassword(password), "Old password rejected after rotation");
            check(r2.verifyPassword(new_pw), "New password accepted after restart");
        }
    }

    return tu::finish("auth");
}
